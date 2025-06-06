# vim: ts=4 sw=4 noet

# Copyright 2025 The Board of Trustees of the Leland Stanford Junior University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Code for cleanup-related stuff

This module contains code for cleaning up old challenges.
"""

# stdlib imports
import binascii
import collections.abc
import dataclasses
import logging
from typing import NewType, NamedTuple

# PyPi imports
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.update

# Local imports
import sudns01.clients.exceptions
import sudns01.clients.resolver
import sudns01.clients.tkey

# Set up logging
logger = logging.getLogger(__name__)
exception = logger.exception
error = logger.error
warn = logger.warning
info = logger.info
debug = logger.debug


TTL: int = 10
"""The TTL to use for new DNS records.
"""


SplitNameLabel = NewType('SplitNameLabel', dns.name.Name)
SplitNameZone = NewType('SplitNameZone', dns.name.Name)
class SplitName(NamedTuple):
	label: SplitNameLabel
	zone: SplitNameZone

	def __str__(self) -> str:
		return f"{self.label!s},{self.zone!s}"

# Make a class for cleanup-related stuff
@dataclasses.dataclass(frozen=True)
class Challenge():
	"""Manage challenges for a single domain

	This handles the challenge (and challenge cleanup) for a single domain.  It
	handles generating the challenge-add and -delete messages, make cleanup
	challenges & messages, fetching records to clean up, and checking if a
	challenge made it into DNS.

	The work of signing and sending is handled separately.

	:raises ValueError: If acme_name is not a subdomain of domain.
	"""

	domain: dns.name.Name
	"""The domain that may end up having records cleaned up.
	"""

	acme_name: dns.name.Name
	"""ACME name for domain.

	This is a DNS name, formed by prepending the ACME label (`_acme-challenge`)
	to the domain.

	This is populated by the first call to `acme_name`.
	"""

	_split: SplitName | None = dataclasses.field(init=False)
	"""Split label and zone name for our ACME name.

	nsupdate messages require the FQDN be split into a zone part, and a label
	part.  For example, for `_acme-challenge.blargh.stanford.edu.`, the zone is
	`stanford.edu.` and the label is `_acme-challenge.blargh`.  This caches
	those two parts, assuming `_acme_name` contains the FQDN.

	This is populated by the first call to `split`.
	"""

	def __post_init__(self) -> None:
		"""Make sure our ACME name is related to our domain, and prep split cache.
		"""
		# Check acme_name is a subdomain of domain
		if not self.acme_name.is_subdomain(self.domain):
			raise ValueError(f"{self.acme_name} is not a subdomain of {self.domain}")

		# Set our split cache to `None`
		object.__setattr__(
			self,
			'_split',
			None,
		)

	@staticmethod
	def acme_name_for_domain(
		domain: dns.name.Name
	) -> dns.name.Name:
		"""Return the Name of the ACME challenge domain for a given domain.
		"""
		acme_challenge_label = dns.name.Name(labels=('_acme-challenge',))
		return acme_challenge_label.concatenate(domain)

	def split(
		self,
		resolver: sudns01.clients.resolver.ResolverClient,
	) -> SplitName:
		"""Split the ACME challenge name into separate label and zone parts.

		When making nsupdate messages, instead of providing the name to update
		as a FQDN, you must provide the zone name and a separate label name.

		The zone name can be found by doing an SOA lookup.  For example, with
		SOA lookups, you can discover that both `blargh.stanford.edu` and
		`_acme-challenge.blargh.stanford.edu` are part of the same zone,
		`stanford.edu`.  So in both cases, the zone is `stanford.edu.` and the
		labels are `blargh` and `_acme-challenge.blargh`.

		This method performs the lookup and the split.

		:param resolver: A resolver to use for SOA record lookup.

		:param acme_challenge_name: The DNS name to use for queries.  If not
		provided, `_acme-challenge.` will be prepended to the existing
		domain.

		:returns: A tuple containing the label and zone portions of the domain.
		"""
		debug(f"In split for {self.acme_name}")

		# If the ACME challenge name is what we expect, can we use cache?
		if self._split is not None:
			debug("Using results from cache")
			return self._split

		# Use the resolver to work out our zone name
		zone_name = resolver.get_zone_name(
			self.domain,
			raise_on_cdname=False,
		)

		# Split our ACME name into relative and zone parts
		acme_name_relative = self.acme_name.relativize(zone_name)
		result = SplitName(
			SplitNameLabel(acme_name_relative),
			SplitNameZone(zone_name),
		)
		debug(f"Split name into {result}")

		# Cache and return
		object.__setattr__(
			self,
			'_split',
			result,
		)
		return result

	@property
	def cleanup_challenge(self) -> str:
		"""Return the challenge string the user needs to provide, in order to do a cleanup.

		If the user wants to do a cleanup of old TXT records, they must provide
		a challenge string.  This returns the challenge string.

		:returns: A string the user must provide, confirming the intent to clean up records.
		"""
		challenge_str = "{:#010x}".format(
			binascii.crc32(str(self.domain).encode('UTF-8'))
		)
		return challenge_str

	def is_cleanup_challenge_valid(
		self,
		challenge: str,
	) -> bool:
		"""Return True if a provided string matches this domain's challenge.

		If the user wants to do a cleanup of old TXT records, they must provide
		a challenge string.  This checks if the provided challenge string is
		correct.

		:param challenge: The challenge to verify.

		:returns: True if the provided challenge is correct; False otherwise.
		"""
		debug(f"Checking provided challenge {challenge} against {self.cleanup_challenge}")
		return (True if challenge == self.cleanup_challenge else False)

	def get_old_challenges(
		self,
		resolver: sudns01.clients.resolver.ResolverClient,
	) -> collections.abc.Iterator[tuple[bytes, ...]]:
		"""Iterate over old challenges to be cleaned up.

		Using the provided resolver, query the ACME Challenge name for TXT
		records.  Return all that are found.

		NOTE: TXT records are encoded as tuples of byte strings; this code
		maintains that structure.

		:param resolver: The DNS resolver to use.

		:param acme_challenge_name: The DNS name to use for queries.  If not
		provided, `_acme-challenge.` will be prepended to the existing
		domain.

		:returns: Tuples of byte strings.
		"""
		debug(f"Looking up old TXT records for {self.acme_name}")

		# Make something to hold what we end up returning
		results: set[tuple[bytes, ...]] = set()

		# Do the lookup!
		records = resolver.get_txt(
			self.acme_name,
			raise_on_cdname=False,
		)
		if len(records) == 0:
			debug(f"No challenge records to clean up for {self.acme_name}")
			return

		# Go through each returned record & convert to tuple
		for record in records:
			record_tuple: tuple[bytes, ...]
			if isinstance(record, tuple):
				debug(f"Passing through record: {record!r}")
				record_tuple = record
			else:
				debug(f"Converting to tuple: {record!r}")
				record_tuple = (record,)
			yield record_tuple

		# All done!
		return

	def get_challenge_cleanup_message(
		self,
		record: tuple[bytes, ...],
		resolver: sudns01.clients.resolver.ResolverClient,
		signer: sudns01.clients.tkey.GSSTSig,
	) -> dns.update.UpdateMessage:
		"""Get a delete-TXT-record message for a challenge.

		:param record: The TXT record to delete.

		:param resolver: A DNS resolver, to look up the domain's zone.

		:param signer: A TSIG signer for the message.

		:param acme_challenge_name: The DNS name to use for queries.  If not
		provided, `_acme-challenge.` will be prepended to the existing
		domain.

		:returns: A ready-to-send DNS message.
		"""
		debug(f"Making challenge cleanup message {record} for {self.acme_name}")

		# Split our domain into label and zone parts
		domain_parts = self.split(resolver)

		# Construct a TXT record to target for deletion
		rdata = dns.rdtypes.ANY.TXT.TXT(
			rdclass=dns.rdataclass.IN,
			rdtype=dns.rdatatype.TXT,
			strings=record,
		)

		# Construct our deletion request
		message = dns.update.UpdateMessage(
			zone=domain_parts.zone,
			rdclass=dns.rdataclass.IN,
			**signer.dnspython_args,
		)
		message.delete(
			domain_parts.label,
			rdata,
		)

		return message

	def get_challenge_add_message(
		self,
		challenge: str,
		resolver: sudns01.clients.resolver.ResolverClient,
		signer: sudns01.clients.tkey.GSSTSig,
	) -> dns.update.UpdateMessage:
		"""Get an add-TXT-record message for a challenge.

		:param challenge: The challenge string to add.

		:param resolver: A DNS resolver, to look up the domain's zone.

		:param signer: A TSIG signer for the message.

		:param acme_challenge_name: The DNS name to use for queries.  If not
		provided, `_acme-challenge.` will be prepended to the existing
		domain.

		:returns: A ready-to-send DNS message.
		"""
		debug(f"Making challenge add message {challenge} for {self.acme_name}")

		# Split our domain into label and zone parts
		domain_parts = self.split(resolver)

		# Prepare our challenge record
		# Per RFC 8555 §8.4, challenge tokens only contain characters from the
		# base64url alphabet, which is a subset of ASCII.  So, we can encode as
		# ASCII.
		challenge_rdata = dns.rdtypes.ANY.TXT.TXT(
			rdclass=dns.rdataclass.IN,
			rdtype=dns.rdatatype.TXT,
			strings=(
				challenge.encode('ASCII'),
			),
		)

		# Add a new ACME Challenge record

		# Construct our add request
		challenge_add = dns.update.UpdateMessage(
			zone=domain_parts.zone,
			rdclass=dns.rdataclass.IN,
			**signer.dnspython_args,
		)
		challenge_add.add(
			domain_parts.label,
			TTL,
			challenge_rdata,
		)

		return challenge_add

	def get_challenge_delete_message(
		self,
		challenge: str,
		resolver: sudns01.clients.resolver.ResolverClient,
		signer: sudns01.clients.tkey.GSSTSig,
		acme_challenge_name: dns.name.Name | None = None
	) -> dns.update.UpdateMessage:
		"""Get an delete-TXT-record message for a challenge.

		:param challenge: The challenge string to delete.

		:param resolver: A DNS resolver, to look up the domain's zone.

		:param signer: A TSIG signer for the message.

		:param acme_challenge_name: The DNS name to use for queries.  If not
		provided, `_acme-challenge.` will be prepended to the existing
		domain.

		:returns: A ready-to-send DNS message.
		"""
		debug(f"Making challenge delete message {challenge} for {self.acme_name}")

		# Split our domain into label and zone parts
		domain_parts = self.split(resolver)

		# Prepare our challenge record
		# Per RFC 8555 §8.4, challenge tokens only contain characters from the
		# base64url alphabet, which is a subset of ASCII.  So, we can encode as
		# ASCII.
		challenge_rdata = dns.rdtypes.ANY.TXT.TXT(
			rdclass=dns.rdataclass.IN,
			rdtype=dns.rdatatype.TXT,
			strings=(
				challenge.encode('ASCII'),
			),
		)

		# Add a new ACME Challenge record

		# Construct our add request
		challenge_delete = dns.update.UpdateMessage(
			zone=domain_parts.zone,
			rdclass=dns.rdataclass.IN,
			**signer.dnspython_args,
		)
		challenge_delete.delete(
			domain_parts.label,
			challenge_rdata,
		)

		return challenge_delete

	def is_challenge_in_dns(
		self,
		challenge: str,
		resolver: sudns01.clients.resolver.ResolverClient,
	) -> bool:
		"""Check if a challenge is appearing in DNS.

		:param challenge: The challenge string to delete.

		:param resolver: A DNS resolver, to look up the domain's zone.

		:param acme_challenge_name: The DNS name to use for queries.  If not
		provided, `_acme-challenge.` will be prepended to the existing
		domain.

		:returns: True if the challenge is in DNS, else False.
		"""
		debug(f"Checking {self.acme_name} for challenge {challenge}")

		challenge_bytes = challenge.encode('ASCII')

		# Do an uncached TXT lookup
		txt_records = resolver.get_txt(
			query=self.acme_name,
			cached=False,
			raise_on_cdname=False,
		)

		# Our output may contain tuples, so we can't do a simple `in` check
		for txt_record in txt_records:
			if isinstance(txt_record, tuple):
				# Challenges are only ever single-item tuples.
				# Single-item tuples are unpacked by `get_txt`, so we we get a
				# tuple, it's definitely wrong.
				debug(f"Skipping non-challenge tuple {txt_record!r}")
				continue
			else:
				debug(f"Checking bytes {txt_records!r}")
				if txt_record == challenge_bytes:
					return True

		debug("No matching records found")
		return False
