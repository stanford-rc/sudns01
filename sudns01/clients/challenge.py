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

ACME_CHALLENGE_LABEL = dns.name.Name(labels=('_acme-challenge',))

SplitNameLabel = NewType('SplitNameLabel', dns.name.Name)
SplitNameZone = NewType('SplitNameZone', dns.name.Name)
class SplitName(NamedTuple):
	label: SplitNameLabel
	zone: SplitNameZone

	def __str__(self) -> str:
		return f"{self.label!s},{self.zone!s}"

# Make a class for cleanup-related stuff
@dataclasses.dataclass(frozen=True)
class Cleanup():
	"""Manage cleanup for a single domain

	This handles the cleanup work for a single domain.  It handles generating
	the cleanup challenge, doing the cleanup, fetching records to clean up, and
	generating the cleanup messages.

The work of signing and sending is handled separately.
	"""

	domain: dns.name.Name
	"""The domain that may end up having records cleaned up.
	"""

	_acme_name: dns.name.Name | None = dataclasses.field(init=False)
	"""Cached ACME name for domain.

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
		"""Populate internal class members (or make placeholders).
		"""
		# Set our two internal members to `None`
		object.__setattr__(
			self,
			'_acme_name',
			None,
		)
		object.__setattr__(
			self,
			'_split',
			None,
		)

	@property
	def acme_name(self) -> dns.name.Name:
		"""Return the Name of the ACME challenge domain.
		"""
		# If we don't have the name generated yet, then generate and cache.
		if self._acme_name is None:
			result = ACME_CHALLENGE_LABEL.concatenate(self.domain)
			object.__setattr__(
				self,
				'_acme_name',
				result,
			)
			return result
		else:
			return self._acme_name

	def split(
		self,
		resolver: sudns01.clients.resolver.ResolverClient,
		acme_challenge_name: dns.name.Name | None = None,
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
		if acme_challenge_name == self.acme_name and self._split is not None:
			debug("Using results from cache")
			return self._split

		# Use the resolver to work out our zone name
		zone_name = resolver.get_zone_name(
			self.acme_name,
			raise_on_cdname=False,
		)

		# Split our ACME name into relative and zone parts
		acme_name_relative = self.acme_name.relativize(zone_name)
		result = SplitName(
			SplitNameLabel(acme_name_relative),
			SplitNameZone(zone_name),
		)
		debug(f"Split name into {result}")

		# Possibly cache, and return
		if acme_challenge_name == self.acme_name:
			object.__setattr__(
				self,
				'_split',
				result,
			)
		return result

	@property
	def challenge(self) -> str:
		"""Return the challenge string the user needs to provide, in order to do a cleanup.

		If the user wants to do a cleanup of old TXT records, they must provide
		a challenge string.  This returns the challenge string.

		:returns: A string the user must provide, confirming the intent to clean up records.
		"""
		challenge_str = "{:#010x}".format(
			binascii.crc32(str(self.domain).encode('UTF-8'))
		)
		return challenge_str

	def is_challenge_valid(
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
		debug(f"Checking provided challenge {challenge} against {self.challenge}")
		return (True if challenge == self.challenge else False)

	def get_old_challenges(
		self,
		resolver: sudns01.clients.resolver.ResolverClient,
		acme_challenge_name: dns.name.Name | None = None,
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
			acme_challenge_name,
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

	def get_delete_message(
		self,
		record: tuple[bytes, ...],
		resolver: sudns01.clients.resolver.ResolverClient,
		signer: sudns01.clients.tkey.GSSTSig,
		acme_challenge_name: dns.name.Name | None = None
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
		if acme_challenge_name is None:
			acme_challenge_name = self.acme_name

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
		acme_challenge_name: dns.name.Name | None = None
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
		if acme_challenge_name is None:
			acme_challenge_name = self.acme_name
		debug(f"Making challenge add message {challenge} for {acme_challenge_name}")

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
		if acme_challenge_name is None:
			acme_challenge_name = self.acme_name
		debug(f"Making challenge delete message {challenge} for {acme_challenge_name}")

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
