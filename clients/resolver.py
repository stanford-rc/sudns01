#vim: ts=4 sw=4 noet

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

"""A simple DNS resolver

This contains a simple DNS resolver for internal use.  There are a few special
DNS lookups that we need to do:

* Doing a SOA lookup, to figoure out a zone from an FQDN.

* Doing TXT lookups.
"""

# stdlib imports
import codecs
import logging
import socket

# PyPi imports
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.tsig
import dns.update

# Local imports
from clients.exceptions import *

RESOLVER_TIMEOUT: int = 10
"""What timeout do we use?
"""

CACHE_CLEAN_INTERVAL: int = 300
"""How often do we clean out cached records?
"""

# Set up logging
logger = logging.getLogger(__name__)
exception = logger.exception
error = logger.error
warning = logger.warning
info = logger.info
debug = logger.debug


class ResolverClient():
	"""A stub DNS resolver, for DNS lookups we need to do.

	This wrap's dnspython's stub resolver.  Both caching and non-caching
    options are available within the same instance.
	"""

	_resolver: dns.resolver.Resolver
	"""A resolver with a cache"""

	_resolver_nocache: dns.resolver.Resolver
	"""A resolver without a cache"""

	def __init__(
		self,
	):
		self._resolver = dns.resolver.Resolver(configure=True)
		self._resolver.cache = dns.resolver.Cache(cleaning_interval=CACHE_CLEAN_INTERVAL)
		self._resolver.retry_servfail = True
		self._resolver.lifetime = RESOLVER_TIMEOUT

		self._resolver_nocache = dns.resolver.Resolver(configure=True)
		self._resolver.retry_servfail = True
		self._resolver.lifetime = RESOLVER_TIMEOUT

	def get_ip(self,
		query: dns.name.Name | str,
		cached: bool = True,
		ipv6: bool = True,
		search: bool = True,
	) -> list[str]:
		"""Return a list of IPs for a query.

		Do an A query (and, if enabled, also a AAAA query), and return the
		results.  IPv6 (if enabled) IPs are returned before IPv4.  Within each
		address type, results are returned in the order provided by the DNS
		server.

		:param query: The DNS name to look up.

		:param cached: If True, use cached names.

		:param ipv6: If True, include IPv6 addresses in the list.

		:param search: If True, use any configured search domains.

		:returns: A list of IP addresses, which may be empty.

		:raises ResolverError: There was a problem looking up the name.  Maybe you can retry?

		:raises ResolverErrorPermanent: There was a permanent problem doing your DNS lookup.
		"""

		debug(
			f"Resolver running get_ip for {query} with " +
			('cached ' if cached else '') +
			('ipv6 ' if ipv6 else '') +
			('search' if search else '')
		)

		# Do we use our caching resolver, or not?
		resolver = (self._resolver if cached is True else self._resolver_nocache)

		# Do we want A and AAAA records, or just A records?
		family = (socket.AF_UNSPEC if ipv6 is True else socket.AF_INET)

		# Do the lookup!
		try:
			answers = resolver.resolve_name(
				name=query,
				family=family,
				search=search,
			)
			addresses = list(answers.addresses())
		except (
			dns.resolver.NXDOMAIN,
			dns.resolver.NoAnswer,
		):
			warning(f"NXDOMAIN or no answer for {query}")
			addresses = list()
		except (
			dns.resolver.NoNameservers,
			dns.resolver.LifetimeTimeout,
		) as e:
			exception("Either NoNameservers or LifetimeTimeout for {query}")
			raise ResolverError(
				'All nameservers returned errors or did not respond.'
			)
		except dns.resolver.YXDOMAIN:
			exception(f"YXDOMAIN for {query}")
			raise ResolverErrorPermanent(
				'A YXDOMAIN error happened.  What?!'
			)

		debug(f"Found {len(addresses)} result(s)")
		return addresses

	def get_txt(self,
		query: dns.name.Name | str,
		cached: bool = True,
		search: bool = True,
	) -> list[bytes | tuple[bytes]]:
		"""Return TXT records for a name.

		Do an TXT query and return the results.

		TXT records do not have a defined encoding.  The work of decoding is
		left up to the client.  In this method's description, "strings" means
		"strings of bytes".

		A single TXT record may contain multiple strings.  If a TXT record
		contains a single string, that TXT record's corresponding list entry
		will contain a single bytes object.  Otherwise, the corresponding list
		entry will contain a tuple of bytes objects.

		Results are returned in the order provided by the DNS server.

		:param query: The DNS name to look up.

		:param cached: If True, use cached lookups.

		:param search: If True, use any configured search domains.

		:returns: The name of the zone containing the given FQDN.

		:raises ResolverError: There was a problem looking up the name.  Maybe you can retry?

		:raises ResolverErrorPermanent: There was a permanent problem doing your DNS lookup.
		"""

		debug(
			f"Resolver running get_txt for {query} with " +
			('cached ' if cached else '') +
			('search' if search else '')
		)

		# Do we use our caching resolver, or not?
		resolver = (self._resolver if cached is True else self._resolver_nocache)

		# Do the lookup!
		try:
			reply = resolver.resolve(
				qname=query,
				rdclass=dns.rdataclass.IN,
				rdtype=dns.rdatatype.TXT,
				search=search,
				raise_on_no_answer=False,
			)
		except (
			dns.resolver.NXDOMAIN,
		):
			warning(f"NXDOMAIN for {query}")
			return list()
		except (
			dns.resolver.NoNameservers,
			dns.resolver.LifetimeTimeout,
		) as e:
			exception("Either NoNameservers or LifetimeTimeout for {query}")
			raise ResolverError(
				'All nameservers returned errors or did not respond.'
			)
		except dns.resolver.YXDOMAIN:
			exception(f"YXDOMAIN for {query}")
			raise ResolverErrorPermanent(
				'A YXDOMAIN error happened.  What?!'
			)

		# If we did not get any answers, that's OK.
		if reply.rrset is None:
			debug(f"Found no TXT records for {query}")
			return list()

		# Extract the strings from the list of results.
		# At this point, we have a list of tuples.
		text_tuples = list(
			map(lambda x: x.strings, reply.rrset)
		)

		# Replace all single-item tuples with their single item.
		# This gives us a list containing either bytes or tuples of bytes.
		# This is what we return to the client!
		debug(f"Found {len(text_tuples)} result(s)")
		return list(
			(entries if len(entries) > 1 else entries[0])
			for entries in text_tuples
		)

	def get_zone_name(self,
		query: dns.name.Name | str,
		cached: bool = True,
	) -> dns.name.Name:
		"""Return the zone name for a FQDN.

		A Zone is a collection of DNS records.  When making changes to DNS,
		instead of providing the Fully-Qualified Domain Name (FQDN) for every
		record, you strip off the zone part of the FQDN.

		For example, take FQDN "blargh.stanford.edu".  The zone is
		"stanford.edu".  Now, take FQDN
		"133.96.19.34.bc.googleusercontent.com.".  In that case, the zone is
		"googleusercontent.com"!

		To find out the zone name, you can look up the SOA (Start of Authority)
		record for a FQDN.  The information comes in the Authority section of
		the answer, with the zone as the name attached to the record.

		This takes a FQDN, and returns a the name of the zone.

		:param query: The DNS name to look up.

		:param cached: If True, use cached lookups.

		:returns: The name of the zone containing the given FQDN.

		:raises ValueError: The name you gave is not "absolute" (it's not a FQDN).

		:raises ResolverError: There was a problem looking up the name.  Maybe you can retry?

		:raises ResolverErrorPermanent: There was a permanent problem doing your DNS lookup.
		"""

		debug(
			f"Resolver running get_soa for {query} with " +
			('cached ' if cached else '')
		)
		if isinstance(query, dns.name.Name) and not query.is_absolute():
			raise ValueError(f"{query} is not a FQDN")

		# Do we use our caching resolver, or not?
		resolver = (self._resolver if cached is True else self._resolver_nocache)

		# Do the lookup!
		try:
			answer = resolver.resolve(
				qname=query,
				rdtype=dns.rdatatype.SOA,
				search=False,
                raise_on_no_answer=False,
			)
		except (
			dns.resolver.NXDOMAIN,
		):
			warning(f"NXDOMAIN for {query}")
			raise ResolverErrorPermanent(f"NXDOMAIN for {query}")
		except (
			dns.resolver.NoNameservers,
			dns.resolver.LifetimeTimeout,
		) as e:
			exception("Either NoNameservers or LifetimeTimeout for {query}")
			raise ResolverError(
				'All nameservers returned errors or did not respond.'
			)
		except dns.resolver.YXDOMAIN:
			exception(f"YXDOMAIN for {query}")
			raise ResolverErrorPermanent(
				'A YXDOMAIN error happened.  What?!'
			)

        # If we got multiple authority records, make sure they're the same name.
		debug(f"Found {len(answer.response.authority)} result(s)")
		if len(answer.response.authority) == 0:
			raise ResolverError(
				f"No authority found for {query}"
			)
		elif len(answer.response.authority) == 1:
			return answer.response.authority[0].name
		else:
			# dns.name.Name objects with the same name hash to the same value.
			# So, if you add the same names to a set, your set will end up with
			# only one item!
			names: set[dns.name.Name] = set()
			for authority in answer.response.authority:
				names.add(authority.name)
			if len(names) > 1:
				raise KeyError(
					f"Multiple authority names returned: {names}"
				)
			else:
				return names.pop()
