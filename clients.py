#vim: ts=4 sw=4 noet

# 

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

# stdlib imports
import logging
import socket

# PyPi imports
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.resolver
import dns.tsig
import dns.update

RESOLVER_TIMEOUT: int = 10
CACHE_CLEAN_INTERVAL: int = 300

# Set up logging
logger = logging.getLogger(__name__)
exception = logger.exception
error = logger.error
warning = logger.warning
info = logger.info
debug = logger.debug


class ResolverClient():
	"""A stub DNS resolver, for DNS lookups we need to do.

	There are a few special DNS lookups that we need to do:

	* Doing a SOA lookup, to figoure out a zone from an FQDN.

	* Doing TXT lookups.

	This wrap's dnspython's stub resolver.
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

		self._resolver_nocache = dns.resolver.Resolver(configure=True)
		self._resolver.retry_servfail = True

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
				lifetime=RESOLVER_TIMEOUT,
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

class ResolverError(Exception):
	"""There was a problem with the DNS resolver.
	"""
	pass

class ResolverErrorPermanent(ResolverError):
	"""There was a temporary problem with the DNS resolver.

	You may be able to recover if you wait a while.
	"""
	pass

class QueryClient():
    """A client for making DNS queries

    This is largely a generic client, but will be getting code to do make DNS
    Update calls.
    """

    _ips: list[str]
    _port: int
    _timeout: float
    _udp: bool

    def __init__(self,
        ips: list[str],
        port: int = 53,
        timeout: float = 10.0,
        udp: bool = False,
    ):
        """
        :param ips: A list of DNS server IP addresses.  Both IPv4 and IPv6 addresses are accepted.  The servers will be tried in the order listed.

        :param port: The server port number to use.  Normally this is 53.

        :param timeout: Timeout, in seconds, for queries to the DNS server.

        :param udp: Set this to True if your DNS server does not support TCP.

        :raise ValueError: Invalid port or timeout, or there were no servers.
        """
        if len(ips) == 0:
            raise ValueError("No server IPs")
        if (port < 0) or (port > 65535):
            raise ValueError(f"Invalid port {port}")
        if timeout < 0:
            raise ValueError(f"Invalid timeout {timeout}")
        self._ips = ips
        self._port = port
        self._timeout = timeout
        self._udp = udp

    def query(
        self,
        message: dns.message.Message,
    ) -> dns.message.Message:
        """Send a DNS query.

        :param message: The message to send.

        :raise NoServers: All the DNS servers had problems.

        :raise DNSError: There was a working DNS server, but there was a problem.

        :return: A DNS response Message
        """
        debug('Sending message ' + self._message_to_text(message))
        if self._udp:
            warning("Using DNS over UDP.  Beware of issues!")

        # Do we have any servers to try?
        if len(self._ips) == 0:
            raise NoServers()

        # Take the first server from the list of IPs
        server = self._ips[0]

        # Send our DNS query
        debug(f"Trying to send query to {server}")
        try:
            if self._udp:
                result = dns.query.udp(
                    message,
                    where=server,
                    port=self._port,
                    timeout=self._timeout,
                )
            else:
                result = dns.query.tcp(
                    message,
                    where=server,
                    port=self._port,
                    timeout=self._timeout,
                )
        except OSError as e:
            # For an OS-type error, we probably need to try another IP
            warning(f"Issue connecting to {server}: {e} — Trying another server")
            self._ips.pop()
            return self.query(message)
        except dns.exception.Timeout:
            warning(f"Timeout interacting with {server} — Trying another server")
            self._ips.pop()
            return self.query(message)
        except (
            dns.query.BadResponse,
            EOFError,
        ) as e:
            raise DNSError()

        # Did we actually make it through!?
        debug('Got response ' + self._message_to_text(result))
        return result

    @staticmethod
    def _message_to_text(
        message: dns.message.Message
    ) -> str:
        # Start with the top-level message stuff
        op_str = message.opcode().name
        rcode_str = message.rcode().name
        flags_str = dns.flags.to_text(message.flags)

        # Build a list of section components
        sections_components: list[str] = list()

        # Go through each DNS Message section
        for question in message.question:
            sections_components.append(
                'QUESTION=<' + question.to_text() + '>'
            )


        if isinstance(message, dns.update.UpdateMessage):
            for zone in message.zone:
                sections_components.append(
                    'ZONE=<' + zone.to_text() + '>'
                )

            for update in message.update:
                sections_components.append(
                    'UPDATE=<' + update.to_text() + '>'
                )

        for answer in message.answer:
            sections_components.append(
                'ANSWER=<' + question.to_text() + '>'
            )

        for authority in message.authority:
            sections_components.append(
                'AUTHORITY=<' + question.to_text() + '>'
            )

        for additional in message.additional:
            sections_components.append(
                'ADDITIONAL=<' + additional.to_text() + '>'
            )

        # Combine the sections into one string
        sections_str = ' '.join(sections_components)

        # Put everything together and return!
        return f"#{message.id}: {op_str} {rcode_str} [{flags_str}] {sections_str}"

class NoServers(Exception):
    """There were no more servers to try."""

class DNSError(Exception):
    """We connected to the DNS server, but ran into a problem."""
