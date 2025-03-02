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

"""A client for making DNS queries

This is not used by the stub resolver.  Instead, it's used for the weird
nsupdate queries that we'll be making, as well as queries used to set up
authentication and signing.
"""

# stdlib imports
import logging
import socket

# PyPi imports
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.tsig
import dns.update

# Local imports
from sudns01.clients.exceptions import *

# Set up logging
logger = logging.getLogger(__name__)
exception = logger.exception
error = logger.error
warning = logger.warning
info = logger.info
debug = logger.debug

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
