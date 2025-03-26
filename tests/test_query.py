# vim: ts=4 sw=4 noet

# Copyright 2025 The Board of Trustees of the Leland Stanford Junior University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Test using our query client (without sending nsupdate messages)

import dns.name
import dns.resolver
import os
import pytest

import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

import sudns01.clients.exceptions
import sudns01.clients.query

# Make a client for sending queries.
# We will create this even if we don't have a test DNS server, since we can do
# a few tests without one.

@pytest.fixture
def query_tcp() -> sudns01.clients.query.QueryClient | None:
	if 'TEST_DNS_PORT' not in os.environ:
		return None
	return sudns01.clients.query.QueryClient(
		ips=['127.0.0.1'],
		port=int(os.environ['TEST_DNS_PORT']),
	)

@pytest.fixture
def query_udp() -> sudns01.clients.query.QueryClient | None:
	if 'TEST_DNS_PORT' not in os.environ:
		return None
	return sudns01.clients.query.QueryClient(
		ips=['127.0.0.1'],
		port=int(os.environ['TEST_DNS_PORT']),
		udp=True
	)

def test_constructor() -> None:
	"""Test the contructor catches configuration errors.
	"""
	with pytest.raises(ValueError):
		query_noip = sudns01.clients.query.QueryClient(
			ips=[],
		)
	with pytest.raises(ValueError):
		query_lowport = sudns01.clients.query.QueryClient(
			ips=['127.0.0.1'],
			port=0,
		)
	with pytest.raises(ValueError):
		query_highport = sudns01.clients.query.QueryClient(
			ips=['127.0.0.1'],
			port=65536,
		)
	with pytest.raises(ValueError):
		query_timeout = sudns01.clients.query.QueryClient(
			ips=['127.0.0.1'],
			timeout=0.0,
		)

def test_resolve_a(query_tcp, query_udp) -> None:
	"""Make a simple call to resolve an A record.

	Since we know our test resolver has a record for `ns.localdomain`, make a
	DNS query for that—both TCP and UDP—then check the response.
	"""
	if query_tcp is None or query_tcp is None:
		pytest.skip('No Test DNS Server configured')

	# Make a name
	ns_localdomain = dns.name.from_text('ns.localdomain')

	# Create a message with a unique ID
	request = dns.message.Message()

	# Ask a question
	question_rrset = dns.rrset.RRset(
		name=ns_localdomain,
		rdclass=dns.rdataclass.IN,
		rdtype=dns.rdatatype.A,
	)
	request.question.append(question_rrset)

	# Send the message via TCP and UDP
	response_tcp = query_tcp.query(request)
	response_udp = query_udp.query(request)

	# Make sure we have one question & answer, and they're the same.
	assert len(response_tcp.question) == 1
	assert len(response_udp.question) == 1
	assert len(response_tcp.answer) == 1
	assert len(response_udp.answer) == 1
	assert response_tcp.question[0] == response_udp.question[0]
	assert response_tcp.answer[0] == response_udp.answer[0]

	# Make sure the question is what we asked
	assert response_tcp.question[0] == question_rrset

	# Make sure we got 127.0.0.1 as our answer
	answer = response_tcp.answer[0]
	assert answer.name == ns_localdomain
	assert answer.rdclass == dns.rdataclass.IN
	assert answer.rdtype == dns.rdatatype.A
	assert len(answer.items) == 1
	assert answer.pop().address == '127.0.0.1'

def test_noservers() -> None:
	"""Hack a query client to test for timeout & no servers.

	By specifying only a single DNS server IP, pointing to an IP we know is not
	going to responsd, we can test both the timeout logic and the "no servers
	remaining" exception.
	"""
	bad_query = sudns01.clients.query.QueryClient(
		ips=['192.0.2.1'],
		timeout=0.1,
	)

	# Make a valid name
	stanford_edu = dns.name.from_text('stanford.edu')

	# Make an IPv4 lookup
	request = dns.message.Message()
	question_rrset = dns.rrset.RRset(
		name=stanford_edu,
		rdclass=dns.rdataclass.IN,
		rdtype=dns.rdatatype.A,
	)
	request.question.append(question_rrset)

	# This will timeout and then run out of servers
	with pytest.raises(sudns01.clients.exceptions.NoServers):
		bad_query.query(request)

def test_oserror() -> None:
	"""Make a query that gets us an OSError back.
	"""
	# TODO
	pass

def test_badresponse(query_tcp, query_udp) -> None:
	"""Hack a query that gives us a bad response.

	A BadResponse is sent by dnspython when the response it gets from a DNS
	server does not correspond to the message that was sent.  This is an
	extremely unusual situation, so the easiest way to trigger it is to
	override dnspython code.
	"""
	# This test does end up sending out a DNS query, so we need a resolver.
	if query_tcp is None or	query_udp is None:
		pytest.skip('No Test DNS Server configured')

	# This monkeyClass always returns False for is_response
	class BadMessage(dns.message.Message):
		def is_response(self,
			m: dns.message.Message,
		) -> bool:
			return False

	# Make a valid name
	stanford_edu = dns.name.from_text('stanford.edu')

	# Make an IPv4 lookup
	request = BadMessage()
	question_rrset = dns.rrset.RRset(
		name=stanford_edu,
		rdclass=dns.rdataclass.IN,
		rdtype=dns.rdatatype.A,
	)
	request.question.append(question_rrset)

	# Having is_response() return False will cause the query client to return a
	# dns.query.BadResponse, which gets turned into a DNSError.
	with pytest.raises(sudns01.clients.exceptions.DNSError):
		query_tcp.query(request)
