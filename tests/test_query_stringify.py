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

# Test message stringification
# NOTE: We're not aiming to test dnspython's conversion code.  Instead, we're
# testing the code that puts everything toegerher.

# Stdlib imports
import os

# PyPi imports
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.SOA
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rrset
import dns.update
import pytest

# Local imports
import sudns01.clients.query


# Make a client for sending queries.
# NOTE: We don't actually make any queries here, we just need the client
# instance to test strinficiation.
query = sudns01.clients.query.QueryClient(
	ips=['127.0.0.1'],
	port=(int(os.environ['TEST_DNS_PORT']) if 'TEST_DNS_PORT' in os.environ else 53),
)


# Now, our tests
def test_message() -> None:
	"""Test stringification of a non-update message.
	"""

	# Make some names
	localhost_localdomain = dns.name.from_text('localhost.localdomain')
	localdomain = dns.name.from_text('localdomain')
	ns_localdomain = dns.name.from_text('ns.localdomain')

	# Create a message
	msg = dns.message.Message(
		id=12345,
	)
	msg.flags = dns.flags.AD | dns.flags.RD

	# Ask a question
	question_rrset = dns.rrset.RRset(
		name=localhost_localdomain,
		rdclass=dns.rdataclass.IN,
		rdtype=dns.rdatatype.ANY,
	)
	msg.question.append(question_rrset)

	# Put in two answers
	localhost_A_rrset = dns.rrset.RRset(
		name=localhost_localdomain,
		rdclass=dns.rdataclass.IN,
		rdtype=dns.rdatatype.A,
	)
	localhost_A_rrset.add(dns.rdtypes.IN.A.A(
		dns.rdataclass.IN,
		dns.rdatatype.A,
		'127.0.0.1',
	))
	msg.answer.append(localhost_A_rrset)
	localhost_AAAA_rrset = dns.rrset.RRset(
		name=localhost_localdomain,
		rdclass=dns.rdataclass.IN,
		rdtype=dns.rdatatype.AAAA,
	)
	localhost_AAAA_rrset.add(dns.rdtypes.IN.AAAA.AAAA(
		dns.rdataclass.IN,
		dns.rdatatype.AAAA,
		'::1',
	))
	msg.answer.append(localhost_AAAA_rrset)

	# Put in an NS entry and an A entry in the additional section
	localdomain_NS_rrset = dns.rrset.RRset(
		name=localdomain,
		rdclass=dns.rdataclass.ANY,
		rdtype=dns.rdatatype.NS,
	)
	localdomain_NS_rrset.add(dns.rdtypes.ANY.NS.NS(
		dns.rdataclass.ANY,
		dns.rdatatype.NS,
		ns_localdomain,
	))
	msg.additional.append(localdomain_NS_rrset)
	ns_A_rrset = dns.rrset.RRset(
		name=ns_localdomain,
		rdclass=dns.rdataclass.IN,
		rdtype=dns.rdatatype.A,
	)
	ns_A_rrset.add(dns.rdtypes.IN.A.A(
		dns.rdataclass.IN,
		dns.rdatatype.A,
		'127.0.0.1',
	))
	msg.additional.append(ns_A_rrset)

	# Make an SOA record for the authority section
	localdomain_SOA_rrset = dns.rrset.RRset(
		name=localdomain,
		rdclass=dns.rdataclass.ANY,
		rdtype=dns.rdatatype.SOA,
	)
	localdomain_SOA_rrset.add(dns.rdtypes.ANY.SOA.SOA(
		dns.rdataclass.ANY,
		dns.rdatatype.SOA,
		'ns.localdomain.',
		'nobody.stanford.edu.',
		1,
		21600,
		21600,
		21600,
		21600,
	))
	msg.authority.append(localdomain_SOA_rrset)

	# Now, stringify and test!
	assert (sudns01.clients.query.QueryClient._message_to_text(msg) == 
		'#12345: QUERY NOERROR [RD AD] ' +
		'QUESTION=<localhost.localdomain. IN ANY> ' +
		'ANSWER=<localhost.localdomain. 0 IN A 127.0.0.1> ' +
		'ANSWER=<localhost.localdomain. 0 IN AAAA ::1> ' +
		'AUTHORITY=<localdomain. 0 ANY SOA ns.localdomain. nobody.stanford.edu. 1 21600 21600 21600 21600> ' +
		'ADDITIONAL=<localdomain. 0 ANY NS ns.localdomain.> '
		'ADDITIONAL=<ns.localdomain. 0 IN A 127.0.0.1>'
	)

def test_update() -> None:
	"""Test stringification of an update message.
	"""

	# Make some names
	localhost_localdomain = dns.name.from_text('localhost.localdomain')
	localdomain = dns.name.from_text('localdomain')

	# Create a message
	msg = dns.update.UpdateMessage(
		id=43210,
		zone=localdomain,
	)

	# Add an A record
	msg.add(
		localhost_localdomain,
		10,
		dns.rdtypes.IN.A.A(
			dns.rdataclass.IN,
			dns.rdatatype.A,
			'127.0.0.1',
		)
	)

	# Delete an AAAA record
	msg.delete(
		localhost_localdomain,
		dns.rdtypes.IN.AAAA.AAAA(
			dns.rdataclass.IN,
			dns.rdatatype.AAAA,
			'::1',
		)
	)

	# Now, stringify and test!
	assert (sudns01.clients.query.QueryClient._message_to_text(msg) == 
		'#43210: UPDATE NOERROR [] ' +
		'QUESTION=<localdomain. IN SOA> ' +
		'ZONE=<localdomain. IN SOA> ' +
		'UPDATE=<localhost.localdomain. 10 IN A 127.0.0.1> ' +
		'UPDATE=<localhost.localdomain. 0 NONE AAAA ::1> ' +
		'AUTHORITY=<localhost.localdomain. 10 IN A 127.0.0.1> ' +
		'AUTHORITY=<localhost.localdomain. 0 NONE AAAA ::1>'
	)
