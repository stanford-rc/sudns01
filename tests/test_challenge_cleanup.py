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

# Test the code responsible for cleaning up other TXT records

# Stdlib imports
import collections.abc
import dataclasses
import os

# PyPi imports
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.update
import pytest

# Local imports
import sudns01.clients.challenge
import sudns01.clients.resolver
import sudns01.clients.tkey


# Make a couple of test cases
@dataclasses.dataclass(frozen=True)
class Case():
	domain: dns.name.Name
	challenge: str
	acme_name: dns.name.Name
cases: list[Case] = [
	Case(
		domain=dns.name.from_text('blargh.stanford.edu'),
		challenge='0x95d402d5',
		acme_name=dns.name.from_text('_acme-challenge.blargh.stanford.edu'),
	),
	Case(
		domain=dns.name.from_text('example.com'),
		challenge='0xbcdf1324',
		acme_name=dns.name.from_text('_acme-challenge.example.com'),
	),
]

# Make some fixtures
@pytest.fixture
def local_resolver() -> sudns01.clients.resolver.ResolverClient | None:
	"""Set up a resolver client pointing to a local test DNS server.

	This provides a `ResolverClient` that works against the local test DNS
	server.  It is only provided if the `TEST_DNS_PORT` environment variable is
	set.

	If the environment variable is not set, then `None` is returned.
	"""
	if 'TEST_DNS_PORT' not in os.environ:
		return None

	local_resolver_resolver = dns.resolver.Resolver(configure=False)
	local_resolver_resolver.nameservers = ['127.0.0.1']
	local_resolver_resolver.port = int(os.environ['TEST_DNS_PORT'])
	local_resolver_resolver.timeout = 0.1
	local_resolver_resolver.lifetime = 0.1
	local_resolver = sudns01.clients.resolver.ResolverClient()
	local_resolver._resolver = local_resolver_resolver
	local_resolver._resolver_nocache = local_resolver_resolver
	return local_resolver

@pytest.fixture
def local_signer(
	local_resolver,
) -> collections.abc.Generator[sudns01.clients.tkey.GSSTSig | None, None, None]:
	"""Set up a signer client using local Kerberos config.

	This provides a GSSTSig instance that works against the local test KDC.
	It is only provided if…

	* `local_resolver` returns a ResolverClient; and

	* The `KR5CONFIG` environment variable is set.

	If any condition is not met, then `None` is returned.

	If a GSSTSig instance *is* returned, then it will be properly closed once
	these tests have completed.
	"""
	if 'KRB5_CONFIG' not in os.environ or local_resolver is None:
		# Yield nothing, then return to skip any cleanup
		yield None
		return

	# Create a query client & signer, then hand over the signer
	local_dnsquery = sudns01.clients.query.QueryClient(
		ips=['127.0.0.1'],
		port=int(os.environ['TEST_DNS_PORT']),
		timeout=0.1,
	)
	local_signer = sudns01.clients.tkey.GSSTSig(
		dnsquery=local_dnsquery,
		server='ns.localdomain',
	)
	yield local_signer

	# At the end of testing, clean up the signer
	local_signer.close()


# Now, our tests
def test_acme_name() -> None:
	"""Make sure the ACME names are generated as expected.
	"""

	for case in cases:
		cleanup = sudns01.clients.challenge.Cleanup(case.domain)
		assert cleanup.acme_name == case.acme_name

def test_split(local_resolver) -> None:
	"""Make sure domain splitting works correctly
	"""
	if local_resolver is None:
		pytest.skip('No Test DNS Server configured')

	# In the zone file, blargh.localdomain should have two TXT entries
	cleanup_blargh = sudns01.clients.challenge.Cleanup(
		dns.name.from_text('blargh.localdomain'),
	)

	# Run split twice, with and without the ACME name
	blargh_split1 = cleanup_blargh.split(
		resolver=local_resolver,
		acme_challenge_name=dns.name.from_text('_acme-challenge.blargh.localdomain'),
	)
	blargh_split2 = cleanup_blargh.split(
		resolver=local_resolver,
	)

	# Check that both methods give the same result, and we got what we expected
	assert blargh_split1 == blargh_split2
	assert blargh_split1.label == dns.name.Name(
		labels=('_acme-challenge', 'blargh')
	)
	assert blargh_split1.zone == dns.name.from_text('localdomain')

def test_challenge() -> None:
	"""Make sure challenge are checked correctly.

	We test that the expected challenge string is generated, and that the
	challenge-validity check works.
	"""

	for case in cases:
		cleanup = sudns01.clients.challenge.Cleanup(case.domain)
		assert cleanup.challenge == case.challenge
		assert cleanup.is_challenge_valid(case.challenge) is True
		assert cleanup.is_challenge_valid('0xdeadbeef') is False

def test_get_old_challenges(
	local_resolver
) -> None:
	"""Make sure old challenges are returned correctly.
	"""
	if local_resolver is None:
		pytest.skip('No Test DNS Server configured')

	# In the zone file, blargh.localdomain should have two TXT entries
	cleanup_blargh = sudns01.clients.challenge.Cleanup(
		dns.name.from_text('blargh.localdomain'),
	)

	# Run the check twice, with and without the ACME name
	blargh_challenge_iterator1 = cleanup_blargh.get_old_challenges(
		resolver=local_resolver,
		acme_challenge_name=dns.name.from_text('_acme-challenge.blargh.localdomain'),
	)
	blargh_challenge_iterator2 = cleanup_blargh.get_old_challenges(
		resolver=local_resolver,
	)
	blargh_challenges1 = set([x for x in blargh_challenge_iterator1])
	blargh_challenges2 = set([x for x in blargh_challenge_iterator2])

	# Make sure the two checks returned the same results (2 entries)
	assert blargh_challenges1 == blargh_challenges2
	assert len(blargh_challenges1) == 2

	# Check that we got the expected entries
	expected_tuple1 = (b'single entry',)
	expected_tuple2 = (b'entry one', b'entry two')
	assert expected_tuple1 in blargh_challenges1
	assert expected_tuple2 in blargh_challenges1

	# Finally, check a record that has no old challenges
	cleanup_ns = sudns01.clients.challenge.Cleanup(
		dns.name.from_text('ns.localdomain'),
	)
	ns_challenge_iterator = cleanup_ns.get_old_challenges(
		resolver=local_resolver,
	)
	ns_challenges = set([x for x in ns_challenge_iterator])
	assert len(ns_challenges) == 0

def test_get_delete_message(
	local_resolver,
	local_signer,
) -> None:
	"""Make sure we get the delete messages we expect.
	"""
	if local_resolver is None:
		pytest.skip('No Test DNS Server configured')
	if local_signer is None:
		pytest.skip('No Test KDC configured')

	# Make some DNS name components
	acme_challenge = dns.name.Name(labels=('_acme-challenge',))
	blargh = dns.name.Name(labels=('blargh',))
	localdomain = dns.name.from_text('localdomain')

	acme_challenge_blargh = acme_challenge + blargh
	acme_challenge_blargh_localdomain = acme_challenge_blargh + localdomain
	blargh_localdomain = blargh + localdomain

	# In the zone file, blargh.localdomain should have two TXT entries
	cleanup = sudns01.clients.challenge.Cleanup(
		blargh_localdomain,
	)

	# Go through each challenge, make a message, and check it
	challenge_iterator = cleanup.get_old_challenges(
		resolver=local_resolver,
		acme_challenge_name=acme_challenge_blargh_localdomain,
	)
	for challenge in challenge_iterator:
		# Generate a delete message, with and without an explicit ACME
		# challenge name.
		message1 = cleanup.get_delete_message(
			record=challenge,
			resolver=local_resolver,
			signer=local_signer,
			acme_challenge_name=acme_challenge_blargh_localdomain,
		)
		message2 = cleanup.get_delete_message(
			record=challenge,
			resolver=local_resolver,
			signer=local_signer,
		)

		# Check message class and top-level fields
		assert isinstance(message1, dns.update.UpdateMessage)
		assert len(message1.zone) == 1
		assert len(message1.update) == 1
		assert isinstance(message2, dns.update.UpdateMessage)
		assert len(message2.zone) == 1
		assert len(message2.update) == 1

		# Check zone
		zone = message1.zone[0]
		assert zone == message2.zone[0]
		assert zone.name == localdomain

		# Check update
		update = message1.update[0]
		assert update == message2.update[0]
		assert update.name == acme_challenge_blargh
		assert update.rdclass == dns.rdataclass.IN
		assert update.rdtype == dns.rdatatype.TXT
		assert update.deleting == dns.rdataclass.NONE
		assert len(update) == 1

		# Check update rdata
		rdata = update[0]
		assert rdata.rdclass == dns.rdataclass.IN
		assert rdata.rdtype == dns.rdatatype.TXT
		assert rdata.strings == challenge

def test_get_challenge_add_message(
	local_resolver,
	local_signer,
) -> None:
	"""Make sure we get the challenge add messages we expect.
	"""
	if local_resolver is None:
		pytest.skip('No Test DNS Server configured')
	if local_signer is None:
		pytest.skip('No Test KDC configured')

	# Make some DNS name components
	acme_challenge = dns.name.Name(labels=('_acme-challenge',))
	blargh = dns.name.Name(labels=('blargh',))
	localdomain = dns.name.from_text('localdomain')

	acme_challenge_blargh = acme_challenge + blargh
	acme_challenge_blargh_localdomain = acme_challenge_blargh + localdomain
	blargh_localdomain = blargh + localdomain

	# Make a string to use as a challenge.  We'll include every URL-safe Base64
	# character in the string.
	challenge = (
		'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
		'abcdefghijklmnopqrstuvwxyz' +
		'1234567890-_'
	)

	# Make a cleanup instance
	cleanup = sudns01.clients.challenge.Cleanup(
		blargh_localdomain,
	)

	# Make add messages
	message1 = cleanup.get_challenge_add_message(
		challenge=challenge,
		resolver=local_resolver,
		signer=local_signer,
		acme_challenge_name=acme_challenge_blargh_localdomain,
	)
	message2 = cleanup.get_challenge_add_message(
		challenge=challenge,
		resolver=local_resolver,
		signer=local_signer,
	)

	# Check message class and top-level fields
	assert isinstance(message1, dns.update.UpdateMessage)
	assert len(message1.zone) == 1
	assert len(message1.update) == 1
	assert isinstance(message2, dns.update.UpdateMessage)
	assert len(message2.zone) == 1
	assert len(message2.update) == 1

	# Check zone
	zone = message1.zone[0]
	assert zone == message2.zone[0]
	assert zone.name == localdomain

	# Check update
	update = message1.update[0]
	assert update == message2.update[0]
	assert update.name == acme_challenge_blargh
	assert update.rdclass == dns.rdataclass.IN
	assert update.rdtype == dns.rdatatype.TXT
	assert update.deleting == None
	assert len(update) == 1

	# Check update rdata
	rdata = update[0]
	assert rdata.rdclass == dns.rdataclass.IN
	assert rdata.rdtype == dns.rdatatype.TXT
	assert rdata.strings == (challenge.encode('ASCII'),)

def test_get_challenge_delete_message(
	local_resolver,
	local_signer,
) -> None:
	"""Make sure we get the challenge delete messages we expect.
	"""
	if local_resolver is None:
		pytest.skip('No Test DNS Server configured')
	if local_signer is None:
		pytest.skip('No Test KDC configured')

	# Make some DNS name components
	acme_challenge = dns.name.Name(labels=('_acme-challenge',))
	blargh = dns.name.Name(labels=('blargh',))
	localdomain = dns.name.from_text('localdomain')

	acme_challenge_blargh = acme_challenge + blargh
	acme_challenge_blargh_localdomain = acme_challenge_blargh + localdomain
	blargh_localdomain = blargh + localdomain

	# Make a string to use as a challenge.  We'll include every URL-safe Base64
	# character in the string.
	challenge = (
		'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
		'abcdefghijklmnopqrstuvwxyz' +
		'1234567890-_'
	)

	# Make a cleanup instance
	cleanup = sudns01.clients.challenge.Cleanup(
		blargh_localdomain,
	)

	# Make add messages
	message1 = cleanup.get_challenge_delete_message(
		challenge=challenge,
		resolver=local_resolver,
		signer=local_signer,
		acme_challenge_name=acme_challenge_blargh_localdomain,
	)
	message2 = cleanup.get_challenge_delete_message(
		challenge=challenge,
		resolver=local_resolver,
		signer=local_signer,
	)

	# Check message class and top-level fields
	assert isinstance(message1, dns.update.UpdateMessage)
	assert len(message1.zone) == 1
	assert len(message1.update) == 1
	assert isinstance(message2, dns.update.UpdateMessage)
	assert len(message2.zone) == 1
	assert len(message2.update) == 1

	# Check zone
	zone = message1.zone[0]
	assert zone == message2.zone[0]
	assert zone.name == localdomain

	# Check update
	update = message1.update[0]
	assert update == message2.update[0]
	assert update.name == acme_challenge_blargh
	assert update.rdclass == dns.rdataclass.IN
	assert update.rdtype == dns.rdatatype.TXT
	assert update.deleting == dns.rdataclass.NONE
	assert len(update) == 1

	# Check update rdata
	rdata = update[0]
	assert rdata.rdclass == dns.rdataclass.IN
	assert rdata.rdtype == dns.rdatatype.TXT
	assert rdata.strings == (challenge.encode('ASCII'),)
