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

# Stdlib imports
import os

# PyPi imports
import dns.name
import dns.resolver
import pytest

# Local imports
import sudns01.clients.exceptions
import sudns01.clients.resolver


# Make some fixtures
@pytest.fixture
def resolver() -> sudns01.clients.resolver.ResolverClient:
	"""Get a normal DNS resolver, using the system's resolver configuration.
	"""
	return sudns01.clients.resolver.ResolverClient()

@pytest.fixture
def bad_resolver() -> sudns01.clients.resolver.ResolverClient:
	"""Return a resolver pointing to a DNS server that doesn't exist.

	192.0.2.0/24 is defined within RFC 5735.
	"""
	# Since we'll never get results, no need for a cache.
	bad_resolver_resolver = dns.resolver.Resolver(configure=False)
	bad_resolver_resolver.nameservers = ['192.0.2.1']
	bad_resolver_resolver.timeout = 0.1
	bad_resolver_resolver.lifetime = 0.1
	bad_resolver = sudns01.clients.resolver.ResolverClient()
	bad_resolver._resolver = bad_resolver_resolver
	bad_resolver._resolver_nocache = bad_resolver_resolver
	return bad_resolver

@pytest.fixture
def local_resolver() -> sudns01.clients.resolver.ResolverClient | None:
	"""Return a resolver pointing to the local test DNS server.

	NOTE: Only use this resolver if the DNS server is actually available!
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


# Now, our tests
def test_get_ip_good(resolver) -> None:
	results = resolver.get_ip('web.stanford.edu')

	# web.stanford.edu points to a single v4 and a single v6 IP.
	assert '171.67.215.200' in results
	assert '2607:f6d0:0:925a::ab43:d7c8' in results
	assert len(results) == 2

def test_get_ip_nxdomain(resolver) -> None:
	results = resolver.get_ip('example.invalid')

	# .invalid comes from RFC 2606
	assert len(results) == 0

def test_get_ip_yxdomain(local_resolver) -> None:
    if local_resolver is None:
        pytest.skip('No Test DNS Server configured')
    with pytest.raises(sudns01.clients.exceptions.ResolverErrorPermanent):
        results = local_resolver.get_ip('1234567890.1234567890.1234567890.1234567890.1234567890.d.localdomain')

def test_get_ip_noresponse(bad_resolver) -> None:
	with pytest.raises(sudns01.clients.exceptions.ResolverError):
		results = bad_resolver.get_ip('example.com')

def test_get_txt_good(resolver) -> None:
	results = resolver.get_txt('example.com')

	# example.com has an SPF record saying that nobody sends mail from it.
	assert b'v=spf1 -all' in results

def test_get_txt_nxdomain(resolver) -> None:
	results = resolver.get_txt('example.invalid')
	assert len(results) == 0

def test_get_txt_yxdomain(local_resolver) -> None:
    if local_resolver is None:
        pytest.skip('No Test DNS Server configured')
    with pytest.raises(sudns01.clients.exceptions.ResolverErrorPermanent):
        results = local_resolver.get_txt('1234567890.1234567890.1234567890.1234567890.1234567890.d.localdomain')

def test_get_txt_noresponse(bad_resolver) -> None:
	with pytest.raises(sudns01.clients.exceptions.ResolverError):
		results = bad_resolver.get_txt('example.com')

def test_get_txt_norecords(resolver) -> None:
	results = resolver.get_txt(
		'www.example.com',
		raise_on_cdname=False,
	)
	assert len(results) == 0

def test_get_zone_name_good(resolver) -> None:
	assert str(resolver.get_zone_name('smtp.stanford.edu')) == 'stanford.edu.'

	assert str(resolver.get_zone_name('stanford.edu')) == 'stanford.edu.'

	# www.stanford.edu is a CNAME
	results = resolver.get_zone_name(
		'www.stanford.edu',
		raise_on_cdname=False,
	)
	assert str(results) == 'fastly.net.'

def test_get_zone_name_relative(resolver) -> None:
	name=dns.name.Name(labels=('hello',))
	with pytest.raises(ValueError):
		results = resolver.get_zone_name(name)

def test_get_zone_name_cdname(resolver) -> None:
	# www.stanford.edu is a CNAME
	with pytest.raises(sudns01.clients.exceptions.ResolverErrorCDName):
		results = resolver.get_zone_name('www.stanford.edu')

def test_get_zone_name_nxdomain(resolver) -> None:
	with pytest.raises(sudns01.clients.exceptions.ResolverErrorPermanent):
		assert resolver.get_zone_name('example.invalid')

def test_get_zone_name_yxdomain(local_resolver) -> None:
    if local_resolver is None:
        pytest.skip('No Test DNS Server configured')
    with pytest.raises(sudns01.clients.exceptions.ResolverErrorPermanent):
        results = local_resolver.get_zone_name('1234567890.1234567890.1234567890.1234567890.1234567890.d.localdomain')

def test_get_zone_name_noresponse(bad_resolver) -> None:
	with pytest.raises(sudns01.clients.exceptions.ResolverError):
		results = bad_resolver.get_zone_name('www.stanford.edu')
