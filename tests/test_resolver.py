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

import dns.name
import dns.resolver
import os
import pytest

import sudns01.clients.exceptions
import sudns01.clients.resolver

resolver = sudns01.clients.resolver.ResolverClient()

# Set up a resolver client pointing to a DNS server that doesn't exist.
# 192.0.2.0/24 is defined within RFC 5735.
# Since we'll never get results, no need for a cache.
bad_resolver_resolver = dns.resolver.Resolver(configure=False)
bad_resolver_resolver.nameservers = ['192.0.2.1']
bad_resolver_resolver.timeout = 0.1
bad_resolver_resolver.lifetime = 0.1
bad_resolver = sudns01.clients.resolver.ResolverClient()
bad_resolver._resolver = bad_resolver_resolver
bad_resolver._resolver_nocache = bad_resolver_resolver

# Set up a resolver client pointing to a local test DNS server.
# NOTE: Only use this resolver if the "dns" mark is set for pytest, and (of
# course) if the DNS server is actually available!
local_resolver: sudns01.clients.resolver.ResolverClient | None = None
if 'TEST_DNS_PORT' in os.environ:
    local_resolver_resolver = dns.resolver.Resolver(configure=False)
    local_resolver_resolver.nameservers = ['127.0.0.1']
    local_resolver_resolver.port = int(os.environ['TEST_DNS_PORT'])
    local_resolver_resolver.timeout = 0.1
    local_resolver_resolver.lifetime = 0.1
    local_resolver = sudns01.clients.resolver.ResolverClient()
    local_resolver._resolver = local_resolver_resolver
    local_resolver._resolver_nocache = local_resolver_resolver

def test_get_ip_good() -> None:
	results = resolver.get_ip('web.stanford.edu')

	# web.stanford.edu points to a single v4 and a single v6 IP.
	assert '171.67.215.200' in results
	assert '2607:f6d0:0:925a::ab43:d7c8' in results
	assert len(results) == 2

def test_get_ip_nxdomain() -> None:
	results = resolver.get_ip('example.invalid')

	# .invalid comes from RFC 2606
	assert len(results) == 0

def test_get_ip_yxdomain() -> None:
    if local_resolver is None:
        pytest.skip('No Test DNS Server configured')
    with pytest.raises(sudns01.clients.exceptions.ResolverErrorPermanent):
        results = local_resolver.get_ip('1234567890.1234567890.1234567890.1234567890.1234567890.d.localdomain')

def test_get_ip_noresponse() -> None:
	with pytest.raises(sudns01.clients.exceptions.ResolverError):
		results = bad_resolver.get_ip('example.com')

def test_get_txt_good() -> None:
	results = resolver.get_txt('example.com')

	# example.com has an SPF record saying that nobody sends mail from it.
	assert b'v=spf1 -all' in results

def test_get_txt_nxdomain() -> None:
	results = resolver.get_txt('example.invalid')
	assert len(results) == 0

def test_get_txt_yxdomain() -> None:
    if local_resolver is None:
        pytest.skip('No Test DNS Server configured')
    with pytest.raises(sudns01.clients.exceptions.ResolverErrorPermanent):
        results = local_resolver.get_txt('1234567890.1234567890.1234567890.1234567890.1234567890.d.localdomain')

def test_get_txt_noresponse() -> None:
	with pytest.raises(sudns01.clients.exceptions.ResolverError):
		results = bad_resolver.get_txt('example.com')

def test_get_txt_norecords() -> None:
	results = resolver.get_txt(
		'www.example.com',
		raise_on_cdname=False,
	)
	assert len(results) == 0

def test_get_zone_name_good() -> None:
	assert str(resolver.get_zone_name('smtp.stanford.edu')) == 'stanford.edu.'

	assert str(resolver.get_zone_name('stanford.edu')) == 'stanford.edu.'

	# www.stanford.edu is a CNAME
	results = resolver.get_zone_name(
		'www.stanford.edu',
		raise_on_cdname=False,
	)
	assert str(results) == 'stanford.edu.'

def test_get_zone_name_relative() -> None:
	name=dns.name.Name(labels=('hello',))
	with pytest.raises(ValueError):
		results = resolver.get_zone_name(name)

def test_get_zone_name_cdname() -> None:
	# www.stanford.edu is a CNAME
	with pytest.raises(sudns01.clients.exceptions.ResolverErrorCDName):
		results = resolver.get_zone_name('www.stanford.edu')

def test_get_zone_name_nxdomain() -> None:
	with pytest.raises(sudns01.clients.exceptions.ResolverErrorPermanent):
		assert resolver.get_zone_name('example.invalid')

def test_get_zone_name_yxdomain() -> None:
    if local_resolver is None:
        pytest.skip('No Test DNS Server configured')
    with pytest.raises(sudns01.clients.exceptions.ResolverErrorPermanent):
        results = local_resolver.get_zone_name('1234567890.1234567890.1234567890.1234567890.1234567890.d.localdomain')

def test_get_zone_name_noresponse() -> None:
	with pytest.raises(sudns01.clients.exceptions.ResolverError):
		results = bad_resolver.get_zone_name('www.stanford.edu')
