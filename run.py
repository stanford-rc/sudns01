#!python3
#vim: ts=4 sw=4 noet

# This is a demo script to show how ACME DNS-01 challenge records can be pushed
# to Stanford DNS using the GSSAPI/Kerberos authentication with host keytabs.
# The demo uses the host keytab for `blargh.stanford.edu`, adds a "challenge"
# phrase into DNS, and (after you press a key) deletes the challenge from DNS.

# The inspiration came from certbot issue #7370[1], which requested GSS-TSIG
# support for certbot's existing RFC2136 plugin.
# [1]: https://github.com/certbot/certbot/issues/7370

# This work relies on a number of RFCs:
# * RFC 2136 defines a way for DNS clients to send updates to a DNS server.  But
#   the process lacks a way to ensure updates are authenticated.
# * RFC 2845 defines a way to authenticate a transaction using a shared secret
#   and hashes of records.  The signature is placed at the end of the
#   "Additional data" section of a DNS query or response.
# * RFC 2930 defines a way to establish a shared secret with a DNS server.  It
#   defines GSSAPI (or "GSS-API") as a mechanism, but doesn't go into detail.
# * RFC 3645 defined how GSSAPI is used, on top of both RFC 2845 and RFC 2930.
#   The RFC refers to it as "gss-tsig".
# Since RFC 2930 and RFC 2845 are related, folks will typicall just mention RFC
# 2930, even if they mean to refer to both.

# All of this is doable thanks to dnspython PR #530[2], which updated dnspython
# to support gss-tsig.  Thanks go out to GitHub users…
# * @bwelling (Brian Wellington)
# * @nrhall (Nick Hall)
# And @rthalley (Bob Halley), maintainer of dnspython
# [2]: https://github.com/rthalley/dnspython/pull/530

# With that PR implemented, GitHub user @grawity (Mantas Mikulėnas) created
# certbot PR #3482[2].  certbot already has an RFC 2136 plugin; this PR modified
# it to add GSSAPI support.  However, the Certbot maintainers have pushed back
# on the request, as proper testing requires Kerberos authentication
# infrastructure.  As of 2022, there were thoughts about making a separate
# plugin specifically for RFC2136 gss-tsig updates.
# [3]: https://github.com/certbot/certbot/pull/9482

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

# The minimum required Python version is 3.10.  That is because the code uses
# PEP 604 union types (`int | None` instead of `Optional[int]`, for example).

# The minimum required dnspython version is 2.6.1: This release fixed a
# security issue in dnspython's DNS resolver.

# The minimum required python-gssapi version is 1.8.0, which added PEP
# 517-compliant source.
# Kerberos-related GSSAPI improvements were made in 1.7.0.

# Of course, bug fixes may mean that the required versions are newer.


# stdlib imports
import base64
import dataclasses
import datetime
import logging
import pathlib
import secrets
import socket
import sys
import tempfile
import time

# PyPi imports
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TKEY
import dns.rdtypes.ANY.TXT
import dns.resolver
import dns.tsig
import dns.update
import gssapi

# local imports
import clients

# Set up logging
logging.basicConfig(
    level='DEBUG',
)

logger = logging.getLogger(__name__)
exception = logger.exception
error = logger.error
warn = logger.warning
info = logger.info
debug = logger.debug

@dataclasses.dataclass()
class KrbCreds:
    ccache: pathlib.Path | str
    client_keytab: pathlib.Path | None

DNSUPDATE_SERVER: str = 'acme-dns.stanford.edu'
DNSUPDATE_PORT: int = 53
DNSUPDATE_TIMEOUT: float = 10.0
# TODO: Work out TARGET_DOMAIN automatically
TARGET_NAME: dns.name.Name = dns.name.from_text('blargh.stanford.edu')
TARGET_DOMAIN: dns.name.Name = dns.name.from_text('stanford.edu')
TTL: int = 60
CHALLENGE: str = ('hello ' + str(datetime.datetime.now()))
CREDS: KrbCreds | None = None

dns_queries_on_udp = False
ACME_CHALLENGE_LABEL = dns.name.Name(labels=('_acme-challenge',))
acme_challenge_name = ACME_CHALLENGE_LABEL.concatenate(TARGET_NAME)
acme_challenge_name_relative = acme_challenge_name.relativize(TARGET_DOMAIN)
info(f"We will be working in domain {TARGET_DOMAIN}")
info(f"We will be modifying label {acme_challenge_name_relative}")

# Set up a Resolver
dnslookup = clients.ResolverClient()

# Get the IPs for our DNS server
try:
    dnsupdate_server_ips = dnslookup.get_ip(DNSUPDATE_SERVER)
except resolver.ResolverError as e:
    print(f"Temporary error: {e}")
    sys.exit(2)
except resolver.ResolverErrorPermanent as e:
    print(f"Permanent error: {e}")
    sys.exit(1)
if len(dnsupdate_server_ips) == 0:
    print(f"No IP addresses found for {DNSUPDATE_SERVER}")
    sys.exit(1)

# Prep DNS TKEY authentication, including GSSAPI.

# Start by loading in our GSSAPI credentials.
# We might use environment variables, or we might accept a credentials cache
# and keytab path directly.
if CREDS is None:
    debug('Initiate GSSAPI from environment')
    gss_creds = gssapi.Credentials(
        usage='initiate',
    )
else:
    debug(f"Initiate GSSAPI with keytab {CREDS.client_keytab} and cache {CREDS.ccache}")
    try:
        gss_creds = gssapi.Credentials(
            usage='initiate',
            store={
                'client_keytab': str(CREDS.client_keytab),
                'ccache': str(CREDS.ccache)
            },
        )
    except NotImplementedError:
        error("Your GSSAPI implementation does not have support for manipulating credential stores.")
        sys.exit(0)

# Now, turn the DNS server name into a Kerberos principal.
# The service name is "DNS", and the hostbased-service name format uses an
# @-character as a separator, instead of a forward-slash.
gss_dnsupdate_principal = gssapi.Name(
    ('DNS@' + str(DNSUPDATE_SERVER)),
    gssapi.NameType.hostbased_service,
)

# Make our GSSAPI Context, which contans the credentials & the service we're
# going to get a ticket for.
gss_ctx = gssapi.SecurityContext(
    name=gss_dnsupdate_principal,
    creds=gss_creds,
    usage='initiate',
)

# Now, let's focus on the TKEY part.  RFC 2930 is helpful here!

# A key is associated with a DNS name: keystr.domain.
# keystr is something random.  domain is the dnsupdate server's FQDN.
# There are two restrictions on length:
# * Per RFC Section 2.1, len(keystr + '.' + domain) should be less than 128
# * Individual DNS label length must be less than 64, so len(keystr) < 64
# * Per Latacora's Cryptographic right answers, a 256-bit random number is OK,
#   which is 32 bytes.
#  secrets.token_hex(32) gives a 64-character string.  We'll take up to 63
#  characters.
dnskey_keystr_max_len = min(63, (128 - len(DNSUPDATE_SERVER) - 1))
dnskey_keystr = secrets.token_hex(32)[0:dnskey_keystr_max_len]
dnskey_keystr_name = dns.name.Name(labels=(dnskey_keystr,))
dnskey_key_name = dnskey_keystr_name.concatenate(
    dns.name.from_text(DNSUPDATE_SERVER)
)
debug(f"Using {dnskey_keystr_max_len}-char TKEY name {dnskey_key_name}")

# Make a TSIG Key, using our random name and our Kerberos context, then put it
# into a single-key keyring.
dnskey_tsig_key = dns.tsig.Key(
    name=dnskey_key_name,
    secret=gss_ctx,
    algorithm=dns.tsig.GSS_TSIG,
)
dnskey_tsig_keyring = dns.tsig.GSSTSigAdapter(
    keyring={
        dnskey_key_name: dnskey_tsig_key,
    }
)

# Auth to the DNS server

# GSSAPI Authentication is performed by going through a number of
# request-response cycles with the server.  The number of cycles depends
# primarily on if we already have a valid Kerberos ticket.  Regardless, we
# continue looping until the GSSAPI Context tells us that we are complete.
gss_step: bytes | None = dnskey_tsig_key.secret.step(None)
while (gss_step is not None) and (dnskey_tsig_key.secret.complete is not True):
    debug(f"Doing GSSAPI Step with {gss_step}")

    # Construct a DNS Query.

    # Start by constructing our DNS TKEY record, to add to the query.
    # Per RFC 2930 Section 4.3, the inception & expiration times are ignored.
    # Mode 3 is GSSAPI Negotiation.
    gss_step_request_tkey = dns.rdtypes.ANY.TKEY.TKEY(
        rdclass=dns.rdataclass.ANY,
        rdtype=dns.rdatatype.TKEY,
        algorithm=dns.tsig.GSS_TSIG,
        inception=0,
        expiration=0,
        mode=3,
        error=dns.rcode.NOERROR,
        key=gss_step,
    )

    # Make our query, which will be against the unique DNS name (the "key
    # name") that we randomly generated.
    # Then, add the keyring (since we can't set that via the constructor)
    gss_step_request = dns.message.make_query(
        qname=dnskey_key_name,
        rdclass=dns.rdataclass.ANY,
        rdtype=dns.rdatatype.TKEY
    )
    gss_step_request.keyring = dnskey_tsig_keyring

    # Add our TKEY record to the additional portion of the query
    gss_step_request_rrset = gss_step_request.find_rrset(
        section=dns.message.ADDITIONAL,
        name=dnskey_key_name,
        rdclass=dns.rdataclass.ANY,
        rdtype=dns.rdatatype.TKEY,
        create=True
    )
    gss_step_request_rrset.add(gss_step_request_tkey)

    # Send out the query!

    # Try TCP first, then fall back to UDP
    try:
        print("REQUEST")
        print(gss_step_request)
        debug("Trying DNS query")
        gss_step_response = dns.query.tcp(
            gss_step_request,
            where=dnsupdate_server_ips[0],
            port=DNSUPDATE_PORT,
            timeout=DNSUPDATE_TIMEOUT,
        )
    except (OSError, dns.exception.Timeout) as e:
        info("DNS server not responding on TCP, falling back to UDP")
        dns_queries_on_udp = True
        gss_step_response = dns.query.udp(
            gss_step_request,
            where=dnsupdate_server_ips[0],
            port=DNSUPDATE_PORT,
            timeout=DNSUPDATE_TIMEOUT,
        )
    print("RESPONSE")
    print(gss_step_response)

    # Upon receipt of the response, we may already be complete.
    # If not complete, then run another step
    if dnskey_tsig_key.secret.complete is False:
        debug('We need to run another GSSAPI step')
        gss_step = dnskey_tsig_key.secret.step(gss_step_response.answer[0][0].key)

if not dnskey_tsig_key.secret.complete:
    print('Error!')
    sys.exit(1)
else:
    print('GSSAPI Negotiation Complete!')

# Prepare our challenge record
challenge_rdata = dns.rdtypes.ANY.TXT.TXT(
    rdclass=dns.rdataclass.IN,
    rdtype=dns.rdatatype.TXT,
    strings=(
        CHALLENGE,
    ),
)

# Add a new ACME Challenge record

# Create the Add request
challenge_add = dns.update.UpdateMessage(
    zone=TARGET_DOMAIN,
    rdclass=dns.rdataclass.IN,
    keyring=dnskey_tsig_keyring,
    keyname=dnskey_key_name,
    keyalgorithm=dns.tsig.GSS_TSIG,
)
challenge_add.add(
    acme_challenge_name_relative,
    TTL,
    challenge_rdata,
)

# Send out the request
print("REQUEST")
print(challenge_add)
if dns_queries_on_udp is True:
    debug("Trying DNS query")
    dns_add_response = dns.query.tcp(
        challenge_add,
        where=dnsupdate_server_ips[0],
        port=DNSUPDATE_PORT,
        timeout=DNSUPDATE_TIMEOUT,
    )
else:
    dns_add_response = dns.query.udp(
        challenge_add,
        where=dnsupdate_server_ips[0],
        port=DNSUPDATE_PORT,
        timeout=DNSUPDATE_TIMEOUT,
    )
print("RESPONSE")
print(dns_add_response)

# Wait to do the deletion
input('Press Return to delete the record')

# Remove the new ACME Challenge record

# Create the Delete request
challenge_delete = dns.update.UpdateMessage(
    zone=TARGET_DOMAIN,
    rdclass=dns.rdataclass.IN,
    keyring=dnskey_tsig_keyring,
    keyname=dnskey_key_name,
    keyalgorithm=dns.tsig.GSS_TSIG,
)
#challenge_delete_rdata = dns.rdtypes.ANY.TXT.TXT(
#    rdclass=dns.rdataclass.IN,
#    rdtype=dns.rdatatype.TXT,
#    strings=(
#        "challenge accepted 202502111103",
#    ),
#)
challenge_delete.delete(
    acme_challenge_name_relative,
    challenge_rdata,
)

# Send out the request
print("REQUEST")
print(challenge_delete)
if dns_queries_on_udp is True:
    debug("Trying DNS query")
    dns_delete_response = dns.query.tcp(
        challenge_delete,
        where=dnsupdate_server_ips[0],
        port=DNSUPDATE_PORT,
        timeout=DNSUPDATE_TIMEOUT,
    )
else:
    dns_delete_response = dns.query.udp(
        challenge_delete,
        where=dnsupdate_server_ips[0],
        port=DNSUPDATE_PORT,
        timeout=DNSUPDATE_TIMEOUT,
    )
print("RESPONSE")
print(dns_delete_response)
