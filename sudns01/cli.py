#!python3
# vim: ts=4 sw=4 noet

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
import argparse
import binascii
from collections.abc import Callable
import logging
import pathlib
import sys
import time
from typing import NoReturn

# PyPi imports
import dns.message
import dns.name
import dns.rcode
import dns.rdtypes.ANY.TXT
import dns.update

# local imports
import sudns01.clients.query
import sudns01.clients.resolver
import sudns01.clients.tkey
import sudns01.clients.exceptions

# Make a generic argument parser
argp = argparse.ArgumentParser(
	add_help=False,
	description='GSS-TSIG ACME DNS Updater',
    epilog=(
        'Your GSSAPI does ' + 
        ('' if sudns01.clients.tkey.HAS_CREDENTIAL_STORE else 'not ') +
        'support the Credential Store Extensions.'
    )
)
argp.add_argument('--timeout',
    help='How long to wait for a response from the DNS servers.',
    type=float,
    default=10.0,
)
argc = argp.add_mutually_exclusive_group()
argc.add_argument('--cleanup',
    help='Remove all other ACME challenge records for {name}.  THIS CAN BE DANGEROUS!',
    action='store_true',
)
argc.add_argument('--cleanup2',
    action='store',
    help=argparse.SUPPRESS,
)
argp.add_argument('--debug',
    help='Enable debug logging.  Overrides --verbose',
    action='store_true',
)
argp.add_argument('--verbose',
    help='Enable verbose logging.',
    action='store_true',
)
if sudns01.clients.tkey.HAS_CREDENTIAL_STORE:
    argp.add_argument('--ccache',
        help='Use a specific Kerberos credentials cache.  Default is to use what is defined in the environment.  Requires support from the GSSAPI and Kerberos libraries.',
    )
    argp.add_argument('--keytab',
        help='Use a specific client keytab to authenticate to the nsupdate server.  Normally a separate program (like `kinit` or `k5start` is used to obtain Kerberos credentials from a client keytab.  If set, --ccache must also be set.  Requires support from the GSSAPI and Kerberos libraries.',
        type=pathlib.Path,
    )
argp.add_argument('name',
    help='The DNS name to update, such as `example.stanford.edu`.',
)
argp.add_argument('challenge',
    help='The ACME DNS01 challenge string.',
)

# Partially set up logging
logger = logging.getLogger(__name__)
exception = logger.exception
error = logger.error
warn = logger.warning
info = logger.info
debug = logger.debug

# Handle running as a generic ACME GSS-TSIG command
def main_generic() -> NoReturn:
	# Make an argument parser for the generic command
	argp_generic = argparse.ArgumentParser(
		parents=[argp],
	)
	argp_generic.add_argument('--port',
		help='The port to use on the nsupdate server.',
		type=int,
		default=53,
	)
	argp_generic.add_argument('--udp',
		help='Force using UDP for DNS queries.  Should never be needed.',
		action='store_true',
	)
	argp_generic.add_argument('--wait',
		help='The number of minutes we wait between propagation checks.',
		type=float,
		default=1.0,
	)
	argp_generic.add_argument('nsupdate',
		help='The DNS server that handles nsupdate messages.',
	)

	# Parse arguments
	args = argp_generic.parse_args()

	# Make sure the wait time is greater than 15 seconds
	if args.wait <= (15.0/60.0):
		print('The wait time must be at least 0.25 minutes (15 seconds)')
		sys.exit(1)

	# Make a wait function
	def wait_func() -> None:
		time.sleep(args.wait * 60.0)

	# Now do the actual stuff!
	main_common(
		args,
		wait=wait_func,
	)
	
# Handle running as sudns01
def main_stanford() -> NoReturn:
	# Make an argument parser for the Stanford command
	argp_stanford = argparse.ArgumentParser(
		parents=[argp],
		description='Stanford NetDB ACME DNS Updater',
	)
	argp_stanford.add_argument('--nsupdate',
		help=argparse.SUPPRESS,
		default='acme-dns.stanford.edu',
	)
	argp_stanford.add_argument('--port',
		help=argparse.SUPPRESS,
		type=int,
		default=53,
	)
	argp_stanford.add_argument('--udp',
		help=argparse.SUPPRESS,
		action='store_true',
	)

	# Parse arguments
	args = argp_stanford.parse_args()

	# Make a wait function
	def wait_func() -> None:
		time.sleep(60)

	# Now do the actual stuff!
	main_common(
		args,
		wait=wait_func,
	)

# Do the common work!
def main_common(
	args: argparse.Namespace,
	wait: Callable[[], None],
) -> NoReturn:
	# Do top-level (program-level) logging configuration
	logging.basicConfig(
		level=(
			'DEBUG' if args.debug is True else (
				'INFO' if args.verbose is True else 'WARNING'
			)
		),
	)
	
	# Are we doing a cleanup?
	cleanup_challenge = "{:#010x}".format(
		binascii.crc32(args.name.encode('ASCII'))
	)
	if args.cleanup:
		# Tell the user what challenge to provide
		print('This option will remove other ACME Challenge TXT records for {args.name}.')
		print('THIS CAN BE DANGEROUS!  The TXT records might be in place for other reasons.')
		print(f"To cleanup anyway, change `--cleanup` to `--cleanup2 {cleanup_challenge}` and try again.")
		sys.exit(1)
	if args.cleanup2 is not None:
		# The user has set --cleanup2.  What challenge do we expect?
		debug(f"Found cleanup, expecting challenge {cleanup_challenge}")

		# If the user provided a challenge, and it does _not_ match, then tell them.
		if args.cleanup2 != cleanup_challenge:
			print(f"You provided the wrong cleanup challenge for {args.name}.")
			print(f"Change `--cleanup2 {args.cleanup2}` to `--cleanup` and try again.")
			sys.exit(1)
		else:
			# We got a valid challenge!
			info('Will cleanup other ACME challenges')

	# Parse custom Kerberos credentials config.
	CREDS: sudns01.clients.tkey.KrbCreds | None = None
	if sudns01.clients.tkey.HAS_CREDENTIAL_STORE:
		debug('We have the Credential Store Extensions')
		if args.ccache is not None or args.keytab is not None:
			CREDS = sudns01.clients.tkey.KrbCreds(
				ccache=args.ccache,
				client_keytab=args.keytab,
			)

	DNSUPDATE_SERVER: str = args.nsupdate
	DNSUPDATE_PORT: int = args.port
	DNSUPDATE_TIMEOUT: float = args.timeout
	TARGET_NAME: dns.name.Name = dns.name.from_text(args.name)
	TTL: int = 60
	CHALLENGE: bytes = args.challenge.encode('ASCII')
	dns_queries_on_udp = args.udp

	# Set up a Resolver
	dnslookup = sudns01.clients.resolver.ResolverClient()

	# From the target name (a FQDN), we need to work out:
	# * The _acme-challenge FQDN
	# * The underlying zone name
	# * The _acme-challenge name relative to the zone name
	target_domain = dnslookup.get_zone_name(
		TARGET_NAME,
		raise_on_cdname=False,
	)
	ACME_CHALLENGE_LABEL = dns.name.Name(labels=('_acme-challenge',))
	acme_challenge_name = ACME_CHALLENGE_LABEL.concatenate(TARGET_NAME)
	acme_challenge_name_relative = acme_challenge_name.relativize(target_domain)
	info(f"We will be working in domain {target_domain}")
	info(f"We will be modifying label {acme_challenge_name_relative}")

	# Get the IPs for our DNS server
	try:
		dnsupdate_server_ips = dnslookup.get_ip(DNSUPDATE_SERVER)
	except sudns01.clients.exceptions.ResolverError as e:
		print(f"Temporary error looking up {DNSUPDATE_SERVER}: {e}")
		sys.exit(2)
	except sudns01.clients.exceptions.ResolverErrorPermanent as e:
		print(f"Permanent error looking up {DNSUPDATE_SERVER}: {e}")
		sys.exit(1)
	if len(dnsupdate_server_ips) == 0:
		print(f"No IP addresses found for {DNSUPDATE_SERVER}")
		sys.exit(1)

	# Create the client for sending DNS queries
	dnsquery = sudns01.clients.query.QueryClient(
		ips=dnsupdate_server_ips,
		port=DNSUPDATE_PORT,
		timeout=DNSUPDATE_TIMEOUT,
		udp=dns_queries_on_udp,
	)

	# Set up DNS signing
	try:
		signer = sudns01.clients.tkey.GSSTSig(
			dnsquery=dnsquery,
			server=DNSUPDATE_SERVER,
			creds=CREDS,

		)
	except NotImplementedError:
		print("Your GSSAPI implementation does not have support for manipulating credential stores.")
		sys.exit(1)

	# Do cleanup first, before issuing our challenge
	if args.cleanup2 is not None:
		old_challenges = dnslookup.get_txt(
			acme_challenge_name,
			raise_on_cdname=False,
		)
		if len(old_challenges) == 0:
			debug(f"No challenge records to clean up for {acme_challenge_name}")
		for old_challenge in old_challenges:
			# if old_challenge is not a tuple, make it a tuple
			if isinstance(old_challenge, tuple):
				old_challenge_tuple = old_challenge
			else:
				old_challenge_tuple = (old_challenge,)

			# To ensure log messages print, make a tuple of strings.
			old_challenge_str = tuple(
				x.decode('ascii', 'backslashreplace')
				for x in old_challenge_tuple
			)
			info(f"Cleaning up old challenge {old_challenge_str}")

			# Construct a TXT record to target for deletion
			old_challenge_rdata = dns.rdtypes.ANY.TXT.TXT(
				rdclass=dns.rdataclass.IN,
				rdtype=dns.rdatatype.TXT,
				strings=old_challenge_tuple,
			)

			# Construct our deletion request
			old_challenge_delete = dns.update.UpdateMessage(
				zone=target_domain,
				rdclass=dns.rdataclass.IN,
				**signer.dnspython_args,
			)
			old_challenge_delete.delete(
				acme_challenge_name_relative,
				old_challenge_rdata,
			)

			# Send out the request.  If we get an exception, log a warning, but
			# otherwise continue.
			try:
				dns_delete_response = dnsquery.query(old_challenge_delete)
			except sudns01.clients.exceptions.NoServers:
				warn(f"Ran out of DNS servers to try, while trying to clean up {old_challenge_str}")
			except sudns01.clients.exceptions.DNSError:
				warn(f"DNS error - hopefully temporary, while trying to clean up {old_challenge_str}")
			if dns_delete_response.rcode() != dns.rcode.NOERROR:
				print(f"When trying to clean up a TXT record '{old_challenge_str}', received unexpected error {dns_delete_response.rcode().name} from DNS server")
				sys.exit(2)

	# Prepare our challenge record
	# Note that TXT records are tuples of byte strings, with no specific encoding.
	# Per RFC 8555 §8.4, challenge tokens only contain characters from the
	# base64url alphabet, which is a subset of ASCII.  So, we can encode as ASCII.
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
		zone=target_domain,
		rdclass=dns.rdataclass.IN,
		**signer.dnspython_args,
	)
	challenge_add.add(
		acme_challenge_name_relative,
		TTL,
		challenge_rdata,
	)

	# Send out the request
	try:
		dns_add_response = dnsquery.query(challenge_add)
		info('DNS record uploaded.  Sleeping before checking…')
	except sudns01.clients.exceptions.NoServers:
		print("Ran out of DNS servers to try")
		sys.exit(1)
	except sudns01.clients.exceptions.DNSError:
		print("DNS error - hopefully temporary!")
		sys.exit(2)
	if dns_add_response.rcode() != dns.rcode.NOERROR:
		print(f"When trying to add TXT record, received unexpected error {dns_add_response.rcode().name} from DNS server")
		sys.exit(2)

	# Close our GSS-TSIG signer.
	#
	# Per RFC 2930 §4.2 gives the DNS server the ability to dicard keys
	# whenever they want.  §5.1, we'd be told so by having a TKEY record in the
	# Additional section of the answer, with the "mode" field set to 5 (delete
	# key).  By getting rid of the key now, we avoid having to check for that
	# situation.
	#
	# Also, since our keys are based on GSSAPI/Kerberos, the lifetime of the
	# key is ultimately bound by the lifetime of the underlying Kerberos
	# ticket.  Deleting the key now lets us avoid having to check into that
	# ticket's lifetime.
	signer.close()

	# Wait for the record to appear via the system resolver
	record_found = False
	while not record_found:
		# Wait for some amount of time
		wait()

		# Do an uncached TXT lookup
		txt_records = dnslookup.get_txt(
			query=acme_challenge_name,
			cached=False,
			raise_on_cdname=False,
		)

		# Our output may contain tuples, so we can't do a simple `in` check
		for txt_record in txt_records:
			if isinstance(txt_record, bytes):
				if txt_record == CHALLENGE:
					record_found = True
					break

		if record_found:
			info('Challenge found in system DNS')
		else:
			debug('Challenge not found.  Sleeping…')

	# Wait to do the deletion
	input('Record found in system DNS!  Press Return to delete the record')

	# Remove the new ACME Challenge record

	# Make a new GSS-TSIG signer, which will be cleaned up when the program ends.
	signer = sudns01.clients.tkey.GSSTSig(
		dnsquery=dnsquery,
		server=DNSUPDATE_SERVER,
		creds=CREDS,

	)

	# Create the Delete request
	challenge_delete = dns.update.UpdateMessage(
		zone=target_domain,
		rdclass=dns.rdataclass.IN,
		**signer.dnspython_args,
	)
	challenge_delete.delete(
		acme_challenge_name_relative,
		challenge_rdata,
	)

	# Send out the request
	try:
		dns_delete_response = dnsquery.query(challenge_delete)
	except sudns01.clients.exceptions.NoServers:
		print("Ran out of DNS servers to try")
		sys.exit(1)
	except sudns01.clients.exceptions.DNSError:
		print("DNS error - hopefully temporary!")
		sys.exit(2)

	# All done!
	debug('Exiting successfully!')
	sys.exit(0)
