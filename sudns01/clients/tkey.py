#!python3
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

# Stdlib imports
import dataclasses
import logging
import pathlib
import secrets
import time
import typing

# PyPi imports
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes
import dns.rdtypes.ANY.TKEY
import dns.tsig
import gssapi

# local imports
import sudns01.clients.exceptions
import sudns01.clients.query

# Set up logging
logger = logging.getLogger(__name__)
exception = logger.exception
error = logger.error
warn = logger.warning
info = logger.info
debug = logger.debug


# Check if we have support for the Kerberos Credential Store Extension, and
# provide a way to configure it.
HAS_CREDENTIAL_STORE: bool
"""Does the underlying GSSAPI library support the Kerberos Credential Store Extension?
"""

if 'acquire_cred_from' in dir(gssapi.raw):
	HAS_CREDENTIAL_STORE=True
else:
	HAS_CREDENTIAL_STORE=False

@dataclasses.dataclass()
class KrbCreds:
	"""Kerberos Credential Store Extension configuration

	If the Kerberos Credential Store Extension is available, you can
	instantiate this class to configure it.
	"""

	ccache: str
	"""A custom credentials cache to use.

	Normally the shared credentials cache is used, either the one specified in
	the `KRB5CCNAME` environment variable, or the default specified by the
	underlying Kerberos library.  This lets you set a specific credentials
	cache to use.
	"""

	client_keytab: pathlib.Path | None
	"""A Keytab to use

	Normally, a tool like `kinit` or `k5start` is needed to get a Kerberos
	credential.

	If you specify this, you must also specify a custom credentials cache.
	"""

class GSSTSig():
	"""

    :param queryclient: A client for making DNS queries.

	:param server: The nsupdate server fully-qualified domain name.

	:param creds: Custom Kerberos credentials to to use: A custom credentials cache, and optionally a keytab.  If not defined, use the credentials cache from the environment, or the default credential cache.  Using this requires support for the Kerberos Credential Store Extension.

	:param krb5_service: The Kerberos 5 service name to use when obtaining a Kerberos ticket for nsupdate.  This is normally "DNS".
	"""

	_closed: bool
	_dnsquery: sudns01.clients.query.QueryClient
	_server: str
	_key: dns.tsig.Key
	_keyname: dns.name.Name
	_keyring: dns.tsig.GSSTSigAdapter

	def __init__(
		self,
        dnsquery: sudns01.clients.query.QueryClient,
		server: str,
		creds: KrbCreds | None = None,
		krb5_service: str = 'DNS',
	) -> None:
		"""

		:raises NotImplementedError: You tried providing custom credentials, but the GSSAPI library or Kerberos installation do not support it.

		:raises gssapi.exceptions.GSSError: A GSSAPI or Kerberos error occurred, either in the process of obtaining Kerberos credentials, getting a Kerberos ticket or in the GSSAPI negotiation with the DNS server.

		:raises clients.exceptions.NoServers: We were unable to communicate with the DNS server.

		:raises clients.exceptions.DNSError: We were able to communicate with the DNS server, but there was an error.
		"""
		debug(
			f"Instantiating Signer for server {krb5_service}/{server}" +
			(' with custom creds' if creds is not None else '')
		)
		self._closed = False

		# Start by storing our server and Kerberos credentials
		self._dnsquery = dnsquery
		self._server = server

		# Prep our Kerberos stuff

		# Turn the DNS server name into a Kerberos principal.
		# The hostbased-service name format uses an @-character as a separator,
		# instead of a forward-slash.
		debug(f"Server principal is {krb5_service}@{server}")
		principal = gssapi.Name(
			(krb5_service + '@' + server),
			gssapi.NameType.hostbased_service,
		)

		# Load in our DNS credentials
		# We might use environment variables, or we might accept a credentials cache
		# and keytab path directly.
		if creds is None:
			debug('Initiate GSSAPI from environment')
			gss_creds = gssapi.Credentials(
				usage='initiate',
			)
		else:
			debug(f"Initiate GSSAPI with keytab {creds.client_keytab} and cache {creds.ccache}")
			try:
				gss_creds = gssapi.Credentials(
					usage='initiate',
					store={
						'client_keytab': str(creds.client_keytab),
						'ccache': creds.ccache,
					},
				)
			except NotImplementedError:
				raise


		# Make our Kerberos Context, which contans the credentials & the
		# service we're going to get a ticket for.
		gss_ctx = gssapi.SecurityContext(
			name=principal,
			creds=gss_creds,
			usage='initiate',
		)

		# Prep the DNS TKEY parameters.  RFC 2930 is helpful here!

		# A key is associated with a DNS name: keystr.domain.
		# keystr is something random.  domain is the dnsupdate server's FQDN.
		# There are two restrictions on length:
		# * Per RFC Section 2.1, len(keystr + '.' + domain) should be less than 128
		# * Individual DNS label length must be less than 64, so len(keystr) < 64
		# * Per Latacora's Cryptographic right answers, a 256-bit random number is OK,
		#   which is 32 bytes.
		#  secrets.token_hex(32) gives a 64-character string.  We'll take up to 63
		#  characters.
		dnskey_keystr_max_len = min(63, (128 - len(server) - 1))
		dnskey_keystr = secrets.token_hex(32)[0:dnskey_keystr_max_len]
		dnskey_keystr_name = dns.name.Name(labels=(dnskey_keystr,))
		self._keyname = dnskey_keystr_name.concatenate(
			dns.name.from_text(server)
		)
		debug(f"Using {dnskey_keystr_max_len}-char TKEY name {self._keyname}")

		# Make a TSIG Key, using our random name and our Kerberos context, then put it
		# into a single-key keyring.
		self._key = dns.tsig.Key(
			name=self._keyname,
			secret=gss_ctx,
			algorithm=dns.tsig.GSS_TSIG,
		)
		self._keyring = dns.tsig.GSSTSigAdapter(
			keyring={
				self._keyname: self._key,
			}
		)

		# Generate our TKEY record, then we're done!
		self._do_auth()
		return

	def _do_auth(
        self,
    ) -> None:
		"""Authenticate us to the DNS server, creating a TKEY record.

		This method does the work of creating a TKEY record on the DNS server.
		At the end, we will have a TKEY record negotiated with the server,
		which will be used (by client code) to sign nsupdate messages.

		To do this, we create a special DNS query.  It will be a query for an
		"ANY TKEY" record, whose name is randomly-generated by us.  In the
		ADDITIONAL section will be an ANY TKEY record of our own, using the
		same randomly-generated name, that will contain Step 1 of the GSSAPI
		negotiation.

		We include our (currently-nascent) keyring in the request, which
		dnspython will call to execute Step 2 of the GSSAPI negotiation.

		GSSAPI/Kerberos negotiation only needs two steps, so that is all we
		support.

		:raises gssapi.exceptions.GSSError: A GSSAPI or Kerberos error occurred, either in the process of getting a Kerberos ticket or in the GSSAPI negotiation.

		:raises clients.exceptions.NoServers: We were unable to communicate with the DNS server.

		:raises clients.exceptions.DNSError: We were able to communicate with the DNS server, but there was an error.
		"""
		if self.closed:
			raise TypeError('This Signer has already been closed!')

		# We'll be doing a lot of work with our GSSAPI context, so grab it.
		gss_ctx = self.key.secret

		# GSSAPI Authentication is performed by going through a number of
		# request-response cycles with the server.  For Kerberos 5, the process
        # looks like this:
        # 0. The client (us) gets a Kerberos ticket for the server.
        # 1. The client sends a message to the server, containing the ticket.
        # 2. The server sends a response message.
        #
        # dnspython's GSS-TSIG support only supports this two-step
        # authentication process.  Some GSSAPI mechanisms require more steps.

        # Begin step 1
		gss_step1: bytes = gss_ctx.step(None)
		debug('Doing GSSAPI Step 1')

        # Construct a DNS Query to send Step 1 to the server.

        # Start by constructing our DNS TKEY record, to add to the query.
        # Per RFC 2930 Section 4.3, the inception & expiration times are ignored.
        # Mode 3 is GSSAPI Negotiation.
		gss_step_request_tkey = dns.rdtypes.ANY.TKEY.TKEY(
			rdclass=dns.rdataclass.ANY,
			rdtype=dns.rdatatype.TKEY,
			algorithm=dns.tsig.GSS_TSIG,
			inception=0,
			expiration=0,
			mode=dns.rdtypes.ANY.TKEY.TKEY.GSSAPI_NEGOTIATION,
			error=dns.rcode.NOERROR,
			key=gss_step1,
		)

		# Make our query, which will be against the unique DNS name (the "key
		# name") that we randomly generated.
		# Then, add the keyring (since we can't set that via the constructor)
		gss_step_request = dns.message.make_query(
			qname=self.keyname,
			rdclass=dns.rdataclass.ANY,
			rdtype=dns.rdatatype.TKEY
		)
		gss_step_request.keyring = self.keyring

		# Add our TKEY record to the additional portion of the query
		gss_step_request_rrset = gss_step_request.find_rrset(
			section=dns.message.ADDITIONAL,
			name=self.keyname,
			rdclass=dns.rdataclass.ANY,
			rdtype=dns.rdatatype.TKEY,
			create=True,
		)
		gss_step_request_rrset.add(gss_step_request_tkey)

		# Send out the query!
		# Upon receipt of the query, dnspython automatically pulls out the
		# GSSAPI Step 2 message, and sends it to the GSSAPI context.
		# NOTE: The clients.exceptions.NoServers and
		# clients.exceptions.DNSError exceptions are passed through to the
		# caller.
		gss_step_response = self._dnsquery.query(gss_step_request)

		# Since we don't support more than two GSSAPI steps, we either finished
		# negotiation, or we failed.
		if gss_ctx.complete:
			debug('GSSAPI Negotiation complete!')
			return
		else:
			error('GSSAPI Negotiation incomplete; bailing out')
			raise NotImplementedError('Only two GSSAPI rounds are supported')

	def close(self) -> None:
		"""Clean up and stop using a signer. 

		This attempts to clean up the TKEY that was created on the DNS seerver,
		per RFC 3645 §3.2.1.

		The GSSAPI context is not cleaned up explicitly.  Per the gssapi
		package's low-level API, cleanup is handled automatically.
		"""
		debug(f"Cleaning GSSTSig for {self._keyname}")

		# We need something from our GSSAPI context
		gss_ctx = self.key.secret

		# Create a TKEY record with the mode set to 5 (delete key).
		# There's no clarity on if the inception and expiration times are used
		# for key-deletions, so set them to now and now-plus-one-minute.
		# There's also no clarity on what key data is sent, so send nothing.
		gss_delete_request_tkey = dns.rdtypes.ANY.TKEY.TKEY(
			rdclass=dns.rdataclass.ANY,
			rdtype=dns.rdatatype.TKEY,
			algorithm=dns.tsig.GSS_TSIG,
			inception=int(time.time()),
			expiration=int(time.time()) + 60,
			mode=dns.rdtypes.ANY.TKEY.TKEY.KEY_DELETION,
			error=dns.rcode.NOERROR,
			key=b'',
		)

		# Make our query against our existng key name.
		# (The keyring etc. will be added later)
		gss_delete_request = dns.message.make_query(
			qname=self.keyname,
			rdclass=dns.rdataclass.ANY,
			rdtype=dns.rdatatype.TKEY,
		)

		# Add our TKEY record to the additional portion of the query
		gss_delete_request_rrset = gss_delete_request.find_rrset(
			section=dns.message.ADDITIONAL,
			name=self.keyname,
			rdclass=dns.rdataclass.ANY,
			rdtype=dns.rdatatype.TKEY,
			create=True,
		)
		gss_delete_request_rrset.add(gss_delete_request_tkey)

		# Our query message should be signed
		# (We can't use self.dnspython_args, because this method has the
		# 'algorithm' parameter name, instead of 'keyalgorithm')
		gss_delete_request.use_tsig(
			keyring=self.keyring,
			keyname=self.keyname,
			algorithm=dns.tsig.GSS_TSIG,
		)

		# Send the deletion.  We don't care about DNS-related issues.
		try:
			self._dnsquery.query(gss_delete_request)
		except sudns01.clients.exceptions.ClientError:
			pass

		# Delete the GSSAPI context and mark our instance as closed.
		gss_delete_token = gssapi.raw.delete_sec_context(gss_ctx)
		self._closed = True

	def __del__(self) -> None:
		if not self.closed:
			self.close()

	@property
	def closed(self) -> bool:
		return self._closed

	@property
	def server(self) -> str:
		if self.closed:
			raise TypeError('This Signer has already been closed!')
		return self._server

	@property
	def key(self) -> dns.tsig.Key:
		if self.closed:
			raise TypeError('This Signer has already been closed!')
		return self._key

	@property
	def keyname(self) -> dns.name.Name:
		if self.closed:
			raise TypeError('This Signer has already been closed!')
		return self._keyname

	@property
	def keyname_str(self) -> str:
		if self.closed:
			raise TypeError('This Signer has already been closed!')
		return str(self.keyname)

	@property
	def keyring(self) -> dns.tsig.GSSTSigAdapter:
		if self.closed:
			raise TypeError('This Signer has already been closed!')
		return self._keyring

	class DNSPythonArgs(typing.TypedDict):
		keyring: dns.tsig.GSSTSigAdapter
		keyname: dns.name.Name
		keyalgorithm: dns.name.Name

	@property
	def dnspython_args(self) -> DNSPythonArgs:
		if self.closed:
			raise TypeError('This Signer has already been closed!')
		return {
			'keyring': self.keyring,
			'keyname': self.keyname,
			'keyalgorithm': dns.tsig.GSS_TSIG,
		}
