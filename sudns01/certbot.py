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

# stdlib imports
import abc
import argparse
import dataclasses
import importlib.metadata
import logging
import pathlib
from typing import Any, Callable

# PyPi imports
import acme
import certbot
import certbot.errors
import certbot.plugins.dns_common

# local imports
import sudns01.clients.exceptions
import sudns01.clients.query
import sudns01.clients.resolver
import sudns01.clients.tkey

# Set up logging
# certbot logs debug-level logs to a file.  As for standard output…
# * certbot's default log level is WARNING.
# * Passing the '--verbose' (or '-v') argument makes the default log level INFO.
# * Passing the '-vv' argument makes the default level DEBUG.
# Log messages on stdout do not have any formatting applied to them.
logger = logging.getLogger(__name__)
exception = logger.exception
error = logger.error
warning = logger.warning
info = logger.info
debug = logger.debug

# If we need to stop execution due to a problem, we should raise a
# certbot.errors.PluginError, which takes one parameter (the message).

# What keys does our conf have?
@dataclasses.dataclass(repr=False)
class GSSConf():
	resolver: sudns01.clients.resolver.ResolverClient | None = None
	nsupdate: sudns01.clients.query.QueryClient | None = None
	creds: sudns01.clients.tkey.KrbCreds | None = None
	signer: sudns01.clients.tkey.GSSTSig | None = None

class BaseAuthenticator(
	certbot.plugins.dns_common.DNSAuthenticator,
	metaclass=abc.ABCMeta
):
	"""Set up Authenticator for DNS01 via GSS TSIG-based nsupdate.

	This is instantiated by the certbot command when it is first run, even if
	the user decides not to use the plugin.

	Every plugin is instantiated once.  Here is where our methods are called,
	in the sequence of certbot's execution:

	1. certbot starts running
	2. argument parsing: `add_parser_arguments`
	3. `__init__`
	4. `prepare` (see note)
	5. If an authentication plugin is not selected: `description`
	6. If we are selected as the authentication method:
		a. `perform`
		b. `_setup_credentials()`
		c. `_perform()`
		d. If authentication fails: `auth_hint`
		e. `_cleanup()`

	If our plugin is never used, it never proceeds past Step 6.

	If our plugin is specified (using the `-a` flag) on certbot's command line,
	then only that plugin will have `prepare` run.  If no plugin is specified
	on the command line, then every plugin's `prepare` will be run.

	The methods prefixed with an underscore are abstract methods defined by
	`certbot.plugins.dns_common.DNSAuthenticator`, so we have to provide an
	implementation for them.

	Because `__init__` and `prepare` are called even when we are not used, we
	do not do very much there.  The bulk of our work is done in the calls made
	by `perform`.

	Since we are a subclass, we have access to a number of things that are set
	up by our superclasses, including…

	* `config`: An `argparse` `Namespace`-alike containing our command-line
	arguments.

	* `certbot.plugins.dns_common.DNSAuthenticator._prompt_for_data`: Prompt for a line of input.

	* `certbot.display.util.notify`: Print a status-update message.

	* `certbot.display.util.notification`: Print a message and wait for the
	user to respond.

	* `certbot.display.util.yesno`: Ask a question and get a Yes/No answer.
	"""

	description = 'PLACEHOLDER DESCRIPTION!  Subclasses must override this.'
	"""The plugin's description.

	When the user doesn't specify a plugin, certbot displays a list of plugins.
	The description is shown to the user at that time.
	"""

	gssconf: GSSConf
	"""Storage for our runtime configuration.

	This stores things like our Kerberos configuration, signer, resolver, etc.
	"""

	cli_prefix: str
	"""Our command-line argument prefix.

	Our CLI options will be prefixed by this, followed by a hyphen.
	"""

	config_prefix: str
	"""Our configuration key prefix.

	Plugin arguments have a prefix, which we need to know in order to fetch
	arguments for our (real) class.
	"""

	def __init__(
		self,
		*args: Any,
		**kwargs: Any,
	) -> None:
		debug('In __init__')

		# Set up our parent class
		super().__init__(*args, **kwargs)

		# Set up an empty conf
		self.gssconf = GSSConf()

		# We need to find the certbot entrypoint name for our class.
		# Pull the list of certbot plugins
		ep_found = False
		entrypoints = importlib.metadata.entry_points(group='certbot.plugins')
		for ep_name in entrypoints.names:
			# Load the entrypoint and check if it matches our class
			if type(self) == entrypoints[ep_name].load():
				self.cli_prefix = ep_name
				ep_found = True
				break
		if not ep_found:
			raise certbot.errors.PluginError('Could not find our class name during plugin setup.')

		# Convert hyphens in the prefix to underscores
		self.config_prefix = self.cli_prefix.replace('-', '_')
		debug(f"Using config_prefix {self.config_prefix}")

	def get_config(self,
		key: str,
	) -> Any:
		"""Get a configuration item.

		Uses our `config_prefix` to find an item in program configuration.

		:param key: The key to find.

		:returns: The configuration value.

		:raises AttributeError: The key does not exist.
		"""
		derived_key = (self.config_prefix + '_' + key)
		debug(f"Fetching {derived_key}")
		return getattr(self.config, derived_key)

	@classmethod
	def add_parser_arguments(
		self,
		add: Callable[..., None],
		default_propagation_seconds: int = 10,
	) -> None:
		"""Add arguments to the certbot command.

		The `add` function we're given takes the same arguments as if we are
		adding an argument to an `argparse` `ArgumentParser`.  certbot runs
		this when the command is first run.

		NOTE: The arguments will be parsed even if this plugin is not used.
		That means, if we require an argument, the user will always need to
		provide it.
		"""
		debug('In add_parser_arguments')
		add('timeout',
			help='How long to wait for a response from the DNS servers.',
			type=float,
			default=10.0,
		)
		add('cleanup',
			help='Remove all other ACME challenge records.  THIS CAN BE DANGEROUS!',
			action='store_true',
		)
		add('cleanup2',
			help=argparse.SUPPRESS,
			action='store',
		)
		if sudns01.clients.tkey.HAS_CREDENTIAL_STORE:
			add('ccache',
				help='Use a specific Kerberos credentials cache.  Default is to use what is defined in the environment.  Requires support from the GSSAPI and Kerberos libraries.',
			)
			add('keytab',
				help='Use a specific client keytab to authenticate to the nsupdate server.  Normally a separate program (like `kinit` or `k5start` is used to obtain Kerberos credentials from a client keytab.  If set, --ccache must also be set.  Requires support from the GSSAPI and Kerberos libraries.',
				type=pathlib.Path,
			)

	def more_info(self) -> str:
		debug('In more_info!!!!!')

		# I'm still not exactly sure where this call is executed.
		return "MORE INFO ABOUT SUDNS01"

	def prepare(self) -> None:
		"""Take an action at the start of program execution.

		This can be called even if the plugin does not end up being used.

		If an authentication plugin is not selected on the certbot command
		line, then this will be run, even if we are not chosen.
		"""
		debug('In prepare')

		# Set up a Resolver
		self.gssconf.resolver = sudns01.clients.resolver.ResolverClient()

		# Check if we will use a Credential Store
		if sudns01.clients.tkey.HAS_CREDENTIAL_STORE:
			debug('We have the Credential Store Extensions')
			if (
				self.get_config('ccache') is not None or
				self.get_config('keytab') is not None
			):
				self.gssconf.creds = sudns01.clients.tkey.KrbCreds(
					ccache=self.get_config('ccache'),
					client_keytab=self.get_config('keytab'),
				)

		# Check timeout
		if self.get_config('timeout') <= 0:
			raise certbot.errors.PluginError(f"--{self.cli_prefix}-timeout must be a positive number")

	def perform(
		self,
		achalls: list[certbot.achallenges.AnnotatedChallenge],
	) -> list[acme.challenges.ChallengeResponse]:
		"""Perform an authentication.

		Given a list of authentication challenges, return a list of challenge
		responses.  In actual use, since our parent classes make clear that we
		can only handle DNS-01 challenges, our list of challenges should
		contain a single entry.  Still, we must be prepared to handle multiple
		DNS-01 challenges.

		:param achalls: A list of challenges to perform.

		:returns: A list of the challenges for which we have a response.
		"""
		debug(f"In perform with {len(achalls)} challenges.")

		# This is a near-total copy of the code from the same method in
		# certbot.plugins.dns_common.DNSAuthenticator.  So, why copy it?
		# Because the parent class has a built-in fixed wait for propagation,
		# and we have a dynamic wait for propagation.
		self._setup_credentials()

		self._attempt_cleanup = True

		responses = []
		for achall in achalls:
			domain = achall.domain
			validation_domain_name = achall.validation_domain_name(domain)
			validation = achall.validation(achall.account_key)

			self._perform(domain, validation_domain_name, validation)
			responses.append(achall.response(achall.account_key))

		return responses

	def _setup_credentials(self) -> None:
		"""Prepare to perform the challenge.

		This is an abstract method defined upstream (in
		`certbot.plugins.dns_common.DNSAuthenticator`), so we have to implement
		it.  It's called by the start of `perform()`.

		If this gets called, we can be certain that we were selected as the
		authenticator plugin, so it's safe to do things (like parameter
		validation) which could cause certbot to fail.
		"""
		debug('In setup_credentials')

		# Make sure we have a resolver
		if self.gssconf.resolver is None:
			error('resolver has not been set yet!')
			raise certbot.errors.PluginError('The Authenticator plugin has not been fully initialized.')

		# Check if we have a cleanup challenge, and if it's valid.
		# TODO

		# Set up a dnsupdate client
		try:
			nsupdate_server_ips = self.gssconf.resolver.get_ip(
				self.get_config('nsupdate')
			)
		except sudns01.clients.exceptions.ResolverError as e:
			raise certbot.errors.PluginError(
				f"Temporary error looking up {self.config.nsupdate}: {e}"
			)
		except sudns01.clients.exceptions.ResolverErrorPermanent as e:
			raise certbot.errors.PluginError(
				f"Permanent error looking up {self.config.nsupdate}: {e}"
			)
		if len(nsupdate_server_ips) == 0:
			raise certbot.errors.PluginError(
				f"No IP addresses found for {self.config.nsupdate}"
			)
		self.gssconf.nsupdate = sudns01.clients.query.QueryClient(
			ips=nsupdate_server_ips,
			port=self.get_config('port'),
			timeout=self.get_config('timeout'),
			udp=self.get_config('udp'),
		)
		info(
			'nsupdate server is ' +
			('UDP' if self.get_config('udp') is True else 'TCP') +
			' to port port ' +
			str(self.get_config('port')) +
			f" of {nsupdate_server_ips}, timeout " +
			str(self.get_config('timeout')) +
			' seconds.'
		)

		# Set up dnsupdate signing
		dnsupdate_info_str = (
			'GSSAPI authentication is to ' +
			'DNS/' + self.get_config('nsupdate').lower() +
			', using '
		)
		if self.gssconf.creds is None:
			dnsupdate_info_str += 'credentials from the environment.'
		else:
			if self.get_config('ccache') is None:
				dnsupdate_info_str += 'credentials cache from the environment'
			else:
				dnsupdate_info_str += 'credentials cache ' + self.get_config('ccache')
			dnsupdate_info_str += ' and '
			if self.get_config('keytab') is None:
				dnsupdate_info_str += 'no keytab.'
			else:
				dnsupdate_info_str += 'keytab from ' + self.get_config('keytab')
			dnsupdate_info_str += '.'
		info(dnsupdate_info_str)
		try:
			signer = sudns01.clients.tkey.GSSTSig(
				dnsquery=self.gssconf.nsupdate,
				server=self.get_config('nsupdate'),
				creds=self.gssconf.creds,
			)
		except NotImplementedError:
			raise certbot.errors.PluginError(
				"Your GSSAPI implementation does not have support for manipulating credential stores.  Try again without the ccache and keytab options."
			)

	def _perform(self,
		domain: str,
		validation_name: str,
		validation: str,
	) -> None:
		"""Respond to a single DNS01 challenge.

		For example, say `blargh.stanford.edu` wants a TLS certificate.  In
		that case, this method will be called with the following parameters:

		* domain = `blargh.stanford.edu`

		* validation_name = `_acme-challenge.blargh.stanford.edu`

		* validation = (Some string to put into the TXT record.)

		This method creates the appropriate TXT record and then returns.

		:note: For most plugins, upon returning from this method, Certbot will
		tell the ACME server to check for the challenge we set up.  For
		`certbot.plugins.dns_common.DNSAuthenticator` plugins, Certbot normally
		waits for a fixed amount of time and then proceeds.  We do not do that:
		We wait for the Stanford DNS refresh, we wait for the record to be in
		DNS, and *then* we return.

		:param domain: The FQDN for which we want a certificate.

		:param validation_name: The FQDN where we need to add a TXT record.

		:param validation: The string to add as the value for the TXT record.
		"""
		debug(f"In perform for {domain}: {validation_name} = {validation}")

		# Do any old-record cleanup, if we're supposed to
		# TODO

		# Prepare our challenge record
		# TODO

		# Send the request
		# TODO

		# Close our current signer
		# TODO

		# Do wait-check loop
		# TODO

	def auth_hint(
		self,
		failed_achalls: list[certbot.achallenges.AnnotatedChallenge],
	) -> str:
		"""Return a message on failed challenges.

		When a challenge fails, the user receives a message telling them how
		the challenge failed.  Certbot's message also includes a 'hint' from
		us.

		:param: A list of failed challenges, including details of why the
		challenge failed.

		:returns: A string, which will prefixed with "Hint: " and displayed to
		the user.
		"""
		return ""

	def _cleanup(self,
		domain: str,
		validation_name: str,
		validation: str,
	) -> None:
		"""Clean up after a completed (passed or failed) challenge.

		This is called after the challenge is performed, and the challenge's
		response (in this case, a TXT record) is not longer required.  This is
		our opportunity to clean up the challenge.

		NOTE: We do not know if the challenge was successful or if the
		challenge failed.

		:param domain: The FQDN for which we want a certificate.

		:param validation_name: The FQDN where we need to add a TXT record.

		:param validation: The string to add as the value for the TXT record.
		"""
		debug(f"In cleanup for {domain}")
		# Set up a dnsupdate client
		# TODO

		# Set up dnsupdate signing
		# TODO

class GenericAuthenticator(BaseAuthenticator):
	"""Authenticator configuration that is not Stanford-specific.

	This has the user provide an nsupdate server name/IP, an (optional) port,
	specify if UDP or TCP should be used, and how long we should wait between
	propagation checks.
	"""

	description = (
		"Uses GSS-TSIG to add an ACME Challenge record to DNS.  " +
		"Requires a Kerberos credential to authenticate to your nsupdate " +
		"server.  DNS challenge only."
	)
	
	@classmethod
	def add_parser_arguments(
		self,
		add: Callable[..., None],
		default_propagation_seconds: int = 10,
	) -> None:
		super().add_parser_arguments(
			add=add,
			default_propagation_seconds=default_propagation_seconds,
		)
		add('port',
			help='The port to use on the nsupdate server.',
			type=int,
			default=53,
		)
		add('udp',
			help='Force using UDP for DNS queries.  Should never be needed.',
			action='store_true',
		)
		add('wait',
			help='The number of minutes we wait between propagation checks.',
			type=float,
			default=1.0,
		)
		add('nsupdate',
			help='The DNS server that handles nsupdate messages.',
		)

	def prepare(self) -> None:
		super().prepare()

		# Check our command-line arguments
		# NOTE: We cannot check nsupdate unless we know we're being used.
		port = self.get_config('port')
		if port < 1 or port > 65535:
			raise certbot.errors.PluginError(f"--{self.cli_prefix}-port {port} is invalid.")
		wait = self.get_config('wait')
		if wait < 0:
			raise certbot.errors.PluginError(f"--{self.cli_prefix}-wait must be non-negative")

class StanfordAuthenticator(BaseAuthenticator):
	"""Stanford-specific Authenticator configuration.

	Compared to the GenericAuthenticator, we don't ask for much, just
	Kerberos-related things.
	"""

	description = (
		"Uses Stanford DNS to add an ACME Challenge record to a " +
		".stanford.edu domain name.  Requires a Kerberos credential for the " +
		"name you want to secure (so, to get a certificate for " +
		"blargh.stanford.edu, you need a Kerberos credential for " +
		"host/blargh.stanford.edu).  DNS challenge only."
	)
	
	@classmethod
	def add_parser_arguments(
		self,
		add: Callable[..., None],
		default_propagation_seconds: int = 10,
	) -> None:
		super().add_parser_arguments(
			add=add,
			default_propagation_seconds=default_propagation_seconds,
		)
		add('port',
			help=argparse.SUPPRESS,
			type=int,
			default=53,
		)
		add('udp',
			help=argparse.SUPPRESS,
			type=bool,
			default=False,
		)
		add('nsupdate',
			help=argparse.SUPPRESS,
			default='acme-dns.stanford.edu',
		)
