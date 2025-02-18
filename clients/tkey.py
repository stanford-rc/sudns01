#!python3
#vim: ts=4 sw=4 noet

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

# PyPi imports
import gssapi

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


