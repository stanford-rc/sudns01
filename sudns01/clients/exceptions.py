#vim: ts=4 sw=4 noet

# These are the exceptions that the clients can throw.

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

class ClientError(Exception):
	"""A client error.
	"""
	pass

class ClientErrorTemporary(ClientError):
	"""A client error, which should be temporary.
	"""
	pass

class ResolverError(ClientErrorTemporary):
	"""There was a problem with the DNS resolver.
	"""
	pass

class ResolverErrorPermanent(ResolverError):
	"""There was a temporary problem with the DNS resolver.

	You may be able to recover if you wait a while.
	"""
	pass

class ResolverErrorCDName(ResolverErrorPermanent):
    """A CNAME or DNAME was encountered during a DNS lookup.

    For some lookups, we do not want to follow CNAME or DNAME records.  Such a
    record was encountered during your requested lookup.
    """
    pass

class NoServers(ClientError):
	"""There were no more servers to try."""
	pass

class DNSError(ClientErrorTemporary):
	"""We connected to the DNS server, but ran into a problem."""
	pass

__all__ = (
	'ClientError',
	'ClientErrorTemporary',
	'ResolverError',
	'ResolverErrorPermanent',
	'ResolverErrorCDName',
	'NoServers',
	'DNSError',
)
