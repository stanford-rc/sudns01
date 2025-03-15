# This is a Makefile to script the operation of our test Kerberos KDC

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

# Thanks to https://stackoverflow.com/a/23324703
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# Ensure all of our commands are pointing to the correct config files
export KRB5_CONFIG=$(ROOT_DIR)/krb5.conf
export KRB5_KDC_PROFILE=$(ROOT_DIR)/kdc.conf

# Make a symlink at /tmp/krb5, set up our Kerberos realm, and start the KDC
start:
	ln -s $(ROOT_DIR) /tmp/krb5
	kdb5_util create -r LOCALDOMAIN -P masterkey -s
	
	# Create principals for our DNS server, and our test client
	kadmin.local -r LOCALDOMAIN add_principal -randkey DNS/ns.localdomain
	kadmin.local -r LOCALDOMAIN add_principal -randkey host/host1.localdomain
	
	# Write out keytabs for our principals
	kadmin.local -r LOCALDOMAIN ktadd -keytab $(ROOT_DIR)/keytab.dns DNS/ns.localdomain
	kadmin.local -r LOCALDOMAIN ktadd -keytab $(ROOT_DIR)/keytab.host1 host/host1.localdomain
	
	# Start the KDC
	krb5kdc -r LOCALDOMAIN -P $(ROOT_DIR)/krb5kdc.pid

# Output the environment variables needed by clients
exports:
	@echo export KRB5_CONFIG=$(KRB5_CONFIG)

# Stops the KDC, removes the PID file, and removes the symlink
stop: $(ROOT_DIR)/krb5kdc.pid
	kill $$(cat $(ROOT_DIR)/krb5kdc.pid)
	rm $(ROOT_DIR)/krb5kdc.pid
	rm /tmp/krb5

# Clean up KDC files
clean:
	rm -f $(ROOT_DIR)/keytab*
	rm -f $(ROOT_DIR)/principal* $(ROOT_DIR)/stash $(ROOT_DIR)/kdc
