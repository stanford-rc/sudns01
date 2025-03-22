# This is a Makefile to script the operation of our test BIND nameserver

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

# Point to the test KDC config
export KRB5_CONFIG=$(ROOT_DIR)../krb5.conf

all:
	@echo You need to specify a target!  Choose from:
	@echo \* kdc: Start the KDC
	@echo \* keytab: Copy the keytab into this directory.
	@echo \* start: Start the DNS Server

kdc:
	$(MAKE) -f $(ROOT_DIR)/../kdc/Makefile start

keytab:
	cp $(ROOT_DIR)/../kdc/keytab.dns $(ROOT_DIR)/keytab

# Make a symlink at /tmp/bind, put the zone file in place, and start named
start: keytab
	ln -s $(ROOT_DIR) /tmp/bind
	cp -f $(ROOT_DIR)/zone.orig $(ROOT_DIR)/zone
	named -4 -c $(ROOT_DIR)/named.conf -p 18853

# Stops named, removes the PID file, and removes the symlink
stop: $(ROOT_DIR)/named.pid
	kill $$(cat $(ROOT_DIR)/named.pid)
	rm $(ROOT_DIR)/named.pid
	rm /tmp/bind

# Clean up named log and temp files
clean:
	rm -f $(ROOT_DIR)/bind $(ROOT_DIR)/log $(ROOT_DIR)/keytab
	rm -f $(ROOT_DIR)/_default.tsigkeys $(ROOT_DIR)/managed-keys.bind*
	rm -f $(ROOT_DIR)/zone $(ROOT_DIR)/zone.jnl
