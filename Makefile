# This is a Makefile to prepare for, run, and clean up after tests.

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

# These are targets whose names do not map to file names.
.PHONY: test test-env check test-clean mypy clean

# If the user doesn't specify an action, or chooses `make all`, give a list of
# options
all:
	@echo What would you like to do?  The following targets are available:
	@echo \* test:       Start test DNS \& KDC, then run all tests via PyTest
	@echo \* test-env:   Start test DNS \& KDC
	@echo \* test-clean: Stop test DNS \& KDC
	@echo \* mypy:       Do MyPy tests only \(no test DNS or KDC or PyTest\)
	@echo \* clean:      Stop test DNS \& KDC, then clean up editable install

# Do an editable install of our package, with required dependencies.
.installed-editable:
	pip install -e .
	touch .installed-editable

# Do an editable install, with the dependencies needed for testing.
.installed-test-editable:
	pip install -e .[test]
	touch .installed-test-editable

# Run all the tests.  This requires the test dependencies.  We…
# * Start up the KDC
# * Copy the DNS server's keytab into place, then start up ISC bind named.
# * Get our Kerberos credential, storing it into a temporary file 
# * Start up BIND named
# * Run pytest tests (including MyPy & those needing local DNS)
# * Stop & clean up BIND named and the KDC
.test-pre: .installed-test-editable
	$(MAKE) -C kdc start
	cp $(ROOT_DIR)/kdc/keytab.dns $(ROOT_DIR)/bind/keytab
	$(MAKE) -C bind start
	touch .test-pre
test-env: .test-pre
test: .test-pre
	# Run a PyTest without our Test DNS or KDC
	# NOTE: We do not --cov-append here, to ensure coverage data are reset.
	pytest
	
	# Run tests with our Test DNS (no KDC)
	TEST_DNS_PORT=18853 pytest --cov-append
	
	# In one multi-command blob, get a Kerberos credential and run tests with
	# our test DNS and KDC!
	export KRB5CCNAME=FILE:$(shell mktemp) KRB5_CONFIG=$(ROOT_DIR)/kdc/krb5.conf;  \
	kinit -k -t $(ROOT_DIR)/kdc/keytab.host1 host/host1.localdomain; \
	TEST_DNS_PORT=18853 pytest --cov-append;

# "check" is a historical synonym for "test"
check: test

# Stop services and cleanup.
# Use this if `test` died before cleaning up
test-clean:
	-$(MAKE) -C bind stop
	-$(MAKE) -C bind clean
	-$(MAKE) -C kdc stop
	-$(MAKE) -C kdc clean
	rm -f .coverage .test-pre

# Doing `make test` includes MyPy, but if you just want to run MyPy, use this.
mypy: .installed-test-editable
	mypy sudns01 tests

# Clean up test files and uninstall our (editable) package.
# NOTE: This does not uninstall any dependencies that we installed.
clean: test-clean
	-pip uninstall -y sudns01
	rm -f .coverage .installed-editable .installed-test-editable
