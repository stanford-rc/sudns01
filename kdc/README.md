In order to properly test sudns01, a Kerberos realm is required.  This
directory contains the configuration needed to make a test Kerberos realm.

# About the Kerberos Realm

The files `krb5.conf` and `kdc.conf` configure a Kerberos realm as follows:

* Realm name: `LOCALDOMAIN`.

* DNS name `localdomain.` maps to the realm `LOCALDOMAIN`.

* KDC on 127.0.0.1; ports 18888 (KDC), 18887 (kpasswd), and 18889 (kadmin)

* Principal canonicalization and reverse-DNS are disabled.

* Ticket max lifetime is 60 minutes; default lifetime is also 60 minutes.

* Principals are `host/host1.localdomain` and `DNS/ns.localdomain`.

# Test KDC Requirements

The test KDC creates temporary files in this directory, so you need this
directory to be writable.  A `.gitignore` file is in place, so that the
temporary files do not get committed by accident.

The symlink `/tmp/krb5` is created on the system, so this requires a writable
`/tmp`, and it limits you to running one test KDC per machine.  If this is a
problem, consider running everything inside a namespace that maps `/tmp` to a
different path.

The test KDC uses MIT Kerberos, so you need MIT Kerberos 5 installed.  You'll
need both the client and server programs. There is no specific minimum version;
install whatever the latest version is available:

* On macOS with MacPorts, install the `kerberos5` package.

* On Debian (and derivatives), install the `krb5-admin-server`, `krb5-kdc`, and
  `krb5-user` packages.

* On Red Hat Enterprise Linux (and derivatives), install the `krb5-libs`,
  `krb5-server`, and `krb5-workstation` packages.

* On Arch Linux, install the `krb5` package.

# Usage Instructions

## Starting the Test KDC

To start the KDC, run `make`, or `make start`.  This will do the following:

* Create a symlink from `/tmp/krb5` to this directory.

* Create a new Kerberos realm, `LOCALDOMAIN`, with the password `masterkey`.
  This will create Kerberos realm data files in this directory.

* Create our Kerberos principals, and generate keytabs for them, using the
  `kadmin.local` command (which lets you control the Kerberos realm without
  going through the master KDC).

* Start the master KDC.

When `krb5kdc` starts, you should expect it to report two errors:

* `(Error): preauth pkinit failed to initialize: PKINIT initialization failed:
  No pkinit_identity supplied for realm LOCALDOMAIN`

* `(Error): preauth spake failed to initialize: No SPAKE preauth groups configured`

Both of these errors are safe to ignore: We do not configure PKINIT or SPAKE.
Even with these errors, the test KDC will still start.

## Using the Test KDC

To use the test KDC, set the `KRB5_CONFIG` environment variable to point to the
`krb5.conf` file that is in this directory.  If you run `make exports`, the
necessary shell lines will be printed.

For example, if you run `$(make exports)` in your shell, you should find that
it has set (or, if already set, changed) the `KRB5_CONFIG` environment
variable.

The `keytab.dns` file will contain a keytab for the Kerberos principal
`DNS/ns.localdomain@LOCALDOMAIN`.  To use it, set the `KRB5_CONFIG` environment
variable and then run the command `kinit -k -t keytab.dns
DNS/ns.localdomain`.  Running `klist` should show you have a Kerberos
credential valid for 5-10 minutes.

Similarly, the `keytab.host1` file will contain a keytab for the Kerberos
principal `host/host1.localdomain`.

**NOTE**: The credentials you get via `kinit` are valid for one hour.  This
should be enough time for a round of testing to complete.  If you need to
extend this, use the `kinit` command to get a fresh Ticket-Granting Ticket
(TGT).

To stop using the test KDC, un-set the `KRB5_CONFIG` environment variable.

## Stopping the Test KDC

To stop the test KDC, run `make stop clean`.  The first action will stop the
KDC, delete the PID file, and delete the symlink.  The second action will clean
up the temporary files.
