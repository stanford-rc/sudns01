In order to properly test sudns01, a test domain is required, along with a DNS
server that supports the nsupdate protocol & GSS-TSIG.  We will use
`localdomain` as the test domain, and ISC bind as the DNS server!

# About the Test Domain and DNS Server

The files `named.conf` and `zone.orig` configure the test domain and DNS server
as follows:

* Domain: `localdomain.`.

* DNS server: `ns.localdomain.`, listening on 127.0.0.1 port 18853 (TCP and
  UDP).

* Queries are allowed from anywhere, but recursion is disabled.

* Logs are written to the file `log` in this directory.

* rndc is disabled.

* GSS-TSIG is enabled.  The DNS server's keytab must be in `keytab`, and the
  Kerberos configuration file must be set via the environment variable
  `KRB5_CONFIG`.

* nsupdate is enabled: Hosts that authenticate with a `host/XXXX.localdomain`
  ticket can send TXT records to `XXXX.localdomain` and subdomains of
  `XXXX.localdomain`.

# DNS Server Requirements

The test DNS server creates temporary files in this directory, so you need this
directory to be writable.  A `.gitignore` file is in place, so that the
temporary files do not get committed by accident.

The symlink `/tmp/bind` is created on the system, so this requires a writable
`/tmp`, and it limits you to running one test DNS server per machine.  If this
is a problem, consider running everything inside a namespace that maps `/tmp`
to a different path.

The test DNS server uses ISC bind, which you will need installed.  There is no
specific minimum version; install whatever the latest version is available:

* On macOS with MacPorts, install the `bind9` package.

* On Debian (and derivatives), install the `bind9` package.

* On Red Hat Enterprise Linux (and derivatives), install the `bind` package.

* On Arch Linux, install the `bind` package.

ISC bind also requires GSSAPI libraries; installing via package will ensure the
necessary library package is installed (for macOS, the built-in GSS Framework
will be used.)

# Usage Instructions

## Starting the Test DNS Server

First, you need to start the Test KDC.  Check the `kdc` directory for
instructions.  Or, you can run `make kdc`, which runs `make start` in the `kdc`
directory.

Once the Test KDC is started, check the `kdc` directory for the file
`keytab.dns`.  Copy that file to this directory, and name it `keytab`.  Or, you
can run `make keytab`, which does the copy for you.

With the keytab in place, to start the DNS server, run `make start`.  This
creates the `/tmp/bind` symlink, copies the zone file into place, and starts
`named` (the DNS server).

## Using the Test DNS Server

You can access the test DNS server at localhost (127.0.0.1) port 18853.
Initially, the zone will contain a SOA record for the `localdomain.` zone, an A
record for `ns.localdomain`, and a long DNAME record at `d.localdomain`.

To test connectivity with the `dig` command, `dig @127.0.0.1 -p 18853
host1.localdomain any` should return NXDOMAIN, and `dig @127.0.0.1 -p 18853
ns.localdomain A` should return `127.0.0.1`.  This confirms that the DNS Server
is operational.

Next, you can test making an nsupdate.  To do this, you need the `nsupdate`
command, which should be installed along with `named`.  You need to have the
`KRB5_CONFIG` environment variable pointing to the `krb5.conf` file in the
`kdc` directory, and you need to have a valid Kerberos credential for
`host/host1.localdomain@LOCALDOMAIN`.

Assuming all that is in place, you can use the following command to add a TXT
record to `host1.localdomain`:

```
nsupdate <<EOF
server 127.0.0.1 18853
gsstsig
add host1.localdomain. 60 IN TXT hello
send
EOF
```

The command should exit with code 0, and without printing any messages.

Afterwards, you can verify the presence of the update using the `dig` command,
by running `dig @127.0.0.1 -p 18853 host1.localdomain any`: This command should
return a single TXT record, `"hello"`.  This confirms that the DNS Server is
sending the nsupdate-d TXT record!

## Stopping the Test DNS Server

To stop the test DNS server, run `make stop clean`.  The first action will stop
the DNS server, delete the PID file, and delete the symlink.  The second action
will clean up the temporary files.
