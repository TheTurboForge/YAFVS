<!-- YAFVS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->

General Installation Instructions for OSPD-based Scanners
=========================================================

This is a general description about installing an ospd-based scanner wrapper
implementation.

The actual scanner implementation usually has individual installation
instructions and may refer to this general guide.

In the following guide, replace `ospd-scanner` with the name of the actual OSPD
scanner.


Install in a Virtual Environment
--------------------------------

The recommended way to install `ospd-scanner` is to do so inside a virtual
environment (`virtualenv` or `venv`).

This way, the server and its dependency are well isolated from system-wide
updates, making it easier to upgrade it, delete it, or install dependencies
only for it.

Refer to the Python documentation for setting up virtual environments for
further information.

First you need to create a virtual environment somewhere on your system, for
example with the following command:

    virtualenv ospd-scanner

Installing `ospd-scanner` inside your newly created virtual environment could
then be done with the following command:

    ospd-scanner/bin/pip install ospd_scanner-x.y.z.tar.gz

Note: As `ospd` is not (yet) available through PyPI, you probably want to
install it manually first inside your virtual environment prior to installing
`ospd-scanner`.

To run `ospd-scanner`, just start the Python script installed inside the
virtual environment:

    ospd-scanner/bin/ospd-scanner


Install (Sub-)System-wide
-------------------------

To install `ospd-scanner` into directory `<prefix>` run this command:

    python3 setup.py install --prefix=<prefix>

The default for `<prefix>` is `/usr/local`.

Be aware that this might automatically download and install missing
Python packages. To prevent this, you should install the prerequisites
first with the mechanism of your system (for example via `apt` or `rpm`).

You may need to set the `PYTHONPATH` like this before running
the install command:

    export PYTHONPATH=<prefix>/lib/python3.7/site-packages/

The actual value for `PYTHONPATH` depends on your Python version.

Creating certificates
---------------------

An OSPD service can be started using a Unix domain socket (only on
respective systems) or using a TCP socket. The latter uses TLS-based
encryption and authorization while the first is not encrypted and uses
the standard file access rights for authorization.

For the TCP socket communication it is mandatory to use adequate
TLS certificates which you need for each of your OSPD service. You may use
the same certificates for all services if you like.

By default, those certificates are used which are also used by GVM
(see paths with `ospd-scanner --help`). Of course this works only
if installed in the same environment.

In case you do not have already a certificate to use, you may quickly
create your own one (can be used for multiple ospd daemons) using the
`gvm-manage-certs` tool provided with `gvmd`
(<https://github.com/greenbone/gvmd>):

    gvm-manage-certs -s

And sign it with the CA checked for by the client. The client is usually
Greenbone Vulnerability Manager for which a global trusted CA certificate
can be configured.


Registering an OSP daemon in YAFVS
----------------------------------

The file [README](../README.md) explains how to control the OSP daemon via
command line.

Register the OSP daemon through YAFVS native scanner configuration. The
authenticated native scanner create and full-configuration replacement
contracts own the name, host/socket, port, type, relay, and certificate
references; the removed `gvmd` scanner mutation options cannot create or modify
scanners. See the [YAFVS API contract](../../../docs/API_CONTRACT.md) for the
native write-control contract.

Confirm registration through authenticated `GET /api/v1/scanners`. When direct
write-control is enabled, `POST /api/v1/scanners/{scanner_id}/verify` provides
the bounded native probe for local Unix-socket scanners. The retained
`gvmd --verify-scanner` compatibility path is limited to remote TLS/relay
verification until that responsibility migrates.

Use the native scanner configuration contract rather than GMP/XML or the removed gvmd mutation options when registering an OSP scanner.


Documentation
-------------

Source code documentation can be accessed over the usual methods,
for example (replace "scanner" by the scanner name):

    $ python3
    >>> import ospd_scanner.wrapper
    >>> help (ospd_scanner.wrapper)

An equivalent to this is:

    pydoc3 ospd_scanner.wrapper

To explore the code documentation in a web browser:

    $ pydoc3 -p 12345
    pydoc server ready at http://localhost:12345/

For further options see the `man` page of `pydoc`.


Creating a source archive
-------------------------

If you already have poetry-core installed you can run this command:

    python3 -m build --skip-dependency-check --no-isolation --sdist

If you don't have or want to install poetry-core you can run this
command:

    python3 -m build --sdist

In both cases a source archive for the `ospd-scanner` module will be
created in the subdirectory *dist*.
