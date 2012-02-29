dnscrypt-proxy(8) -- A DNSCrypt forwarder
=========================================

## SYNOPSIS

`dnscrypt-proxy` [<options>]

## DESCRIPTION

**dnscrypt-proxy** accepts DNS requests, encrypts and signs them using
dnscrypt and forwards them to a remote dnscrypt-enabled resolver.

Replies from the resolver are expected also to be encrypted and signed.

The proxy verifies the signature of replies, decrypts them, and transparently
forwards them to the local stub resolver.

`dnscrypt-proxy` listens to `127.0.0.1` / port `53` by default.

## WARNING

**dnscrypt-proxy** is not a DNS cache. Unless your operating system
already provides a decent built-in cache (and by default, most systems
don't), clients shouldn't directly send requests to **dnscrypt-proxy**.

Intead, run a DNS cache like **Unbound**, and configure it to use
**dnscrypt-proxy** as a forwarder. Both can safely run on the same
machine as long as they use different IP addresses and/or different
ports.

## OPTIONS

  * `-a`, `--local-address=<ip>`: what local IP the daemon will listen to.

  * `-d`, `--daemonize`: detach from the current terminal and run the server
    in background.

  * `-e`, `--edns-payload-size=<bytes>`: transparently add an OPT
    pseudo-RR to outgoing queries in order to enable the EDNS0
    extension mechanism. The payload size is the size of the largest
    response we accept from the resolver before retrying over TCP.
    This feature is enabled by default, with a payload size of 1280
    bytes. Any value below 512 disables it.

  * `-h`, `--help`: show usage.

  * `-k`, `--provider-key=<key>`: specify the provider public key (see below).

  * `-l`, `--logfile=<file>`: log events to this file instead of the
    standard output.

  * `-n`, `--max-active-requests=<count>`: set the maximum number of
    simultaneous active requests. The default value is 250.

  * `-p`, `--pidfile=<file>`: write the PID number to a file.

  * `-r`, `--resolver-address=<ip>`: a DNSCrypt-capable resolver IP
    address.

  * `-t`, `--tcp-port=<port>`: connect to the resolver on port <port>
    over TCP, as a workaround if UDP over port 53 is filtered.

  * `-u`, `--user=<user name>`: chroot(2) to this user's home directory
    and drop privileges.

  * `-N`, `--provider-name=<FQDN>`: the fully-qualified name of the
    dnscrypt certificate provider.

  * `-P`, `--local-port=<port>`: local port to listen to.

  * `-V`, `--version`: show version number.

A public key is 256-bit long, and it has to be specified as a hexadecimal
string, with optional columns.

## OPENDNS SPECIFIC FLAGS

  * `-0`, `--opendns-device-id=<device id>`: tag outgoing UDP queries with
an OpenDNS-specific device identifier.

Columns are optional and can be placed anywhere between hex bytes:

OpenDNS device ID example:

    --opendns-device-id=CA:FE:BA:BE:DEAD:BEEF

## SIMPLE USAGE EXAMPLE

    $ dnscrypt-proxy --daemonize

## ADVANCED USAGE EXAMPLE

    $ dnscrypt-proxy --provider-key=B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79 --provider-name=2.dnscrypt-cert.dnscrypt.org. --resolver-ip=208.67.220.220 --daemonize

## KNOWN BUGS

OpenDNS device identifiers are not added when using TCP and when an OPT
section was already present.

## COPYRIGHT

dnscrypt-proxy is Copyright (C) 2011-2012 OpenDNS, Inc.
`http://www.opendns.com/`

