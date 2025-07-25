## rpki-rtr-demo

[![Build Status](https://github.com/APNIC-net/rpki-rtr-demo/actions/workflows/build.yml/badge.svg)](https://github.com/APNIC-net/rpki-rtr-demo/actions)

A proof-of-concept for the RPKI-to-Router protocol, as at
[draft-ietf-sidrops-8210bis-21](https://www.ietf.org/archive/id/draft-ietf-sidrops-8210bis-21.txt).

### Build

    $ perl Makefile.PL
    $ make

### Install

    $ sudo make install

### Single server usage

#### Server

    $ mkdir data-dir
    $ rpki-rtr-server data-dir init --server 127.0.0.1 --port 8282

#### Server updates

    $ rpki-rtr-server-mnt data-dir start-changeset
    $ rpki-rtr-server-mnt data-dir add-vrp "192.0.2.0/24 => 64496"
    $ rpki-rtr-server-mnt data-dir add-aspa "64494 => 1, 2, 3"
    $ rpki-rtr-server-mnt data-dir commit-changeset

#### Client

    $ mkdir client-data-dir
    $ rpki-rtr-client client-data-dir init --server 127.0.0.1 --port 8282 --version 2
    $ rpki-rtr-client client-data-dir reset
    $ rpki-rtr-client client-data-dir print
    Server:            127.0.0.1
    Port:              8282
    Last run:          2023-11-05 12:26:28
    Last failure:      N/A
    Refresh interval:  3600
    Next refresh time: 2023-11-05 13:26:28
    Retry interval:    600
    Next retry time:   N/A
    Expire interval:   7200
    Expiry time:       2023-11-05 14:26:28
    State:
     - IPv4 Prefix: 192.0.2.0/24-24 => AS64494
     - ASPA: AS64494 => AS1, AS2, AS3
    $ rpki-rtr-client client-data-dir aspa-validation --announcement "TABLE_DUMP2|1698933600|B|64.71.137.241|6939|1.0.0.0/24|6939 13335|IGP|64.71.137.241|0|0||NAG|13335 10.34.0.16|" --provider-asns 6939
    Valid
    $ rpki-rtr-client client-data-dir aspa-validation --announcement "TABLE_DUMP2|1698933600|B|64.71.137.241|6939|1.0.0.0/24|6939 13335|IGP|64.71.137.241|0|0||NAG|13335 10.34.0.16|" --provider-asns 6939
    Unknown

### Multiple server usage

    $ mkdir data-dir1
    $ rpki-rtr-server data-dir1 init --server 127.0.0.1 --port 8282

    $ rpki-rtr-server-mnt data-dir1 start-changeset
    $ rpki-rtr-server-mnt data-dir1 add-vrp "192.0.2.0/24 => 64496"
    $ rpki-rtr-server-mnt data-dir1 commit-changeset

    $ mkdir data-dir2
    $ rpki-rtr-server data-dir2 init --server 127.0.0.1 --port 8284

    $ rpki-rtr-server-mnt data-dir2 start-changeset
    $ rpki-rtr-server-mnt data-dir2 add-vrp "192.0.4.0/24 => 64496"
    $ rpki-rtr-server-mnt data-dir2 commit-changeset

    $ mkdir client-data-dir1
    $ rpki-rtr-client client-data-dir1 init --server 127.0.0.1 --port 8282 --version 2
    $ mkdir client-data-dir2
    $ rpki-rtr-client client-data-dir2 init --server 127.0.0.1 --port 8284 --version 2
    $ mkdir aggregator-data-dir
    $ rpki-rtr-client-aggregator aggregator-data-dir init --clients 1,client-data-dir1,1,client-data-dir2
    $ rpki-rtr-client-aggregator aggregator-data-dir reset
    $ rpki-rtr-client-aggregator aggregator-data-dir print
    State:
     - IPv4 Prefix: 192.0.2.0/24-24 => AS64496
     - IPv4 Prefix: 192.0.4.0/24-24 => AS64496

### Other

If the `APNIC_DEBUG` environment variable is set to a true value, then
each command will print debug output to standard error.

To run tests, including basic integration tests against
[RTRTR](https://github.com/NLnetLabs/rtrtr),
[RTRlib](https://github.com/rtrlib/rtrlib), and
[StayRTR](https://github.com/bgp/stayrtr):

    docker build . -t rpki-rtr-demo
    # Single test:
    docker run --env-file docker-env -it rpki-rtr-demo perl -Mblib t/35-rtrtr.t
    # All tests:
    docker run --env-file docker-env -it rpki-rtr-demo make test

### Todo

 - Documentation/tidying of code.
 - See [issues](https://github.com/APNIC-net/rpki-rtr-demo/issues).

### License

See [LICENSE](./LICENSE).
