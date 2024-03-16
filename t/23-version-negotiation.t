#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);

use Test::More tests => 3;

my $pid;

{
    # "If a cache which supports version C receives a query with
    # Protocol Version Q < C, and the cache does not support versions
    # <= Q, the cache MUST send an Error Report (Section 5.11) with
    # Protocol Version C and Error Code 4 ("Unsupported Protocol
    # Version") and disconnect the transport, as negotiation is
    # hopeless."

    my $data_dir = tempdir(CLEANUP => 1);
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;
    my $server =
        APNIC::RPKI::RTR::Server->new(
            server             => '127.0.0.1',
            port               => $port,
            data_dir           => $data_dir,
            supported_versions => [2]
        );

    if (my $ppid = fork()) {
        $pid = $ppid;
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [1],
        );

    eval { $client->reset() };
    my $error = $@;
    like($error, qr/Unsupported server version '2'/,
        'Got expected error message');

    # "If a cache which supports version C receives a query with
    # Protocol Version Q < C, and the ache can support version Q, the
    # cache MUST downgrade to protocol version Q, [RFC6810] or
    # [RFC8210], and respond with a Cache Response (Section 5.5) of
    # that Protocol Version, Q, and the RPKI-Rtr session is considered
    # open."

    my $res = kill('TERM', $pid);

    $data_dir = tempdir(CLEANUP => 1);
    $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    $server =
        APNIC::RPKI::RTR::Server->new(
            server             => '127.0.0.1',
            port               => $port,
            data_dir           => $data_dir,
            supported_versions => [1, 2]
        );

    if (my $ppid = fork()) {
        $pid = $ppid;
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '1.0.0.0',
            prefix_length => 24,
            max_length    => 32
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);

    $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [1],
        );

    eval { $client->reset() };
    $error = $@;
    $res = ok((not $error),
        'Server supporting v1 and v2 works with v1 client');
    if (not $res) {
        use Data::Dumper;
        diag Dumper($error);
    }

    # "If the the cache which supports C as its highest verion receives
    # a query of version Q > C, the cache MUST send an Error Report
    # with Protocol Version C and Error Code 4.  The router SHOULD
    # send another query with a Protocol Version Q with Q == the
    # version C in the Error Report; unless it has already failed at
    # that version, which indicates a fatal error in programming of
    # the cache which SHOULD result in transport termination."

    $res = kill('TERM', $pid);

    $data_dir = tempdir(CLEANUP => 1);
    $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    $server =
        APNIC::RPKI::RTR::Server->new(
            server             => '127.0.0.1',
            port               => $port,
            data_dir           => $data_dir,
            supported_versions => [1]
        );

    if (my $ppid = fork()) {
        $pid = $ppid;
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '1.0.0.0',
            prefix_length => 24,
            max_length    => 32
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);

    $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [1,2],
        );

    eval { $client->reset() };
    $error = $@;
    $res = ok((not $error),
        'Client supporting v1 and v2 works with v1 server');
    if (not $res) {
        use Data::Dumper;
        diag Dumper($error);
    }
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
