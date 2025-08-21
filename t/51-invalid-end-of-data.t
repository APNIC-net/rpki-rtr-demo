#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::PDU::Utils qw(parse_pdu);

use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);

use Test::More tests => 2;

my $pid;

{
    # Set up the server and the client.

    my $data_dir = tempdir(CLEANUP => 1);
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port = empty_port();
    my $server =
        APNIC::RPKI::RTR::Server->new(
            server           => '127.0.0.1',
            port             => $port,
            data_dir         => $data_dir,
            refresh_interval => 3600,
            retry_interval   => 3600,
            expire_interval  => 1,
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
            supported_versions => [2],
            strict_receive     => 1,
        );

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my %defaults = (
        version       => 1,
        flags         => 1,
        asn           => 4608,
        prefix_length => 24,
        max_length    => 24
    );
    my $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            %defaults,
            address => '1.0.0.0',
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset, 4294967292);

    eval { $client->reset() };
    my $error = $@;
    ok($error, 'Unable to reset client');
    like($error, qr/expire interval too small/,
        'Got correct error message');

    $client->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
