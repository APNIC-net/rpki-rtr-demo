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

use Test::More tests => 3;

my $pid;

{
    # Set up the server and the client.

    my $data_dir = tempdir(CLEANUP => 1);
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;
    my $server =
        APNIC::RPKI::RTR::Server->new(
            server   => '127.0.0.1',
            port     => $port,
            data_dir => $data_dir,
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
    ok((not $error), 'Reset client successfully');

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            %defaults,
            address => '2.0.0.0',
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            %defaults,
            address => '3.0.0.0',
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            %defaults,
            address => '4.0.0.0',
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            %defaults,
            address => '5.0.0.0',
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);

    eval { $client->refresh(1) };
    $error = $@;
    ok((not $error), 'Refreshed client successfully');

    is($client->state()->serial_number(), 2,
        'Serial number wrapped as expected');

    my $res = kill('TERM', $pid);
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
