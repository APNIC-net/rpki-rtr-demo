#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::Client::Aggregator;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::PDU::Utils qw(parse_pdu);

use File::Slurp qw(write_file read_file);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);

use Test::More tests => 10;

my @pids;

{
    my $data_dir1 = tempdir(CLEANUP => 1);
    my $mnt1 =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir1
        );
    my $port1 = empty_port();
    my $server1 =
        APNIC::RPKI::RTR::Server->new(
            server           => '127.0.0.1',
            port             => $port1,
            data_dir         => $data_dir1,
        );

    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        $server1->run();
        exit(0);
    }
    sleep(1);

    my $data_dir2 = tempdir(CLEANUP => 1);
    my $mnt2 =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir2
        );
    my $port2 = empty_port();
    my $server2 =
        APNIC::RPKI::RTR::Server->new(
            server           => '127.0.0.1',
            port             => $port2,
            data_dir         => $data_dir2,
        );

    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        $server2->run();
        exit(0);
    }
    sleep(1);

    my $data_dir3 = tempdir(CLEANUP => 1);
    my $mnt3 =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir3
        );
    my $port3 = empty_port();
    my $server3 =
        APNIC::RPKI::RTR::Server->new(
            server           => '127.0.0.1',
            port             => $port3,
            data_dir         => $data_dir3,
        );

    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        $server3->run();
        exit(0);
    }
    sleep(1);

    # Add changesets to each server.

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
    $mnt1->apply_changeset($changeset);

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            %defaults,
            address => '1.0.1.0',
        );
    $changeset->add_pdu($pdu);
    $mnt2->apply_changeset($changeset);

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            %defaults,
            address => '1.0.2.0',
        );
    $changeset->add_pdu($pdu);
    $mnt3->apply_changeset($changeset);

    # Set up clients for each server.

    my $client1 =
        APNIC::RPKI::RTR::Client->new(
            timeout => 1,
            server  => '127.0.0.1',
            port    => $port1
        );

    my $client2 =
        APNIC::RPKI::RTR::Client->new(
            timeout => 1,
            server  => '127.0.0.1',
            port    => $port2
        );

    my $client3 =
        APNIC::RPKI::RTR::Client->new(
            timeout => 1,
            server  => '127.0.0.1',
            port    => $port3
        );

    my $cd = tempdir();
    my $json1 = $client1->serialise_json();
    write_file("$cd/client1.json", $json1);
    my $json2 = $client2->serialise_json();
    write_file("$cd/client2.json", $json2);
    my $json3 = $client3->serialise_json();
    write_file("$cd/client3.json", $json3);

    # Create an aggregator over these clients.

    my $aggregator =
        APNIC::RPKI::RTR::Client::Aggregator->new(
            clients => [
                [ 1, "$cd/client1.json" ],
                [ 2, "$cd/client2.json" ],
                [ 2, "$cd/client3.json" ]
            ]
        );

    # Reset the aggregator.  The end state should be per server 1.

    eval { $aggregator->reset() };
    my $error = $@;
    ok((not $error), "Reset aggregator successfully");
    diag $error if $error;

    my $state = $aggregator->state();
    my @pdus = $state->pdus();
    is(@pdus, 1, "Got one PDU");
    $pdu = $pdus[0];
    is($pdu->type(), PDU_IPV4_PREFIX(),
        'PDU is IPv4 prefix PDU');
    is($pdu->address(), '1.0.0.0',
        'PDU has correct address');

    # Exit the first server.  The aggregator should pick up both
    # records from the second server.

    $client1->exit_server();

    eval { $aggregator->refresh(1) };
    $error = $@;
    ok((not $error), "Refreshed aggregator successfully");
    diag $error if $error;

    $state = $aggregator->state();
    @pdus = $state->pdus();
    is(@pdus, 2, "Got two PDUs");
    $pdu = $pdus[0];
    is($pdu->type(), PDU_IPV4_PREFIX(),
        'PDU is IPv4 prefix PDU');
    is($pdu->address(), '1.0.2.0',
        'PDU has correct address');
    $pdu = $pdus[1];
    is($pdu->type(), PDU_IPV4_PREFIX(),
        'PDU is IPv4 prefix PDU');
    is($pdu->address(), '1.0.1.0',
        'PDU has correct address');

    $client2->exit_server();
    $client3->exit_server();
}

END {
    for my $pid (@pids) {
        kill('TERM', $pid);
    }
}

1;
