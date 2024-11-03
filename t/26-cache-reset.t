#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);

use Test::More tests => 11;

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
    $changeset = APNIC::RPKI::RTR::Changeset->new();
    my $pdu2 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '1.0.1.0',
            prefix_length => 24,
            max_length    => 32
        );
    $changeset->add_pdu($pdu2);
    $mnt->apply_changeset($changeset);

    # Try to reset.

    eval { $client->reset() };
    my $error = $@;
    ok((not $error), 'Got successful response from server');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    my @pdus = $client->state()->pdus();
    is(@pdus, 2, 'State has two PDUs');
    @pdus = sort { $a->address() cmp $b->address() } @pdus;
    $pdu = $pdus[0];
    is($pdu->type(), 4, 'Got IPv4 prefix PDU (1)');
    is($pdu->address(), '1.0.0.0', 'Got correct address (1)');
    $pdu2 = $pdus[1];
    is($pdu2->type(), 4, 'Got IPv4 prefix PDU (2)');
    is($pdu2->address(), '1.0.1.0', 'Got correct address (2)');

    # Remove the changeset from the data directory.  The server
    # should send a cache reset to the client.

    unlink("$data_dir/changeset_1.json") or die $!;
    unlink("$data_dir/changeset_2.json") or die $!;
    unlink("$data_dir/snapshot.json") or die $!;

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '2.0.0.0',
            prefix_length => 24,
            max_length    => 32
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);
    ok((-e "$data_dir/changeset_1.json"),
        'New first changeset written');

    eval { $client->refresh(1) };
    $error = $@;
    my $res = ok((not $error),
        'Refresh fell back to reset on missing changeset');
    if (not $res) {
        use Data::Dumper;
        diag Dumper($error);
    }

    @pdus = $client->state()->pdus();
    is(@pdus, 1, 'State has one PDU');
    $pdu = $pdus[0];
    is($pdu->type(), 4, 'Got IPv4 prefix PDU (1)');
    is($pdu->address(), '2.0.0.0', 'Got correct address (1)');

    $client->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
