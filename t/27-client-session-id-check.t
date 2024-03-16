#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);

use Test::More tests => 6;

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

    # Try to reset.

    eval { $client->reset() };
    my $error = $@;
    ok((not $error), 'Got successful response from server');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    my @pdus = $client->state()->pdus();
    is(@pdus, 1, 'State has single PDU');
    $pdu = $pdus[0];
    is($pdu->type(), 4, 'Got IPv4 prefix PDU');
    is($pdu->address(), '1.0.0.0', 'Got correct address');

    # Start a new server, which will get a new session ID, and then
    # give it changesets up to changeset 2, so that the available
    # changesets line up.  The serial query should still fail, because
    # of the session ID mismatch.

    my $res = kill('TERM', $pid);

    $data_dir = tempdir(CLEANUP => 1);
    $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    $server =
        APNIC::RPKI::RTR::Server->new(
            server              => '127.0.0.1',
            port                => $port,
            data_dir            => $data_dir,
            supported_versions  => [1, 2],
            no_session_id_check => 1,
        );

    if (my $ppid = fork()) {
        $pid = $ppid;
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu->{'flags'} = 0;
    $changeset->add_pdu($pdu);
    my $pdu2 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '2.0.0.0',
            prefix_length => 8,
            max_length    => 8
        );
    $changeset->add_pdu($pdu2);

    eval { $client->refresh(1) };
    $error = $@;
    ok($error, 'Serial query failed on session ID mismatch');
    like($error, qr/got PDU with unexpected session/,
        'Got correct error message');

    $res = kill('TERM', $pid);
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
