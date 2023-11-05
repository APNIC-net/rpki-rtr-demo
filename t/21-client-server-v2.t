#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);

use Test::More tests => 14;

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
            server  => '127.0.0.1',
            port    => $port,
            version => 2,
        );

    # Try to reset.  Server should respond with 'no data' error.

    eval { $client->reset() };
    my $error = $@;
    ok($error, 'Server has no data, responded with error');
    like($error, qr/Server has no data/,
        'Got expected error response');

    # Add an IPv4 prefix to the server.  (Version should be overridden
    # when returning the PDUs, so 1 is fine.)

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

    # Try to reset again.  Should get back some content.

    eval { $client->reset() };
    $error = $@;
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

    # Add an IPv4 and an IPv6 prefix, and remove the previous one.

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
    my $pdu3 =
        APNIC::RPKI::RTR::PDU::IPv6Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '2001:1234::',
            prefix_length => 32,
            max_length    => 48
        );
    $changeset->add_pdu($pdu3);
    $mnt->apply_changeset($changeset);

    # Refresh the client, and confirm that the updates are applied
    # correctly.

    eval { $client->refresh(1) };
    $error = $@;
    ok((not $error), 'Got successful response from server');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    @pdus = $client->state()->pdus();
    is(@pdus, 2, 'State has two PDUs');
    @pdus = sort { $a->type() <=> $b->type() } @pdus;
    my $pdu1 = $pdus[0];
    is($pdu1->type(), 4, 'Got IPv4 prefix PDU');
    is($pdu1->address(), '2.0.0.0', 'Got correct address');
    $pdu2 = $pdus[1];
    is($pdu2->type(), 6, 'Got IPv6 prefix PDU');
    is($pdu2->address(), '2001:1234::', 'Got correct address');

    # Refresh the client again, confirm that nothing happens.

    eval { $client->refresh(1) };
    $error = $@;
    ok((not $error), 'Got successful response from server (no change)');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    @pdus = $client->state()->pdus();
    is(@pdus, 2, 'State has two PDUs');

    my $res = kill('TERM', $pid);
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
