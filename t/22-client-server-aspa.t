#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);

use Test::More tests => 12;

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

    # Try to reset.  Server should respond with 'no data' error.

    eval { $client->reset() };
    my $error = $@;
    ok($error, 'Server has no data, responded with error');
    like($error, qr/Server has no data/,
        'Got expected error response');

    # Add an ASPA PDU to the server. 

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my $pdu =
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            afi_flags     => 3,
            customer_asn  => 4608,
            provider_asns => [1, 2, 3, 4],
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
    is($pdu->type(), 11, 'Got ASPA PDU');
    is($pdu->customer_asn(), 4608, 'Got correct customer ASN');

    # Withdraw the previous ASPA, and add another one.

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu->{'flags'} = 0;
    $changeset->add_pdu($pdu);
    my $pdu2 =
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            afi_flags     => 3,
            customer_asn  => 4609,
            provider_asns => [5, 6, 7, 8],
        );
    $changeset->add_pdu($pdu2);
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
    is(@pdus, 1, 'State has one PDU');
    @pdus = sort { $a->type() <=> $b->type() } @pdus;
    my $pdu1 = $pdus[0];
    is($pdu1->type(), 11, 'Got ASPA PDU');
    is($pdu1->customer_asn(), 4609, 'Got correct customer ASN');

    # Refresh the client again, confirm that nothing happens.

    eval { $client->refresh(1) };
    $error = $@;
    ok((not $error), 'Got successful response from server (no change)');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    @pdus = $client->state()->pdus();
    is(@pdus, 1, 'State has one PDU');

    my $res = kill('TERM', $pid);
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
