#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);

use Test::More tests => 7;

my $pid;

{
    # Set up the server and the client.

    my $data_dir = tempdir(CLEANUP => 1); 
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port = empty_port();

    if (my $ppid = fork()) {
        $pid = $ppid;
    } else {
        for (;;) {
            my $server =
                APNIC::RPKI::RTR::Server->new(
                    server         => '127.0.0.1',
                    port           => $port,
                    data_dir       => $data_dir,
                    retry_interval => 5
                );
            $server->run();
            diag("Server exited, sleeping for 2s before restarting...");
            sleep(2);
        }
        exit(0);
    }
    sleep(1);

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server => '127.0.0.1',
            port   => $port,
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

    eval { $client->reset() };
    my $error = $@;
    ok((not $error), 'Got successful response from server');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    # Send the shutdown signal to the server.  Because the client is
    # not operating persistently, the first reset operation should
    # fail due to the server not being available, but the second
    # should 'just work'.  (Note that although it's a shutdown, the
    # server will start back up again automatically.  Because the
    # client does not receive the shutdown message, the client will
    # just use the existing end-of-data retry interval when attempting
    # to reconnect, which is fine.)

    kill('TERM', $pid);

    eval { $client->reset() };
    $error = $@;
    ok($error, 'Got failed response from server');
    like($error, qr/connection reset by peer/i,
        'Got expected error message');

    my $tur = $client->time_until_retry();
    diag "Client sleeping for ${tur}s...";
    sleep($tur);

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

    $client->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
