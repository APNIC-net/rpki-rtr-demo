#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);

use Test::More tests => 3;

my $pid;

{
    my $data_dir = tempdir(CLEANUP => 1);
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port = empty_port();
    my $server =
        APNIC::RPKI::RTR::Server->new(
            server   => '127.0.0.1',
            port     => $port,
            data_dir => $data_dir,
        );

    $ENV{'APNIC_SEND_EARLY_SERIAL_NOTIFY'} = 1;
    if (my $ppid = fork()) {
        $pid = $ppid;
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server => '127.0.0.1',
            port   => $port,
        );

    # Add an IPv4 prefix to the server.

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

    my @pdus;
    $client->{'pdu_cb'} = sub {
        my ($pdu) = @_;
        push @pdus, $pdu;
    };

    # Try to reset.  The client should process the data from the
    # server successfully, receiving and ignoring the initial serial
    # notify PDU.

    eval { $client->reset() };
    my $error = $@;
    ok((not $error), 'Processed data from server successfully');
    ok(@pdus, 'Got PDUs from server');
    is($pdus[0]->type(), PDU_SERIAL_NOTIFY(),
        'Got (and ignored) a serial notify PDU from the server');

    $client->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
