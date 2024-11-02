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
    ok((not $error), 'Client reset successfully');

    # Send an invalid request.

    $client->_init_socket_if_not_exists();
    my $socket = $client->{'socket'};
    my $reset_query =
        APNIC::RPKI::RTR::PDU::EndOfData->new(
            version          => 1,
            session_id       => 1,
            serial_number    => 1,
            refresh_interval => 1,
            retry_interval   => 1,
            expire_interval  => 1,
        );
    my $data = $reset_query->serialise_binary();
    my $res = $socket->send($data);
    if ($res != length($data)) {
        die "Got unexpected send result for reset query: '$res' ($!)";
    }

    $pdu = parse_pdu($socket);
    is($pdu->type(), PDU_ERROR_REPORT(),
        'Got error report PDU');
    is($pdu->error_code(), ERR_INVALID_REQUEST(),
        'Got correct error type');

    $res = kill('TERM', $pid);
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
