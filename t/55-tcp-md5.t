#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);

use Test::More tests => 3;

my $pid;

{
    my $data_dir = tempdir(CLEANUP => 1); 
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;
    my $server =
        APNIC::RPKI::RTR::Server->new(
            server      => '127.0.0.1',
            port        => $port,
            data_dir    => $data_dir,
            tcp_md5_key => 'ABCD',
        );

    if (my $ppid = fork()) {
        $pid = $ppid;
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

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

    # Connection fails on incorrect key.

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server      => '127.0.0.1',
            port        => $port,
            timeout     => 1,
            tcp_md5_key => 'ASDF',
        );

    eval { $client->reset() };
    my $error = $@;
    ok($error, 'Mismatching TCP keys causes failure');
    like($error, qr/timeout/, 'Got expected error message');

    # Connection succeeds on correct key.

    $client =
        APNIC::RPKI::RTR::Client->new(
            server      => '127.0.0.1',
            port        => $port,
            timeout     => 1,
            tcp_md5_key => 'ABCD',
        );

    eval { $client->reset() };
    $error = $@;
    ok((not $error), 'Connection succeeds on matching TCP keys');

    $client->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
