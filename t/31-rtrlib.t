#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);
use Test::More;

if ($ENV{'HAS_RTRCLIENT'}) {
    plan tests => 2;
} else {
    plan skip_all => 'rtrclient not available';
}

my $pid;

{
    # Set up the server and add a changeset.

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

    # Run rtrclient.

    my @res =
        grep { $_ }
        map { s/\s*//; chomp; $_ }
            `rtrclient -e tcp 127.0.0.1 $port 2>/dev/null`;
    my $header = shift @res;
    is(@res, 1, 'Got one VRP line in rtrclient output');
    is($res[0], '1.0.0.0/24-32 AS 4608',
        'Got correct VRP line in rtrclient output');

    my $res = kill('TERM', $pid);
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
