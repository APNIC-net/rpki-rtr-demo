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

# Per https://github.com/tanneberger/rtrlib.
if ($ENV{'HAS_ASPA_RTRCLIENT'}) {
    plan tests => 5;
} else {
    plan skip_all => 'ASPA rtrclient not available';
}

my @pids;

{
    # Set up two servers with different changesets.

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
        push @pids, $ppid;
    } else {
        $server->run();
        exit(0);
    }

    my $data_dir2 = tempdir(CLEANUP => 1);
    my $mnt2 =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir2
        );
    my $port2 =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;
    my $server2 =
        APNIC::RPKI::RTR::Server->new(
            server   => '127.0.0.1',
            port     => $port2,
            data_dir => $data_dir2,
        );

    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        $server2->run();
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
    my $pdu2 =
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            afi_flags     => 3,
            customer_asn  => 4608,
            provider_asns => [1, 2, 3, 4],
        );
    $changeset->add_pdu($pdu2);
    $mnt->apply_changeset($changeset);

    my $changeset2 = APNIC::RPKI::RTR::Changeset->new();
    my $pdu2_1 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '2.0.0.0',
            prefix_length => 24,
            max_length    => 32
        );
    $changeset2->add_pdu($pdu2_1);
    my $pdu2_2 =
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            afi_flags     => 3,
            customer_asn  => 4608,
            provider_asns => [4, 5, 6, 7],
        );
    $changeset2->add_pdu($pdu2_2);
    $mnt2->apply_changeset($changeset2);

    # Run rtrclient.  (The branch that supports ASPA records doesn't
    # print them when -e is set, so rely on the '+' lines instead.)

    my @raw_res =
        `rtrclient -e -a -p tcp 127.0.0.1 $port tcp 127.0.0.1 $port2 2>/dev/null`;
    my @res =
        sort
        map { s/\s+/ /g; s/:\d+//; $_ }
        grep { $_ and /^\s*\+/ }
        map { s/\s*//; chomp; $_ }
            @raw_res;
    is(@res, 4, 'Got four lines in rtrclient output');
    is($res[0], '+ 127.0.0.1 1.0.0.0 24 - 32 4608',
        'Got correct VRP line in rtrclient output (1)');
    is($res[1], '+ 127.0.0.1 2.0.0.0 24 - 32 4608',
        'Got correct VRP line in rtrclient output (2)');
    # todo: it's arguable that this isn't correct.
    is($res[2], '+ ASPA 4608 => [ 1, 2, 3, 4 ]',
        'Got correct ASPA line in rtrclient output (1)');
    is($res[3], '+ ASPA 4608 => [ 4, 5, 6, 7 ]',
        'Got correct ASPA line in rtrclient output (2)');

    for my $pid (@pids) {
        kill('TERM', $pid);
    }
}

END {
    for my $pid (@pids) {
        kill('TERM', $pid);
    }
}

1;