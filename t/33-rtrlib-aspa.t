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
    plan tests => 3;
} else {
    plan skip_all => 'ASPA rtrclient not available';
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

    # Run rtrclient.  (The branch that supports ASPA records doesn't
    # print them when -e is set, so rely on the '+' lines instead.)

    my $error_output =
        $ENV{'APNIC_DEBUG'}
            ? ""
            : " 2>/dev/null";
    my @raw_res =
        `rtrclient -a -p tcp 127.0.0.1 $port $error_output`;
    my @res =
        map { s/\s+/ /g; $_ }
        grep { $_ and /^\s*\+/ }
        map { s/\s*//; chomp; $_ }
            @raw_res;
    if ($ENV{'APNIC_DEBUG'}) {
        use Data::Dumper;
        diag Dumper(\@res);
    }
    my $header = shift @res;
    is(@res, 2, 'Got two lines in rtrclient output');
    is($res[0], '+ 1.0.0.0 24 - 32 4608',
        'Got correct VRP line in rtrclient output');
    is($res[1], '+ ASPA 4608 => [ 1, 2, 3, 4 ]',
        'Got correct ASPA line in rtrclient output');

    my $res = kill('TERM', $pid);
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
