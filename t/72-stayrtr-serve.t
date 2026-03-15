#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);
use List::Util qw(min);
use Net::EmptyPort qw(empty_port);
use Test::More;

if ($ENV{'HAS_STAYRTR'}) {
    plan tests => 2;
} else {
    plan skip_all => 'stayrtr not available';
}

my @pids;

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

    if (my $ppid = fork()) {
        push @pids, $ppid;
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
        APNIC::RPKI::RTR::PDU::RouterKey->new(
            version  => 1,
            flags    => 1,
            ski      => 1234,
            asn      => 4608,
            spki     => 'asdf',
        );
    $changeset->add_pdu($pdu2);
    $mnt->apply_changeset($changeset);

    my $oft = File::Temp->new();
    my $ofn = $oft->filename();
    # Remove the object now, so that the forked process does not
    # remove the underlying file when it exits.
    $oft = undef;
    my $rpid;
    if ($rpid = fork()) {
        push @pids, $rpid;
    } else {
        system("/stayrtr-SelectiveSync/rtr-client -host 127.0.0.1 -port $port -subscribe 9 >$ofn 2>&1");
        exit(0);
    }
    sleep(5);
    kill('TERM', $rpid);
    my @lines = read_file($ofn);
    my @rks = grep { /Router Key Add/ } @lines;
    my @ips = grep { /IPv4 Add/ } @lines;
    is(@rks, 1, "Got one debug line for router key PDUs");
    is(@ips, 0, "Got no debug lines for IPv4 PDUs");

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
