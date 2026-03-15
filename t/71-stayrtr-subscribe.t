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
    my @stayrtr_pids = `ps -C stayrtr`;
    shift @stayrtr_pids;
    my %stayrtr_pid_lookup;
    for my $stayrtr_pid (@stayrtr_pids) {
        $stayrtr_pid =~ s/^\s*//;
        $stayrtr_pid =~ s/\s.*//;
        chomp $stayrtr_pid;
        $stayrtr_pid_lookup{$stayrtr_pid} = 1;
    }

    my $stayrtr_rtr_port = empty_port();
    my $metrics_port = empty_port();
    if (my $pid = fork()) {
        push @pids, $pid;
    } else {
        system("/stayrtr-SelectiveSync/stayrtr -bind=\"127.0.0.1:$stayrtr_rtr_port\" -metrics.addr=\"127.0.0.1:$metrics_port\" -cache=./t/rpki.json -checktime=false -protocol=1 -loglevel debug -log.verbose");
        exit(0);
    }
    sleep(1);

    @stayrtr_pids = `ps -C stayrtr`;
    shift @stayrtr_pids;
    for my $stayrtr_pid (@stayrtr_pids) {
        $stayrtr_pid =~ s/^\s*//;
        $stayrtr_pid =~ s/\s.*//;
        chomp $stayrtr_pid;
        if (not $stayrtr_pid_lookup{$stayrtr_pid}) {
            push @pids, $stayrtr_pid;
        }
    }

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $stayrtr_rtr_port,
            # Does not work when version is set to 2.
            supported_versions => [0, 1],
            data_types         => [9],
        );
    $client->reset();
    my @pdus = $client->{'state'}->pdus();
    is(@pdus, 1, 'Got one PDU from stayrtr (subscribed to router key)');
    my @rk_pdus = grep { $_->type() == PDU_ROUTER_KEY() } @pdus;
    is(@rk_pdus, 1, 'Got single router key PDU');

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
