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
use Net::EmptyPort qw(empty_port);
use Test::More;

plan skip_all => 'stayrtr not yet updated for ASPAs';

if ($ENV{'HAS_STAYRTR'}) {
    plan tests => 3;
} else {
    plan skip_all => 'stayrtr not available';
}

my @pids;

{
    # Run stayrtr using the test JSON file.

    my @stayrtr_pids = `ps -C stayrtr`;
    shift @stayrtr_pids;
    my %stayrtr_pid_lookup;
    for my $stayrtr_pid (@stayrtr_pids) {
        $stayrtr_pid =~ s/\s.*//;
        chomp $stayrtr_pid;
        $stayrtr_pid_lookup{$stayrtr_pid} = 1;
    }

    my $stayrtr_rtr_port = empty_port();
    my $metrics_port = empty_port();
    if (my $pid = fork()) {
        push @pids, $pid;
    } else {
        system("stayrtr -bind=\"127.0.0.1:$stayrtr_rtr_port\" -metrics.addr=\"127.0.0.1:$metrics_port\" -cache=./t/rpki.json -checktime=false");
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
            supported_versions => [0, 1, 2]
        );
    $client->reset();
    my @pdus = $client->{'state'}->pdus();
    is(@pdus, 11, 'Got ten PDUs from stayrtr');
    my @aspa_pdus = grep { $_->type() == PDU_ASPA() } @pdus;
    is(@aspa_pdus, 3, 'Got three ASPA PDUs');
    my @customer_asns =
        sort { $a <=> $b }
        map  { $_->customer_asn() }
            @aspa_pdus;
    is_deeply(\@customer_asns, [945, 970, 7480],
        'Got correct set of customer ASNs');

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
