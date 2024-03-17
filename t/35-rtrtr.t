#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);
use Test::More;

if ($ENV{'HAS_RTRTR'}) {
    plan tests => 2;
} else {
    plan skip_all => 'rtrtr not available';
}

my @pids;

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
    $mnt->apply_changeset($changeset);

    # Run rtrtr.

    my $rtrtr_rtr_port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;
    my $rtrtr_http_port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;

    my $config = <<EOF;
#log_level = "debug"
#log_target = "stderr"
#log_facility = "daemon"
http-listen = ["127.0.0.1:$rtrtr_http_port"]

[units.ufirst]
type = "rtr"
remote = "127.0.0.1:$port"

[targets.tfirst]
type = "rtr"
listen = [ "127.0.0.1:$rtrtr_rtr_port" ]
unit = "ufirst"
EOF

    my $ft = File::Temp->new();
    my $fn = $ft->filename();
    write_file($fn, $config);

    my @rtrtr_pids = `ps -C rtrtr`;
    shift @rtrtr_pids;
    my %rtrtr_pid_lookup;
    for my $rtrtr_pid (@rtrtr_pids) {
        $rtrtr_pid =~ s/\s.*//;
        chomp $rtrtr_pid;
        $rtrtr_pid_lookup{$rtrtr_pid} = 1;
    }
    if (my $pid = fork()) {
        push @pids, $pid;
    } else {
        system("rtrtr -c $fn");
        exit(0);
    }
    sleep(1);

    @rtrtr_pids = `ps -C rtrtr`;
    shift @rtrtr_pids;
    for my $rtrtr_pid (@rtrtr_pids) {
        $rtrtr_pid =~ s/\s.*//;
        chomp $rtrtr_pid;
        if (not $rtrtr_pid_lookup{$rtrtr_pid}) {
            push @pids, $rtrtr_pid;
        }
    }

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $rtrtr_rtr_port,
            supported_versions => [0, 1, 2]
        );
    $client->reset();
    my @pdus = $client->{'state'}->pdus();
    is(@pdus, 1, 'Got one PDU from RTRTR');
    $pdu = $pdus[0];
    is($pdu->address(), '1.0.0.0',
        'PDU has correct address');
 
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
