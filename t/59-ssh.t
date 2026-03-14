#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::PDU::Utils qw(parse_pdu);

use Cwd qw(cwd);
use File::Slurp qw(write_file read_file);
use File::Temp qw(tempdir);
use List::MoreUtils qw(uniq);
use Net::EmptyPort qw(empty_port);
use IPC::Open2 qw(open2);
use IO::File;

use Test::More;
if ($ENV{'SKIP_RTR_SSH'}) {
    plan skip_all => 'Skipping SSH tests';
} else {
    plan tests => 4;
}

my @pids;

{
    my $ssh_port = empty_port();
    my $port = empty_port();

    my %ssh_pids =
        map { chomp; $_ => 1 } 
            `ps aux | grep ssh | sed 's/  */ /g' | cut -f2 -d' '`;

    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        diag "SSH PID is $$";
        unlink "t/key";
        unlink "t/key.pub";
        for my $f (`ls t/hostkeys/etc/ssh`) {
            chomp $f;
            unlink "t/hostkeys/etc/ssh/$f";
        }
        system("ssh-keygen -f t/key -t rsa -N ''");
        system("mkdir -p t/hostkeys/etc/ssh");
        system("ssh-keygen -A -f t/hostkeys");
        my @rsa_data = read_file("t/hostkeys/etc/ssh/ssh_host_rsa_key.pub");
        for (@rsa_data) {
            s/^/127.0.0.1 /;
        }
        write_file("t/known-hosts", @rsa_data);
        my @sshd_conf = read_file("t/sshd.conf");
        my $cwd = cwd();
        for (@sshd_conf) {
            s/{port}/$ssh_port/g;
            s/{cwd}/$cwd/g;
            s/{rr_port}/$port/g;
        }
        write_file("t/_sshd.conf", (join '', @sshd_conf));
        my ($sshd) = `which sshd`;
        if (not $sshd) {
            die "Unable to find sshd executable";
        }
        chomp $sshd;
        system("chmod 600 ./t/hostkeys/etc/ssh/ssh_host_rsa_key");
        system("$sshd -d -D -f t/_sshd.conf");
        warn "sshd exited";
        exit(0);
    }
    sleep(2);

    my @new_ssh_pids = `ps aux | grep ssh | sed 's/  */ /g' | cut -f2 -d' '`;
    chomp for @new_ssh_pids;
    for my $new_ssh_pid (@new_ssh_pids) {
        if (not $ssh_pids{$new_ssh_pid}) {
            push @pids, $new_ssh_pid;
        }
    }

    my $data_dir = tempdir(CLEANUP => 1); 
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
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

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server      => '127.0.0.1',
            port        => $ssh_port,
            known_hosts => "t/known-hosts",
            ssh_key     => "t/key",
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

    eval { $client->reset() };
    my $error = $@;
    ok((not $error), 'Got successful response from server');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    my @pdus = $client->state()->pdus();
    is(@pdus, 1, 'State has single PDU');
    $pdu = $pdus[0];
    is($pdu->type(), 4, 'Got IPv4 prefix PDU');
    is($pdu->address(), '1.0.0.0', 'Got correct address');

    $client->exit_server();
}

END {
    for my $pid (sort uniq @pids) {
        kill('TERM', $pid);
    }
}

1;
