#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::PDU::IPv6Prefix;
use APNIC::RPKI::RTR::PDU::ASPA;
use APNIC::RPKI::RTR::PDU::RouterKey;
use APNIC::RPKI::RTR::PDU::Utils qw(order_pdus);

use Cwd qw(cwd);
use File::Slurp qw(write_file read_file);
use File::Temp qw(tempdir);
use JSON::XS qw(decode_json encode_json);
use List::Util qw(shuffle first);
use Net::EmptyPort qw(empty_port);
use Time::HiRes qw(time);
use POSIX ":sys_wait_h";

## rtrtr.

my $preamble = "rtrtr,main";

sub start_server
{
    my (%args) = @_;

    my $data_dir = tempdir(CLEANUP => 1);
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port = empty_port();
    my $server =
        APNIC::RPKI::RTR::Server->new(
            server               => '127.0.0.1',
            port                 => $port,
            data_dir             => $data_dir,
            serial_notify_period => 0,
            %args,
        );

    my $pid;
    if ($pid = fork()) {
    } else {
        $server->run();
        exit(0);
    }
    sleep(0.2);

    my $server_data = {
        data_dir => $data_dir,
        mnt      => $mnt,
        port     => $port,
        pid      => $pid
    };

    return $server_data;
}

sub kill_process
{
    my ($pid) = @_;

    my $wp = waitpid($pid, WNOHANG);
    if ($wp == $pid) {
        return 1;
    }

    my $res = kill('TERM', $pid);
    if ($res != 1) {
        die "unable to send term signal to pid '$pid'";
    }
    my $tries = 10;
    while (kill(0, $pid) and ($tries > 0)) {
        my $wp = waitpid($pid, WNOHANG);
        if ($wp == $pid) {
            return 1;
        }
        $tries--;
        sleep(1);
    }
    if (kill(0, $pid)) {
        warn `ps aux | grep $pid | grep -v grep`;
        warn "pid '$pid' still running after term";
        my $wp = waitpid($pid, WNOHANG);
        if ($wp == $pid) {
            return 1;
        }

        my $res = kill('KILL', $pid);
        if ($res != 1) {
            die "unable to send kill signal to pid '$pid'";
        }
        my $tries = 10;
        while (kill(0, $pid) and ($tries > 0)) {
            $tries--;
            sleep(1);
        }
        if (kill(0, $pid)) {
            warn `ps aux | grep $pid | grep -v grep`;
            die "pid '$pid' still running after kill";
        }
    }

    return 1;
}

sub stop_server
{
    my ($server) = @_;

    kill_process($server->{'pid'});

    return 1;
}

sub run_client
{
    my ($port, $timeout) = @_;
    $timeout ||= 5;

    my $fto = File::Temp->new();
    my $fto_fn = $fto->filename();

    my $fte = File::Temp->new();
    my $fte_fn = $fte->filename();

    my $rtrtr_rtr_port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;
    my $rtrtr_http_port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;

    my $config = <<EOF;
log_level = "trace"
log_target = "stderr"
log_facility = "daemon"
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
    warn "$fn";

    my $pid;
    if ($pid = fork()) {
    } else {
        my $rtr_path = $ENV{'RTRTR_PATH'} || 'rtrtr';
        system("timeout $timeout $rtr_path -c $fn >$fto_fn 2>$fte_fn");
        exit(0);
    }
    waitpid($pid, 0);

    my @out = read_file($fto_fn);
    my @err = read_file($fte_fn);
    chomp for @out;
    chomp for @err;

    return ($pid, \@out, \@err);
}

# Can connect with version 0.
{
    # Hardcoded (not configurable in the client).
    print "$preamble,v0_connect,failure\n";
}

# Can connect with version 1.
{
    # Hardcoded (not configurable in the client).
    print "$preamble,v1_connect,failure\n";
}

# Can connect with version 2.
{
    my $server = start_server();
    my ($mnt, $port) = @{$server}{qw(mnt port)};

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

    my ($pid, $out, $err) = run_client($port, 1);
    if (first { /Got update .1 entries./ } @{$err}) {
        print "$preamble,v2_connect,success\n";
    } else {
        print "$preamble,v2_connect,failure\n";
    }

    stop_server($server);
}

# Basic operation.
{
    my $server = start_server(refresh_interval => 1);
    my ($mnt, $port) = @{$server}{qw(mnt port)};

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

    my ($pid, $out, $err) = run_client($port);
    if ((grep { /starting update/ } @{$err}) >= 4) {
        print "$preamble,sends_reset_query,success\n";
        print "$preamble,accepts_cache_response,success\n";
        print "$preamble,accepts_end_of_data,success\n";
    } else {
        print "$preamble,sends_reset_query,failure\n";
        print "$preamble,accepts_cache_response,failure\n";
        print "$preamble,accepts_end_of_data,failure\n";
    }

    stop_server($server);
}

# Handles serial notify.
{
    my $server = start_server();
    my ($mnt, $port) = @{$server}{qw(mnt port)};

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

    my $state_path_ft = File::Temp->new();
    my $state_path = $state_path_ft->filename();

    my $pid;
    if ($pid = fork()) {
    } else {
        my ($pid, $out, $err) = run_client($port, 5);
        if ((grep { /starting update/ } @{$err}) == 2) {
            print "$preamble,accepts_serial_notify,success\n";
        } else {
            print "$preamble,accepts_serial_notify,failure\n";
        }
        exit(0);
    }
    sleep(1);

    my $changeset2 = APNIC::RPKI::RTR::Changeset->new();
    my $pdu2 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '2.0.0.0',
            prefix_length => 24,
            max_length    => 32
        );
    $changeset2->add_pdu($pdu2);
    $mnt->apply_changeset($changeset2);
    sleep(5);

    kill_process($pid);
    stop_server($server);
}

# Handles no-op response.
{
    my $server = start_server(refresh_interval => 1);
    my ($mnt, $port) = @{$server}{qw(mnt port)};

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

    my $pid;
    if ($pid = fork()) {
    } else {
        my ($pid, $out, $err) = run_client($port, 5);
        my @ss = grep { /starting update/ } @{$err};
        if (@ss > 3) {
            print "$preamble,handles_cache_response_no_op,success\n";
        } else {
            print "$preamble,handles_cache_response_no_op,failure\n";
        }
        exit(0);
    }
    sleep(6);

    kill_process($pid);
    stop_server($server);
}

# Handles reset on bad session ID.
{
    my $server = start_server(next_session_id  => 1,
                              refresh_interval => 1,
                              retry_interval   => 1);
    my ($mnt, $port) = @{$server}{qw(mnt port)};

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

    my $pid;
    if ($pid = fork()) {
    } else {
        my ($pid, $out, $err) = run_client($port, 5);
        # It gets to "awaiting reconnect", but then stops there.
        my @ss = grep { /starting update/ } @{$err};
        if (@ss >= 2) {
            print "$preamble,handles_reset_on_session_mismatch,success\n";
        } else {
            print "$preamble,handles_reset_on_session_mismatch,failure\n";
        }
        exit(0);
    }
    sleep(8);

    kill_process($pid);
    stop_server($server);
}

# Handles reset on absence of server history.
{
    my $server = start_server(refresh_interval => 1);
    my ($mnt, $port, $data_dir) =
        @{$server}{qw(mnt port data_dir)};

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

    my $pid;
    if ($pid = fork()) {
    } else {
        my ($pid, $out, $err) = run_client($port, 5);
        # It gets to "awaiting reconnect", but then stops there.
        use Data::Dumper;
        warn Dumper($out,$err);
        my @ss = grep { /starting update/ } @{$err};
        if (@ss >= 2) {
            print "$preamble,handles_reset_on_absence_of_history,success\n";
        } else {
            print "$preamble,handles_reset_on_absence_of_history,failure\n";
        }
        exit(0);
    }
    sleep(1);

    my $cwd = cwd();
    chdir $data_dir or die $!;
    my @data_dir_contents = `ls .`;
    chomp for @data_dir_contents;
    for my $ddc (@data_dir_contents) {
        if ($ddc eq '.' or $ddc eq '..') {
            next;
        }
        warn "mv $ddc _$ddc";
        my $res = system("mv $ddc _$ddc");
        if ($res != 0) {
            warn "unable to move data file";
        }
    }

    $changeset = APNIC::RPKI::RTR::Changeset->new();
    $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '2.0.0.0',
            prefix_length => 24,
            max_length    => 32
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);

    sleep(8);

    kill_process($pid);
    stop_server($server);
}

# Handles no data.
{
    my $server = start_server();
    my ($mnt, $port, $data_dir) =
        @{$server}{qw(mnt port data_dir)};

    my ($pid, $out, $err) = run_client($port, 2);
    my ($nda) = grep { /reported error 2/ } @{$err};
    if ($nda) {
        print "$preamble,no_data_returned_correctly,success\n";
    } else {
        print "$preamble,no_data_returned_correctly,failure\n";
    }

    stop_server($server);
}

# Handles all payload PDU types.
{
    my $server = start_server();
    my ($mnt, $port, $data_dir) =
        @{$server}{qw(mnt port data_dir)};

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my @pdus = (
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '1.0.0.0',
            prefix_length => 24,
            max_length    => 32
        ),
        APNIC::RPKI::RTR::PDU::IPv6Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '1::',
            prefix_length => 24,
            max_length    => 32
        ),
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            afi_flags     => 3,
            customer_asn  => 4608,
            provider_asns => [1, 2, 3, 4],
        ),
        APNIC::RPKI::RTR::PDU::RouterKey->new(
            version => 1,
            flags   => 1,
            ski     => ('1' x 20),
            spki    => ('1' x 91),
            asn     => 4608,
        )
    );
    for my $pdu (@pdus) {
        $changeset->add_pdu($pdu);
    }
    $mnt->apply_changeset($changeset);

    my ($pid, $out, $err) = run_client($port, 2);
    if (first { /4 entries/ } @{$err}) {
        print "$preamble,handles_ipv4,success\n";
        print "$preamble,handles_ipv6,success\n";
        print "$preamble,handles_aspa,success\n";
        print "$preamble,handles_router_key,success\n";
    } else {
        print "$preamble,handles_ipv4,failure\n";
        print "$preamble,handles_ipv6,failure\n";
        print "$preamble,handles_aspa,failure\n";
        print "$preamble,handles_router_key,failure\n";
    }

    stop_server($server);
}

{
    print "$preamble,handles_cache_restart,failure\n";
    print "$preamble,handles_cache_shutdown,failure\n";
    print "$preamble,ssh,failure\n";
    print "$preamble,tls,failure\n";
    print "$preamble,tcp-md5,failure\n";
    print "$preamble,tcp-ao,failure\n";
}

1;
