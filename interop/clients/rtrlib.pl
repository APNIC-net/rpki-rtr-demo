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

## rtrlib.

my $preamble = "rtrlib,master";

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
    my ($port, $persist) = @_;

    my $fto = File::Temp->new();
    my $fto_fn = $fto->filename();

    my $fte = File::Temp->new();
    my $fte_fn = $fte->filename();

    my $extra =
        ($persist)
            ? ""
            : "-e";

    my $res =
        system("timeout 5 rtrclient -k -a $extra tcp 127.0.0.1 $port ".
               ">$fto_fn 2>$fte_fn");
    my @out = read_file($fto_fn);
    my @err = read_file($fte_fn);
    chomp for @out;
    chomp for @err;
    @out =
        grep { $_ ne 'Sync done' }
        grep { $_ }
        map  { s/^\s*$//; $_ }
            @out;
    @err =
        grep { $_ }
        map  { s/^\s*$//; $_ }
            @err;
    my @pdus;
    my @residual;
    for my $o (@out) {
        if ($o =~ /^(.*?)\/(\d+?)-(\d+?) AS (\d+)$/) {
            my ($addr, $pl, $ml, $asn) = ($1, $2, $3, $4);
            if ($addr =~ /\./) {
                my $pdu =
                    APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
                        version       => 2,
                        flags         => 1,
                        address       => $addr,
                        prefix_length => $pl,
                        max_length    => $ml,
                        asn           => $asn,
                    );
                push @pdus, $pdu;
            } else {
                my $pdu =
                    APNIC::RPKI::RTR::PDU::IPv6Prefix->new(
                        version       => 2,
                        flags         => 1,
                        address       => $addr,
                        prefix_length => $pl,
                        max_length    => $ml,
                        asn           => $asn,
                    );
                push @pdus, $pdu;
            }
        } elsif ($o =~ /ASPA (\d+) => \[ (.*) \]/) {
            my $pdu =
                APNIC::RPKI::RTR::PDU::ASPA->new(
                    version       => 2,
                    flags         => 1,
                    customer_asn  => $1,
                    provider_asns => [split(/\s*,\s*/, $2)]
                );
            push @pdus, $pdu;
        } elsif ($o =~ /^ASN:\s+(\d+)$/) {
            my $pdu =
                APNIC::RPKI::RTR::PDU::RouterKey->new(
                    version       => 2,
                    flags         => 1,
                    asn           => $1,
                    ski           => '1234',
                    spki          => '1234'
                );
            push @pdus, $pdu;
        } else {
            push @residual, $o;
        }
    }

    return ($res, \@pdus, \@residual, \@err);
}

# Can connect with version 0.
{
    # Hardcoded (not configurable in the client).
    print "$preamble,v0_connect,failure\n";
}

# Can connect with version 1.
{
    # This is currently the only version supported by rtrlib,
    # notwithstanding the support for ASPAs.

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

    my ($res, $pdus, $out, $err) = run_client($port);
    if (($res == 0)
            and (@{$pdus})) {
        print "$preamble,v1_connect,success\n";
    } else {
        print "$preamble,v1_connect,failure\n";
    }

    stop_server($server);
}

# Can connect with version 2.
{
    # Hardcoded (not configurable in the client, client uses v1 only).
    print "$preamble,v2_connect,failure\n";
}

# Basic operation.
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

    my ($res, $pdus, $out, $err) = run_client($port);
    if (($res == 0)
            and (@{$pdus})
            and (first { /Sending reset query/ } @{$err})
            and (first { /EOD PDU received/    } @{$err})) {
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
        my ($res, $pdus, $out, $err) = run_client($port, 1);
        my $found =
            first { /Serial Notify received/ }
                @{$err};
        if ($found) {
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
        my ($res, $pdus, $out, $err) = run_client($port, 1);
        my @ss = grep { /Sync successful/ } @{$err};
        if (@ss > 3) {
            print "$preamble,handles_cache_response_no_op,success\n";
        } else {
            print "$preamble,handles_cache_response_no_op,failure\n";
        }
        exit(0);
    }
    sleep(8);

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
        my ($res, $pdus, $out, $err) = run_client($port, 1);
        # Currently, there will be more than two errors, because
        # instead of flushing data, it just keeps retrying the serial
        # query.
        my @errs = grep { /RTR_MGR_ERROR/ } @{$err};
        if (@errs == 2) {
            print "$preamble,handles_reset_on_session_mismatch,success\n";
        } else {
            print "$preamble,handles_reset_on_session_mismatch,failure\n";
        }
        exit(0);
    }
    sleep(8);

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
        my ($res, $pdus, $out, $err) = run_client($port, 1);
        my @prs = grep { /received 1 Prefix PDUs/ } @{$err};
        if (@prs == 2) {
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

    my ($res, $pdus, $out, $err) = run_client($port);
    my ($nda) = grep { /No data available/ } @{$err};
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

    my ($res, $pdus, $out, $err) = run_client($port);
    if (first { $_->type() == PDU_IPV4_PREFIX() } @{$pdus}) {
        print "$preamble,handles_ipv4,success\n";
    } else {
        print "$preamble,handles_ipv4,failure\n";
    }

    if (first { $_->type() == PDU_IPV6_PREFIX() } @{$pdus}) {
        print "$preamble,handles_ipv6,success\n";
    } else {
        print "$preamble,handles_ipv6,failure\n";
    }

    if (first { $_->type() == PDU_ASPA() } @{$pdus}) {
        print "$preamble,handles_aspa,success\n";
    } else {
        print "$preamble,handles_aspa,failure\n";
    }

    if (first { $_->type() == PDU_ROUTER_KEY() } @{$pdus}) {
        print "$preamble,handles_router_key,success\n";
    } else {
        print "$preamble,handles_router_key,failure\n";
    }
    stop_server($server);
}

{
    # todo: add a specific test for SSH.

    print "$preamble,handles_cache_restart,failure\n";
    print "$preamble,handles_cache_shutdown,failure\n";
    print "$preamble,ssh,success\n";
    print "$preamble,tls,failure\n";
    print "$preamble,tcp-md5,failure\n";
    print "$preamble,tcp-ao,failure\n";
}

1;
