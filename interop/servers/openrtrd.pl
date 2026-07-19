#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::PDU::IPv6Prefix;
use APNIC::RPKI::RTR::PDU::ASPA;
use APNIC::RPKI::RTR::PDU::RouterKey;
use APNIC::RPKI::RTR::PDU::Utils qw(order_pdus);

use File::Slurp qw(write_file read_file);
use File::Temp qw(tempdir);
use JSON::XS qw(decode_json encode_json);
use List::Util qw(shuffle);
use Net::EmptyPort qw(empty_port);
use POSIX ":sys_wait_h";
use Time::HiRes qw(sleep);

## openrtrd.

my $port = 3323;
my $preamble = "openrtrd,main";
my $expiry = time() + 86400;

sub start_server
{
    my @res = `ps aux | grep _rtrd | grep -v grep`;
    if (@res) {
        die "openrtrd is already running: ".
            (join "", @res);
    }

    my $fork_pid;
    if ($fork_pid = fork()) {
    } else {
        my $extra = "2>/dev/null";
        if (not $ENV{'APNIC_DEBUG'}) {
            close STDOUT;
            close STDERR;
        } else {
            $extra = "";
        }
        system("rtrd -f -s /tmp/rtrd.sock $extra");
        exit(0);
    }
    sleep(1); 

    my @pid_lines = `ps aux | grep ^_rtrd`;
    chomp for @pid_lines;
    my @real_pids =
        map { my (undef, $real_pid) =
                split /\s+/;
              $real_pid }
            @pid_lines;

    return \@real_pids;
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
    my ($real_pids) = @_;

    for my $pid (reverse @{$real_pids}) {
        if (!kill(0, $pid)) {
            die "server pid '$pid' no longer present";
        }
        kill_process($pid);
    }

    return 1;
}

sub write_state
{
    my ($state) = @_;

    my $state_ft = File::Temp->new();
    my $state_fn = $state_ft->filename();
    write_file($state_fn, $state);
    my $res = system("rtr-import $state_fn /tmp/rtrd.sock");
    if ($res != 0) {
        die "unable to run rtr-import";
    }

    return 1;
}

# Can connect with version 0.
{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
        1.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
}
EOF

    write_state($state);

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [0]
        );
    my @pdus;
    eval {
        $client->reset();
        @pdus = $client->{'state'}->pdus();
    };
    my $error = $@;
    if ((@pdus == 1)
            and ($pdus[0]->address() eq '1.0.0.0')
            and ($client->_current_version() == 0)) {
        print "$preamble,v0_connect,success\n";
    } else {
        warn $error;
        use Data::Dumper;
        warn Dumper(\@pdus, $client->_current_version());
        print "$preamble,v0_connect,failure\n";
    }

    stop_server($pids);
}

# Can connect with version 1.
{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
        1.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
}
EOF

    write_state($state);

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [1]
        );
    my @pdus = ();
    eval {
        $client->reset();
        @pdus = $client->{'state'}->pdus();
    };
    my $error = $@;
    if ((@pdus == 1)
            and ($pdus[0]->address() eq '1.0.0.0')
            and ($client->_current_version() == 1)) {
        print "$preamble,v1_connect,success\n";
    } else {
        warn $error;
        print "$preamble,v1_connect,failure\n";
    }

    stop_server($pids);
}

# Can connect with version 2.
{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
        1.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
}
EOF

    write_state($state);

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [2]
        );
    my @pdus = ();
    eval {
        $client->reset();
        @pdus = $client->{'state'}->pdus();
    };
    my $error = $@;
    if ((@pdus == 1)
            and ($pdus[0]->address() eq '1.0.0.0')
            and ($client->_current_version() == 2)) {
        print "$preamble,v2_connect,success\n";
    } else {
        print "$preamble,v2_connect,failure\n";
    }

    stop_server($pids);
}

# Uses version 2 if available.
{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
        1.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
}
EOF

    write_state($state);

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [0, 1, 2]
        );
    my @pdus = ();
    eval {
        $client->reset();
        @pdus = $client->{'state'}->pdus();
    };
    my $error = $@;
    if ((@pdus == 1)
            and ($pdus[0]->address() eq '1.0.0.0')
            and ($client->_current_version() == 2)) {
        print "$preamble,v2_connect,success\n";
        print "$preamble,accepts_reset_query,success\n";
        print "$preamble,sends_cache_response,success\n";
    } else {
        warn $error;
        print "$preamble,v2_connect,failure\n";
        print "$preamble,accepts_reset_query,failure\n";
        print "$preamble,sends_cache_response,failure\n";
    }
    if ($client->{'eod'}) {
        print "$preamble,sends_end_of_data,success\n";
    } else {
        print "$preamble,sends_end_of_data,failure\n";
    }

    stop_server($pids);
}

# Serial notify.
{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
        1.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
}
EOF

    write_state($state);

    my $state_path_ft = File::Temp->new();
    my $state_path = $state_path_ft->filename();

    my $client_pid;
    if ($client_pid = fork()) {
    } else {
	my $client =
	    APNIC::RPKI::RTR::Client->new(
		server     => '127.0.0.1',
		port       => $port,
		state_path => $state_path,
	    );
        $client->reset(undef, 1);
        exit(0);
    }
    sleep(1);

    $state = <<EOF;
roa-set {
        1.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
        2.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
}
EOF
    write_state($state);
    sleep(5);

    my $state_data = read_file($state_path);
    $state_data = decode_json($state_data);
    $state_data = decode_json($state_data->{'state'});
    if (exists $state_data->{'vrps'}
			  ->{'4608'}->{'2.0.0.0'}->{'24'}) {
        print "$preamble,sends_serial_notify,success\n";
    } else {
        print "$preamble,sends_serial_notify,failure\n";
    }

    kill_process($client_pid);
    stop_server($pids);
}

{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
        1.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
}
EOF

    write_state($state);
    
    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [0, 1, 2]
        );
    my @pdus = ();
    my $res;
    eval {
        $client->reset();
        $res = $client->refresh(1);
        @pdus = $client->{'state'}->pdus();
    };
    my $error = $@;
    if (($res == 1) and (@pdus == 1)) {
        print "$preamble,accepts_serial_query_no_op,success\n";
    } else {
        warn $error;
        print "$preamble,accepts_serial_query_no_op,failure\n";
    }

    stop_server($pids);
}

{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
        1.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
}
EOF

    write_state($state);

    my $state_path_ft = File::Temp->new();
    my $state_path = $state_path_ft->filename();

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server     => '127.0.0.1',
            port       => $port,
            state_path => $state_path,
        );
    $client->reset();
    $client->{'state'}->{'session_id'}++;
    $client->{'state'}->{'session_id'} &= 0xFFFF;

    eval {
        $client->refresh(1);
    };
    my $error = $@;
    my $error_data = "";
    my $ec;
    my $ec_is_zero = 0;
    eval {
        my ($error_json) = ($error =~ /({.*})/);
        $error_data = decode_json($error_json);
        if (exists $error_data->{'error_code'}) {
            $ec = $error_data->{'error_code'};
            if ($ec == 0) {
                $ec_is_zero = 1;
            }
        }
    };
    my $error2 = $@;
    # Currently returns "cache reset" instead.
    if ($ec_is_zero) {
        print "$preamble,returns_corrupt_data_on_session_mismatch,success\n";
    } else {
        warn "$error, $error_data, $error2";
        print "$preamble,returns_corrupt_data_on_session_mismatch,failure\n";
    }

    stop_server($pids);
}

{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
        1.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
}
EOF

    write_state($state);

    my $state_path_ft = File::Temp->new();
    my $state_path = $state_path_ft->filename();

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server     => '127.0.0.1',
            port       => $port,
            state_path => $state_path,
        );
    $client->reset();

    # openrtrd retains only 10 history entries, so adding 13 here will
    # mean that the client can't refresh.  (The check below assumes
    # that this is what happens, which is the case at the moment at
    # least, but the test could be more robust.)
    my $common = "0.0.0/24 maxlen 32 source-as 4608 expires $expiry";
    my @current = (
        "1.$common",
        "2.$common"
    );
    for my $i (3..15) {
        push @current, "$i.$common";
        my $current_str = join "\n", @current;
        $state = <<EOF;
roa-set {
$current_str
}
EOF
        print "($state)\n";
        write_state($state);
        sleep(0.25);
    }

    eval {
        $client->refresh(1);
    };
    my $error = $@;
    if (not $error) {
        print "$preamble,reset_on_absence_of_history,success\n";
    } else {
        warn "$error";
        print "$preamble,reset_on_absence_of_history,failure\n";
    }

    stop_server($pids);
}

# Empty openrtrd server.
{
    my $pids = start_server();

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server     => '127.0.0.1',
            port       => $port,
        );
    eval { 
        $client->reset();
    };
    my $error = $@;
    if ($error =~ /Server has no data/) {
        print "$preamble,no_data_returned_correctly,success\n";
    } else {
        warn $error;
        print "$preamble,no_data_returned_correctly,failure\n";
    }

    stop_server($pids);
}

# Multiple PDU types.
{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
    1.0.0.0/24 maxlen 32 source-as 4608 expires $expiry
    1::/24 maxlen 32 source-as 4608 expires $expiry
}
aspa-set {
    customer-as 4608 provider-as { 1, 2, 3, 4 }
}
EOF

    write_state($state);
    sleep(1);
   
    my $client =
        APNIC::RPKI::RTR::Client->new(
            server => '127.0.0.1',
            port   => $port,
        );
    eval { 
        $client->reset();
    };
    my $error = $@;
    my $state_data = $client->{'state'};
    if (exists $state_data->{'vrps'}
                        ->{'4608'}->{'1.0.0.0'}->{'24'}) {
        print "$preamble,sends_ipv4,success\n";
    } else {
        print "$preamble,sends_ipv4,failure\n";
    }

    if (exists $state_data->{'vrps'}
                        ->{'4608'}->{'1::'}->{'24'}) {
        print "$preamble,sends_ipv6,success\n";
    } else {
        print "$preamble,sends_ipv6,failure\n";
    }

    if (exists $state_data->{'aspas'}->{4608}) {
        print "$preamble,sends_aspa,success\n";
    } else {
        print "$preamble,sends_aspa,failure\n";
    }

    # Hardcoded.
    print "$preamble,sends_router_key,failure\n";

    stop_server($pids);
}

# Ordering.
{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
    3::/16 maxlen 28 source-as 4608 expires $expiry
    3::/24 maxlen 32 source-as 4609 expires $expiry
    3::/24 maxlen 32 source-as 4608 expires $expiry
}
aspa-set {
    customer-as 4609 provider-as { 1, 2, 3, 4 }
}
EOF
    write_state($state);
    sleep(1);

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server         => '127.0.0.1',
            port           => $port,
            strict_receive => 1,
        );
    eval { 
        $client->reset();
    };
    my $error = $@;
    if ($error) {
        if ($error =~ /got unordered PDUs/) {
            print "$preamble,sends_ordered_pdus,failure\n";
        } else {
            warn "Expected unordered PDUs, got other error '$error'";
            print "$preamble,sends_ordered_pdus,failure\n";
        }
    } else {
        print "$preamble,sends_ordered_pdus,success\n";
    }
    
    stop_server($pids);
}

# Cache restart.
{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
    3::/16 maxlen 28 source-as 4608 expires $expiry
    3::/24 maxlen 32 source-as 4609 expires $expiry
    3::/24 maxlen 32 source-as 4608 expires $expiry
}
aspa-set {
    customer-as 4609 provider-as { 1, 2, 3, 4 }
}
EOF
    write_state($state);
    sleep(1);

    my $state_path_ft = File::Temp->new();
    my $state_path = $state_path_ft->filename();

    my $corrupt_data_ft = File::Temp->new();
    my $corrupt_data_fn = $corrupt_data_ft->filename();

    my $restart_ft = File::Temp->new();
    my $restart_fn = $restart_ft->filename();

    my $client_pid;
    if ($client_pid = fork()) {
    } else {
        my $client =
            APNIC::RPKI::RTR::Client->new(
                server         => '127.0.0.1',
                port           => $port,
                state_path     => $state_path,
                retry_interval => 10
            );
        $client->{'pdu_cb'} = sub {
            my ($pdu) = @_;
            if (($pdu->type() == PDU_ERROR_REPORT())
                    and ($pdu->error_code() == ERR_CACHE_RESTART())) {
                write_file($restart_fn, "yes");
            }
        };
        for (;;) {
            eval { $client->reset(undef, 1); };
            if (my $error = $@) {
                warn "client reset error: $error";
                my $error_pdu = $client->{'error_pdu'};
                if (not $error_pdu) {
                    die "expected error PDU to be set on client";
                }
                if ($error_pdu->error_code() == ERR_CORRUPT_DATA()) {
                    # This will happen when the server restarts, so
                    # just try again in this case.
                    write_file($corrupt_data_fn, "yes");
                    next;
                } else {
                    die $error;
                }
            }
        }
        exit(0);
    }
    sleep(1);

    my $rtrd_pid = pop(@{$pids});
    my $count = kill("USR1", $rtrd_pid);
    if ($count != 1) {
        die "unable to restart openrtrd";
    }
    warn "Sleeping for 2s to allow openrtrd to shut down...";
    sleep(2);
    if (kill(0, $rtrd_pid)) {
        die "openrtrd process has not shut down";
    }
    stop_server($pids);

    # Have to manually restart it, since the signal is just about
    # the PDU that gets sent to the client.

    $pids = start_server();
    write_state($state);
    sleep(1);

    warn "Sleeping for 15s to allow client import to continue...";
    sleep(15);

    my $state_data = read_file($state_path);
    $state_data = decode_json($state_data);
    $state_data = decode_json($state_data->{'state'});
    my $has_vrp =
        (exists $state_data->{'vrps'}
                        ->{'4608'}->{'3::'}->{'16'});
	my ($cd_line) = read_file($corrupt_data_fn);
	chomp $cd_line;
    my $has_cd = ($cd_line eq "yes");
	my ($pdu_line) = read_file($restart_fn);
	chomp $pdu_line;
    my $has_pdu = ($pdu_line eq "yes");

    if ($has_vrp) {
        print "$preamble,cache_restart_repopulated,success\n";
    } else {
        print "$preamble,cache_restart_repopulated,failure\n";
    }
    if ($has_pdu) {
        print "$preamble,cache_restart_pdu_received,success\n";
    } else {
        print "$preamble,cache_restart_pdu_received,failure\n";
    }
    # Cache reset (vs. corrupt data) again.
    if ($has_cd) {
        print "$preamble,cache_restart_correct_error,success\n";
    } else {
        print "$preamble,cache_restart_correct_error,failure\n";
    }

    stop_server($pids);
}

# Cache shutdown.
{
    my $pids = start_server();

    my $state = <<EOF;
roa-set {
    3::/16 maxlen 28 source-as 4608 expires $expiry
    3::/24 maxlen 32 source-as 4609 expires $expiry
    3::/24 maxlen 32 source-as 4608 expires $expiry
}
aspa-set {
    customer-as 4609 provider-as { 1, 2, 3, 4 }
}
EOF
    write_state($state);
    sleep(1);

    my $state_path_ft = File::Temp->new();
    my $state_path = $state_path_ft->filename();

    my $corrupt_data_ft = File::Temp->new();
    my $corrupt_data_fn = $corrupt_data_ft->filename();

    my $shutdown_ft = File::Temp->new();
    my $shutdown_fn = $shutdown_ft->filename();

    my $client_pid;
    if ($client_pid = fork()) {
    } else {
        my $client =
            APNIC::RPKI::RTR::Client->new(
                server         => '127.0.0.1',
                port           => $port,
                state_path     => $state_path,
                retry_interval => 10
            );
        $client->{'pdu_cb'} = sub {
            my ($pdu) = @_;
            if (($pdu->type() == PDU_ERROR_REPORT())
                    and ($pdu->error_code() == ERR_CACHE_SHUTDOWN())) {
                write_file($shutdown_fn, "yes");
            }
        };
        for (;;) {
            eval { $client->reset(undef, 1); };
            if (my $error = $@) {
                warn "client reset error: $error";
                my $error_pdu = $client->{'error_pdu'};
                if (not $error_pdu) {
                    die "expected error PDU to be set on client";
                }
                if ($error_pdu->error_code() == ERR_CORRUPT_DATA()) {
                    # This will happen when the server restarts, so
                    # just try again in this case.
                    write_file($corrupt_data_fn, "yes");
                    next;
                } else {
                    die $error;
                }
            }
        }
        exit(0);
    }
    sleep(1);

    my $rtrd_pid = pop(@{$pids});
    my $count = kill("TERM", $rtrd_pid);
    if ($count != 1) {
        die "unable to shut down openrtrd";
    }
    warn "Sleeping for 2s to allow openrtrd to shut down...";
    sleep(2);
    if (kill(0, $rtrd_pid)) {
        die "openrtrd process has not shut down";
    }
    stop_server($pids);

    # Have to manually restart it, since the signal is just about
    # the PDU that gets sent to the client.

    $pids = start_server();
    write_state($state);
    sleep(1);

    warn "Sleeping for 15s to allow client import to continue...";
    sleep(15);

    my $state_data = read_file($state_path);
    $state_data = decode_json($state_data);
    $state_data = decode_json($state_data->{'state'});
    my $has_vrp =
        (exists $state_data->{'vrps'}
                        ->{'4608'}->{'3::'}->{'16'});
    my ($cd_line) = read_file($corrupt_data_fn);
    chomp $cd_line;
    my $has_cd = ($cd_line eq "yes");
    my ($pdu_line) = read_file($shutdown_fn);
    chomp $pdu_line;
    my $has_pdu = ($pdu_line eq "yes");

    if ($has_vrp) {
        print "$preamble,cache_shutdown_repopulated,success\n";
    } else {
        print "$preamble,cache_shutdown_repopulated,failure\n";
    }
    if ($has_pdu) {
        print "$preamble,cache_shutdown_pdu_received,success\n";
    } else {
        print "$preamble,cache_shutdown_pdu_received,failure\n";
    }
    # Cache reset (vs. corrupt data) again.
    if ($has_cd) {
        print "$preamble,cache_shutdown_correct_error,success\n";
    } else {
        print "$preamble,cache_shutdown_correct_error,failure\n";
    }

    stop_server($pids);
}

# Hardcoded, for now at least.
{
    print "$preamble,ssh,failure\n";
    print "$preamble,tls,failure\n";
    print "$preamble,tcp-md5,failure\n";
    print "$preamble,tcp-ao,failure\n";
}

1;
