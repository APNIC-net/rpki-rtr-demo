#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Client;
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
use List::Util qw(shuffle);
use Net::EmptyPort qw(empty_port);
use Time::HiRes qw(time);
use POSIX ":sys_wait_h";

## rpki-rtr-demo.

my $preamble = "rpki-rtr-demo,main";

goto here;

sub start_server
{
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
        );

    my $pid;
    if ($pid = fork()) {
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

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

# Can connect with version 0.
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

    stop_server($server);
}

# Can connect with version 1.
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

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [1]
        );
    my @pdus;
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
        use Data::Dumper;
        warn Dumper(\@pdus, $client->_current_version());
        print "$preamble,v1_connect,failure\n";
    }

    stop_server($server);
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

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [2]
        );
    my @pdus;
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
        warn $error;
        use Data::Dumper;
        warn Dumper(\@pdus, $client->_current_version());
        print "$preamble,v2_connect,failure\n";
    }

    stop_server($server);
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
        print "$preamble,sends_reset_query,success\n";
        print "$preamble,accepts_cache_response,success\n";
    } else {
        warn $error;
        print "$preamble,sends_reset_query,failure\n";
        print "$preamble,accepts_cache_response,failure\n";
    }
    if ($client->{'eod'}) {
        print "$preamble,accepts_end_of_data,success\n";
    } else {
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
    sleep(2);

    my $state_data = read_file($state_path);
    $state_data = decode_json($state_data);
    $state_data = decode_json($state_data->{'state'});
    if (exists $state_data->{'vrps'}
                          ->{'4608'}->{'2.0.0.0'}->{'24'}) {
        print "$preamble,accepts_serial_notify,success\n";
    } else {
        print "$preamble,accepts_serial_notify,failure\n";
    }

    kill_process($pid);
    stop_server($server);
}

# Handles no-op response.
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
        print "$preamble,handles_cache_response_no_op,success\n";
    } else {
        warn $error;
        print "$preamble,handles_cache_response_no_op,failure\n";
    }

    stop_server($server);
}

# Handles reset on bad session ID.
{
    my $server = start_server(retry_interval => 1);
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

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server => '127.0.0.1',
            port   => $port,
        );
    $client->reset();
    my $state = $client->{'state'};
    my $original_session_id = $state->{'session_id'};
    $state->{'session_id'}++;
    $state->{'session_id'} &= 0xFFFF;

    eval {
        eval { $client->refresh(1); };
        if (my $error = $@) {
            warn $error;
            $client->reset(1);
        }
    };
    my $error = $@;
    $state = $client->{'state'};
    if ((not $error) and ($state->{'session_id'} == $original_session_id)) {
        print "$preamble,handles_reset_on_session_mismatch,success\n";
    } else {
        warn "'$error', '".$state->{'session_id'}."', ".
             "$original_session_id";
        print "$preamble,handles_reset_on_session_mismatch,failure\n";
    }

    stop_server($server);
}

# Handles reset on absence of server history.
{
    my $server = start_server();
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

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server => '127.0.0.1',
            port   => $port,
        );
    $client->reset();

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

    eval {
        $client->refresh(1);
    };
    my $error = $@;
    my $state_data = $client->{'state'};
    if ((not $error)
            and (exists $state_data->{'vrps'}
                            ->{'4608'}
                            ->{'2.0.0.0'})
            and (not exists $state_data->{'vrps'}
                            ->{'4608'}
                            ->{'1.0.0.0'})) {
        print "$preamble,handles_reset_on_absence_of_history,success\n";
    } else {
        warn "$error";
        print "$preamble,handles_reset_on_absence_of_history,failure\n";
    }

    stop_server($server);
}

# Handles no data.
{
    my $server = start_server();
    my ($mnt, $port, $data_dir) =
        @{$server}{qw(mnt port data_dir)};

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server => '127.0.0.1',
            port   => $port,
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
            ski     => '1234',
            spki    => '1234',
            asn     => 4608,
        )
    );
    for my $pdu (@pdus) {
        $changeset->add_pdu($pdu);
    }
    $mnt->apply_changeset($changeset);

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
        print "$preamble,handles_ipv4,success\n";
    } else {
        print "$preamble,handles_ipv4,failure\n";
    }

    if (exists $state_data->{'vrps'}
                        ->{'4608'}->{'1::'}->{'24'}) {
        print "$preamble,handles_ipv6,success\n";
    } else {
        print "$preamble,handles_ipv6,failure\n";
    }

    if (exists $state_data->{'aspas'}->{4608}) {
        print "$preamble,handles_aspa,success\n";
    } else {
        print "$preamble,handles_aspa,failure\n";
    }

    if (exists $state_data->{'rks'}->{4608}) {
        print "$preamble,handles_router_key,success\n";
    } else {
        print "$preamble,handles_router_key,failure\n";
    }

    stop_server($server);
}

{
    # These have tests elsewhere.  (No ordering test here, because
    # it's really more of a server-side issue.)
    print "$preamble,handles_cache_restart,success\n";
    print "$preamble,handles_cache_shutdown,success\n";
    print "$preamble,ssh,success\n";
    print "$preamble,tls,success\n";
    print "$preamble,tcp-md5,success\n";
    print "$preamble,tcp-ao,failure\n";
}

1;
