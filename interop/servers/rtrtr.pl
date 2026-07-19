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

use File::Slurp qw(write_file read_file);
use File::Temp qw(tempdir);
use JSON::XS qw(decode_json encode_json);
use List::Util qw(shuffle);
use Net::EmptyPort qw(empty_port);

## rtrtr.

# Can connect with version 0.
{
    my @pids;

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
            # So that separate serial notify testing works as
            # expected.
            serial_notify_period => 0,
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

    my $rtr_path = $ENV{'RTRTR_PATH'} || 'rtrtr';
    my ($rtrtr_version) = `$rtr_path --version`;
    chomp $rtrtr_version;
    $rtrtr_version =~ s/^rtrtr\s*//;
    my $preamble = "rtrtr,$rtrtr_version";

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
        system("$rtr_path -c $fn");
        exit(0);
    }
    sleep(1);

    @rtrtr_pids = `ps -C rtrtr`;
    shift @rtrtr_pids;
    for my $rtrtr_pid (@rtrtr_pids) {
        $rtrtr_pid =~ s/^\s*//;
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

    $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $rtrtr_rtr_port,
            supported_versions => [1]
        );
    @pdus = ();
    eval {
        $client->reset();
        @pdus = $client->{'state'}->pdus();
    };
    $error = $@;
    if ((@pdus == 1)
            and ($pdus[0]->address() eq '1.0.0.0')
            and ($client->_current_version() == 1)) {
        print "$preamble,v1_connect,success\n";
    } else {
        warn $error;
        print "$preamble,v1_connect,failure\n";
    }

    $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $rtrtr_rtr_port,
            supported_versions => [2]
        );
    @pdus = ();
    eval {
        $client->reset();
        @pdus = $client->{'state'}->pdus();
    };
    $error = $@;
    if ((@pdus == 1)
            and ($pdus[0]->address() eq '1.0.0.0')
            and ($client->_current_version() == 2)) {
        print "$preamble,v2_connect,success\n";
    } else {
        print "$preamble,v2_connect,failure\n";
    }

    $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $rtrtr_rtr_port,
            supported_versions => [0, 1, 2]
        );
    @pdus = ();
    eval {
        $client->reset();
        @pdus = $client->{'state'}->pdus();
    };
    $error = $@;
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

    my $state_path_ft = File::Temp->new();
    my $state_path = $state_path_ft->filename();

    if (my $pid = fork()) {
        push @pids, $pid;
    } else {
	my $client =
	    APNIC::RPKI::RTR::Client->new(
		server     => '127.0.0.1',
		port       => $rtrtr_rtr_port,
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

    my $persistent_pid = pop @pids;
    kill('TERM', $persistent_pid);

    $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $rtrtr_rtr_port,
            supported_versions => [0, 1, 2]
        );
    @pdus = ();
    my $res;
    eval {
        $client->reset();
        $res = $client->refresh(1);
        @pdus = $client->{'state'}->pdus();
    };
    $error = $@;
    if (($res == 1) and (@pdus == 2)) {
        print "$preamble,accepts_serial_query_no_op,success\n";
    } else {
        warn $error;
        print "$preamble,accepts_serial_query_no_op,failure\n";
    }

    $client =
        APNIC::RPKI::RTR::Client->new(
            server     => '127.0.0.1',
            port       => $rtrtr_rtr_port,
            state_path => $state_path,
        );
    $client->reset();
    $client->{'state'}->{'session_id'}++;
    $client->{'state'}->{'session_id'} &= 0xFFFF;

    eval {
        $client->refresh(1);
    };
    $error = $@;
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

    $client =
        APNIC::RPKI::RTR::Client->new(
            server     => '127.0.0.1',
            port       => $rtrtr_rtr_port,
            state_path => $state_path,
        );
    $client->reset();

    # rtrtr retains only 10 history entries, so adding 13 here will
    # mean that the client can't refresh.
    for my $i (3..15) {
        my $changeset = APNIC::RPKI::RTR::Changeset->new();
        my $pdu =
            APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
                version       => 1,
                flags         => 1,
                asn           => 4608,
                address       => "$i.0.0.0",
                prefix_length => 24,
                max_length    => 32
            );
        $changeset->add_pdu($pdu);
        $mnt->apply_changeset($changeset);
        warn "Sleeping for 2s to allow rtrtr to retrieve ".
             "update ($i)...";
        sleep(2);
    }
    sleep(2);
    my $got_reset = 0;
    $client->{'pdu_cb'} = sub {
        my ($pdu) = @_;
        if ($pdu->type() == PDU_CACHE_RESET()) {
            $got_reset = 1;
        }
    };
    eval {
        $client->refresh(1);
    };
    $error = $@;
    if (not $error and $got_reset) {
        print "$preamble,reset_on_absence_of_history,success\n";
    } else {
        warn "$error, '$got_reset'";
        print "$preamble,reset_on_absence_of_history,failure\n";
    }

    # Empty rtrtr server.

    my $data_dir2 = tempdir(CLEANUP => 1);
    my $mnt2 =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port2 = empty_port();
    my $server2 =
        APNIC::RPKI::RTR::Server->new(
            server               => '127.0.0.1',
            port                 => $port2,
            data_dir             => $data_dir2,
            # So that separate serial notify testing works as
            # expected.
            serial_notify_period => 0,
        );

    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        $server2->run();
        exit(0);
    }
    sleep(1); 

    my $rtrtr2_rtr_port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;
    my $rtrtr2_http_port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;

    my $config2 = <<EOF;
#log_level = "debug"
#log_target = "stderr"
#log_facility = "daemon"
http-listen = ["127.0.0.1:$rtrtr2_http_port"]

[units.ufirst]
type = "rtr"
remote = "127.0.0.1:$port2"

[targets.tfirst]
type = "rtr"
listen = [ "127.0.0.1:$rtrtr2_rtr_port" ]
unit = "ufirst"
EOF

    my $ft2 = File::Temp->new();
    my $fn2 = $ft2->filename();
    write_file($fn2, $config2);

    my @rtrtr2_pids = `ps -C rtrtr`;
    shift @rtrtr2_pids;
    my %rtrtr2_pid_lookup;
    for my $rtrtr2_pid (@rtrtr2_pids) {
        $rtrtr2_pid =~ s/\s.*//;
        chomp $rtrtr2_pid;
        $rtrtr2_pid_lookup{$rtrtr2_pid} = 1;
    }
    if (my $pid = fork()) {
        push @pids, $pid;
    } else {
        system("$rtr_path -c $fn2");
        exit(0);
    }
    sleep(1);

    @rtrtr2_pids = `ps -C rtrtr`;
    shift @rtrtr2_pids;
    for my $rtrtr2_pid (@rtrtr2_pids) {
        $rtrtr2_pid =~ s/^\s*//;
        $rtrtr2_pid =~ s/\s.*//;
        chomp $rtrtr2_pid;
        if (not $rtrtr2_pid_lookup{$rtrtr2_pid}) {
            push @pids, $rtrtr2_pid;
        }
    }

    $client =
        APNIC::RPKI::RTR::Client->new(
            server     => '127.0.0.1',
            port       => $rtrtr2_rtr_port,
        );
    eval { 
        $client->reset();
    };
    $error = $@;
    if ($error =~ /Server has no data/) {
        print "$preamble,no_data_returned_correctly,success\n";
    } else {
        warn $error;
        print "$preamble,no_data_returned_correctly,failure\n";
    }

    # Multiple PDU types.
    {
        my $changeset = APNIC::RPKI::RTR::Changeset->new();

        my $pdu1 =
            APNIC::RPKI::RTR::PDU::IPv6Prefix->new(
                version       => 1,
                flags         => 1,
                asn           => 4608,
                address       => '1::',
                prefix_length => 24,
                max_length    => 32
            );
        $changeset->add_pdu($pdu1);

        my $pdu2 =
            APNIC::RPKI::RTR::PDU::ASPA->new(
		version       => 2,
		flags         => 1,
		afi_flags     => 3,
		customer_asn  => 4608,
		provider_asns => [1, 2, 3, 4],
            );
        $changeset->add_pdu($pdu2);

        my $pdu3 =
            APNIC::RPKI::RTR::PDU::RouterKey->new(
		version => 1,
		flags   => 1,
		ski     => '1234',
		spki    => '1234',
		asn     => 4608,
            );
        $changeset->add_pdu($pdu3);

        $mnt->apply_changeset($changeset);
        sleep(2);

        my $client =
            APNIC::RPKI::RTR::Client->new(
                server => '127.0.0.1',
                port   => $rtrtr_rtr_port,
            );
        eval { 
            $client->reset();
        };
        $error = $@;
        $state_data = $client->{'state'};
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

        if (exists $state_data->{'rks'}->{4608}) {
            print "$preamble,sends_router_key,success\n";
        } else {
            print "$preamble,sends_router_key,failure\n";
        }
    }

    # Ordering.
    {
        my $changeset = APNIC::RPKI::RTR::Changeset->new();

        my @pdus = (
            APNIC::RPKI::RTR::PDU::IPv6Prefix->new(
                version       => 1,
                flags         => 1,
                asn           => 4608,
                address       => '3::',
                prefix_length => 24,
                max_length    => 32
            ),
            APNIC::RPKI::RTR::PDU::IPv6Prefix->new(
                version       => 1,
                flags         => 1,
                asn           => 4608,
                address       => '3::',
                prefix_length => 16,
                max_length    => 28
            ),
            APNIC::RPKI::RTR::PDU::IPv6Prefix->new(
                version       => 1,
                flags         => 1,
                asn           => 4609,
                address       => '3::',
                prefix_length => 24,
                max_length    => 32
            ),
            APNIC::RPKI::RTR::PDU::ASPA->new(
		version       => 2,
		flags         => 1,
		afi_flags     => 3,
		customer_asn  => 4609,
		provider_asns => [1, 2, 3, 4],
            )
        );
        for (;;) {
            my @shuffled_pdus = shuffle(@pdus);
            my @ordered_pdus = order_pdus(@pdus);
            if (encode_json([ map { $_->serialise_json() } @shuffled_pdus ])
                    ne encode_json([ map { $_->serialise_json() } @ordered_pdus ])) {
                for my $pdu (@shuffled_pdus) {
                    $changeset->add_pdu($pdu);
                }
                $mnt->apply_changeset($changeset);
                sleep(2);
                last;
            }
        }

        my $client =
            APNIC::RPKI::RTR::Client->new(
                server         => '127.0.0.1',
                port           => $rtrtr_rtr_port,
                strict_receive => 1,
            );
        eval { 
            $client->reset();
        };
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
    }

    # Hardcoded, for now at least.
    print "$preamble,cache_restart_repopulated,failure\n";
    print "$preamble,cache_restart_correct_error,failure\n";
    print "$preamble,cache_shutdown_repopulated,failure\n";
    print "$preamble,cache_shutdown_correct_error,failure\n";
    print "$preamble,ssh,failure\n";
    print "$preamble,tls,failure,server certificate verification only\n";
    print "$preamble,tcp-md5,failure\n";
    print "$preamble,tcp-ao,failure\n";

    for my $pid (@pids) {
        kill('TERM', $pid);
    }
}

1;
