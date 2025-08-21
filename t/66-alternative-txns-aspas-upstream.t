#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::Validator::ASPA;

use File::Temp qw(tempdir);

use Test::More tests => 6;

my $pid;

{
    # Set up the server and the client.

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
        $pid = $ppid;
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

    my $validator = sub {
        my ($client, $results) = @_;

        # Using these AS numbers so that they are more visually
        # distinct in the route string, and also so that the default
        # ordering on the server side doesn't indirectly lead to valid
        # results.
        my $res =
            APNIC::RPKI::Validator::ASPA::validate(
                $client->{'state'},
                {},
                "||||44|10.0.0.0/24|44 22 33",
                "1.0.0.0/24"
            );
        push @{$results}, $res;
    };

    # This client commits all PDUs as a unit (default behaviour). 

    my $client_eod =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [2],
        );
    my @client_eod_results;
    $client_eod->{'post_commit_cb'} = sub {
        $validator->($client_eod, \@client_eod_results);
    };

    # This client commits each PDU as it is received.

    my $client_asr =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [2],
        );
    my @client_asr_results;
    $client_asr->{'commit_as_received'} = 1;
    $client_asr->{'post_commit_cb'} = sub {
        $validator->($client_asr, \@client_asr_results);
    };

    # This client commits each PDU using the alternative
    # implementation approach described in the document.

    my $client_alt =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [2],
        );
    my @client_alt_results;
    $client_alt->{'commit_aspas'} = 1;
    $client_alt->{'post_commit_cb'} = sub {
        $validator->($client_alt, \@client_alt_results);
    };

    # Add two ASPA PDUs to the server, to test the ASPA batching
    # behaviour (upstream logic).

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my $pdu1 =
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            afi_flags     => 3,
            customer_asn  => 22,
            provider_asns => [33, 44],
        );
    $changeset->add_pdu($pdu1);
    my $pdu2 =
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            afi_flags     => 3,
            customer_asn  => 44,
            provider_asns => [22],
        );
    $changeset->add_pdu($pdu2);
    $mnt->apply_changeset($changeset);

    # Test each client.

    # EOD is unproblematic.

    eval { $client_eod->reset() };
    my $error = $@;
    ok((not $error), 'Got successful response from server (EOD)');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    is_deeply(\@client_eod_results, [1],
              'Got expected validation results');

    # Committing as received leads to three results: unknown (after
    # the 22 ASPA, which indicates a valley, but not sufficiently to
    # lead to invalidity), unknown (after the 33 ASPA, which is not
    # sufficient for validity), and unknown (after the EOD PDU).

    eval { $client_asr->reset() };
    $error = $@;
    ok((not $error), 'Got successful response from server (ASR)');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    is_deeply(\@client_asr_results, [1, 1, 1],
              'Got expected validation results');

    # Committing with the alternative approaches leads to one unknown
    # result, since all of the ASPAs are processed as a single unit.

    eval { $client_alt->reset() };
    $error = $@;
    ok((not $error), 'Got successful response from server (ALT)');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    is_deeply(\@client_alt_results, [1],
              'Got expected validation results');

    $client_eod->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
