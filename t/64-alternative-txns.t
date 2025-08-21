#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::Validator::ROA;

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

        my $res =
            APNIC::RPKI::Validator::ROA::validate(
                $client->{'state'},
                "4609",
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
    $client_alt->{'commit_same_prefixes'} = 1;
    $client_alt->{'post_commit_cb'} = sub {
        $validator->($client_alt, \@client_alt_results);
    };

    # Add three IPv4 PDUs to the server, to test the same-prefix
    # behaviour.

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my $pdu1 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4610,
            address       => '1.0.0.0',
            prefix_length => 24,
            max_length    => 24,
        );
    $changeset->add_pdu($pdu1);
    my $pdu2 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4609,
            address       => '1.0.0.0',
            prefix_length => 24,
            max_length    => 24,
        );
    $changeset->add_pdu($pdu2);
    my $pdu3 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4609,
            address       => '2.0.0.0',
            prefix_length => 24,
            max_length    => 24,
        );
    $changeset->add_pdu($pdu3);
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

    is_deeply(\@client_eod_results, [2],
              'Got expected validation results');

    # Committing as received leads to four results: unknown (after the
    # 2.0.0.0/24 PDU), invalid (after the 4610 PDU), valid (after the
    # 4609 PDU), and valid (after the EOD PDU).

    eval { $client_asr->reset() };
    $error = $@;
    ok((not $error), 'Got successful response from server (ASR)');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    is_deeply(\@client_asr_results, [1, 0, 2, 2],
              'Got expected validation results');

    # Committing with the alternative approaches leads to three
    # results: unknown (after the 2.0.0.0/24 PDU), and valid (after
    # the two 1.0.0.0/24 PDUs and EOD PDU, which are processed as a
    # single unit).

    eval { $client_alt->reset() };
    $error = $@;
    ok((not $error), 'Got successful response from server (ALT)');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    is_deeply(\@client_alt_results, [1, 2],
              'Got expected validation results');

    $client_eod->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
