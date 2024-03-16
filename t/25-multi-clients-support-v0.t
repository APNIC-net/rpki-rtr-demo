use strict;
use warnings;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);
use Time::HiRes qw(time);

use Test::More tests => 31;

my $server_pid;
{
    # Set up the server and the client.
    # And some initial data.
    my $data_dir = tempdir(CLEANUP => 1);
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
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

    my $port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;
    my $server =
        APNIC::RPKI::RTR::Server->new(
            server   => '127.0.0.1',
            port     => $port,
            data_dir => $data_dir,
        );

    # Start server in a separate fork that gets terminated
    # when the script exit.
    if (my $pid = fork()) {
        $server_pid = $pid;
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

    my $start_time = time;
    my $max_clients = 10;
    my @clients =
        map {
            APNIC::RPKI::RTR::Client->new(
                server             => '127.0.0.1',
                port               => $port,
                supported_versions => [2],
            );
        } (1..$max_clients);

    my @clients_pids;
    for (my $i = 0; $i < $max_clients; $i++) {
        my $client = $clients[$i];

        if (my $pid = fork()) {
            push @clients_pids, $pid;
        } else {
            eval { $client->reset() };
            diag $@ if $@;
            write_file("$data_dir/client_$i.json", $client->serialise_json());
            exit(0);
        }
    }
    for my $pid (@clients_pids) {
        waitpid($pid, 0);
    }

    for (my $i = 0; $i < $max_clients; $i++) {
        my $client = APNIC::RPKI::RTR::Client->deserialise_json(
            read_file("$data_dir/client_$i.json"));
        my @pdus = $client->state()->pdus();

        my $name = "Client $i";
        is(@pdus, 1, "$name: State has single PDU");
        $pdu = $pdus[0];
        is($pdu->type(), 4, "$name: Got IPv4 prefix PDU");
        is($pdu->address(), "1.0.0.0", "$name: Got correct address");
    }

    my $elapsed = time - $start_time;
    ok(($elapsed < 2), "Processing multiple clients in a reasonable time.");

    # Terminate the process that runs the server.
    kill('TERM', $server_pid);
}