package APNIC::RPKI::RTR::Server;

use warnings;
use strict;

use IO::Socket qw(AF_INET SOCK_STREAM SHUT_WR);
use File::Slurp qw(read_file);
use JSON::XS qw(decode_json);

use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::State;
use APNIC::RPKI::RTR::Utils qw(dprint);
use APNIC::RPKI::RTR::PDU::Utils qw(parse_pdu);

sub new
{
    my $class = shift;
    my %args = @_;

    my $server = $args{'server'} || '127.0.0.1';
    if (not $server) {
        die "No server provided.";
    }

    my $port = $args{'port'};
    if (not $port) {
        die "No port provided.";
    }

    my $data_dir = $args{'data_dir'};
    if (not $data_dir) {
        die "No data directory provided.";
    }

    my $refresh_interval = $args{'refresh_interval'} || 3600;
    my $retry_interval   = $args{'retry_interval'}   || 600;
    my $expire_interval  = $args{'expire_interval'}  || 7200;

    my $session_id = int(rand(65535));

    my $self = {
        server           => $server,
        port             => $port,
        data_dir         => $data_dir,
        refresh_interval => $refresh_interval,
        retry_interval   => $retry_interval,
        expire_interval  => $expire_interval,
        strict_send      => $args{'strict_send'},
        strict_receive   => $args{'strict_receive'},
        session_id       => $session_id,
    };

    bless $self, $class;
    return $self;
}

sub session_id
{
    my ($self) = @_;

    return $self->{'session_id'};
}

sub run
{
    my ($self) = @_;

    dprint("server: starting server");
    my $server = $self->{'server'};
    my $port = $self->{'port'};
    my $socket =
        IO::Socket->new(
            Domain    => AF_INET,
            Type      => SOCK_STREAM,
            proto     => 'tcp',
            LocalHost => $self->{'server'},
            LocalPort => $port,
            ReusePort => 1,
            Listen    => 1,
        );
    if (not $socket) {
        die "Unable to start server socket: $!";
    }
    dprint("server: started on $server:$port");
    my $data_dir = $self->{'data_dir'};

    for (;;) {
        dprint("server: waiting for client connection");
	my $client = $socket->accept();
        dprint("server: got client connection");

        eval {
            my $client_address = $client->peerhost();
            my $client_port = $client->peerport();
            dprint("server: connection from $client_address:$client_port");

            my $pdu = parse_pdu($client);
            my $version = $pdu->version();
            if (not (($version == 1) or ($version == 2))) {
                dprint("server: unsupported version '$version'");
                my $err_pdu =
                    APNIC::RPKI::RTR::PDU::ErrorReport->new(
                        version    => 2,
                        error_code => 4,
                    );
                $client->send($err_pdu->serialise_binary());
                goto FINISHED;
            }
            my $type = $pdu->type();
            if ($type == 2) {
                dprint("server: got reset query");
                my $ss_path = "$data_dir/snapshot.json";
                my $has_snapshot = -e $ss_path;
                if (not $has_snapshot) {
                    dprint("server: no snapshot");
                    my $err_pdu =
                        APNIC::RPKI::RTR::PDU::ErrorReport->new(
                            version    => $version,
                            error_code => 2,
                        );
                    $client->send($err_pdu->serialise_binary());
                } else {
                    dprint("server: has snapshot");
                    my $cr_pdu =
                        APNIC::RPKI::RTR::PDU::CacheResponse->new(
                            version    => $version,
                            session_id => $self->session_id(),
                        );
                    my $sb = $cr_pdu->serialise_binary();
                    dprint("server: sending cache response: ".$cr_pdu->serialise_json());
                    $client->send($sb);

                    my $data = read_file($ss_path);
                    my $state =
                        APNIC::RPKI::RTR::State->deserialise_json($data);
                    $state->{'session_id'} = $self->{'session_id'};

                    for my $pdu ($state->pdus()) {
                        if ($pdu->supported_in_version($version)) {
                            $pdu->{'version'} = $version;
                            dprint("server: sending PDU: ".$pdu->serialise_json());
                            $client->send($pdu->serialise_binary());
                        } else {
                            dprint("server: not sending PDU, not supported in client version: ".
                                   $pdu->serialise_json());
                        }
                    }

                    my $eod_pdu =
                        APNIC::RPKI::RTR::PDU::EndOfData->new(
                            version          => $version,
                            session_id       => $self->{'session_id'},
                            serial_number    => $state->serial_number(),
                            refresh_interval => $self->{'refresh_interval'},
                            retry_interval   => $self->{'retry_interval'},
                            expire_interval  => $self->{'expire_interval'},
                        );
                    dprint("server: sending end of data PDU: ".$eod_pdu->serialise_json());
                    $client->send($eod_pdu->serialise_binary());
                }
            } elsif ($type == 1) {
                dprint("server: got serial query");
                my $cr_pdu =
                    APNIC::RPKI::RTR::PDU::CacheResponse->new(
                        version    => $version,
                        session_id => $self->session_id(),
                    );
                my $sb = $cr_pdu->serialise_binary();
                dprint("server: sending cache response: ".$cr_pdu->serialise_json());
                $client->send($sb);

                # Serial query.
                my $last_serial_number = $pdu->serial_number();
                my @changeset_paths;
                for (my $i = $last_serial_number + 1;; $i++) {
                    my $changeset_path = "$data_dir/changeset_$i.json";
                    if (-e $changeset_path) {
                        push @changeset_paths, $changeset_path;
                    } else {
                        last;
                    }
                }
                my @changesets;
                for my $changeset_path (@changeset_paths) {
                    my $data = read_file($changeset_path);
                    my $changeset =
                        APNIC::RPKI::RTR::Changeset->deserialise_json($data);
                    push @changesets, $changeset;
                }
                my $serial_number = $last_serial_number;
                if (@changesets) {
                    my $first_changeset = shift @changesets;
                    for my $changeset (@changesets) {
                        $first_changeset->apply_changeset($changeset);
                    }
                    $serial_number =
                        $first_changeset->{'last_serial_number'};
                    for my $pdu ($first_changeset->pdus()) {
                        if ($pdu->supported_in_version($version)) {
                            $pdu->{'version'} = $version;
                            dprint("server: sending PDU: ".$pdu->serialise_json());
                            $client->send($pdu->serialise_binary());
                        } else {
                            dprint("server: not sending PDU, not supported in client version: ".
                                   $pdu->serialise_json());
                        }
                    }
                }

                my $eod_pdu =
                    APNIC::RPKI::RTR::PDU::EndOfData->new(
                        version          => $version,
                        session_id       => $self->{'session_id'},
                        serial_number    => $serial_number,
                        refresh_interval => $self->{'refresh_interval'},
                        retry_interval   => $self->{'retry_interval'},
                        expire_interval  => $self->{'expire_interval'},
                    );
                dprint("server: sending end of data PDU: ".$eod_pdu->serialise_json());
                $client->send($eod_pdu->serialise_binary());
            }
        };
        if (my $error = $@) {
            warn("server: failed to handle request/connection: $error");
        }
        FINISHED: {
            dprint("server: finished with client");
            $client->shutdown(SHUT_WR);
            $client->close();
        }
    }

    $socket->close();

    return 1;
}

1;
