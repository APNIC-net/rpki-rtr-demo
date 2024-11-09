package APNIC::RPKI::RTR::Server;

use warnings;
use strict;

use IO::Select;
use IO::Socket qw(AF_INET SOCK_STREAM SHUT_WR);
use File::Slurp qw(read_file);
use JSON::XS qw(decode_json);
use List::Util qw(max);

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::State;
use APNIC::RPKI::RTR::Utils qw(dprint
                               validate_intervals);
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

    my $strict_send = $args{'strict_send'};
    if ($strict_send) {
        my $msg = validate_intervals($refresh_interval,
                                     $retry_interval,
                                     $expire_interval);
        if ($msg) {
            die $msg;
        }
    }

    # Only overridable for tests.
    my $serial_notify_period = $args{'serial_notify_period'} || 60;

    my $session_id = int(rand(65535));

    my @svs = @{$args{'supported_versions'} || [0, 1, 2]};
    for my $sv (@svs) {
        if (not ($sv >= 0 and $sv <= 2)) {
            die "Version '$sv' is not supported.";
        }
    }

    my $self = {
        server                => $server,
        port                  => $port,
        data_dir              => $data_dir,
        refresh_interval      => $refresh_interval,
        retry_interval        => $retry_interval,
        expire_interval       => $expire_interval,
        strict_send           => $args{'strict_send'},
        strict_receive        => $args{'strict_receive'},
        no_session_id_check   => $args{'no_session_id_check'},
        no_ss_exists_check    => $args{'no_ss_exists_check'},
        session_id            => $session_id,
        supported_versions    => \@svs,
        sv_lookup             => { map { $_ => 1 } @svs },
        max_supported_version => (max @svs),
        serial_notify_period  => $serial_notify_period,
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
    my $server_socket =
        IO::Socket->new(
            Domain    => AF_INET,
            Type      => SOCK_STREAM,
            proto     => 'tcp',
            LocalHost => $self->{'server'},
            LocalPort => $port,
            ReusePort => 1,
            Listen    => 1,
        );
    if (not $server_socket) {
        die "Unable to start server socket: $!";
    }
    dprint("server: started on $server:$port");
    my $data_dir = $self->{'data_dir'};

    my $select = IO::Select->new($server_socket);
    my $last_update = (stat("$data_dir/snapshot.json"))[7] || 0;
    $self->{'versions'} = {};
    $self->{'select'}   = $select;
    my $last_serial_notify = 0;
    my $serial_notify_period = $self->{'serial_notify_period'};

    for (;;) {
        dprint("server: pending reads");
        my @ready = $select->can_read(1);
        dprint("server: got reads: ".(scalar @ready));
        my %skip_update_check;
        for my $socket (@ready) {
            if ($socket == $server_socket) {
                my $new_socket = $socket->accept();
                my $pp = $new_socket->peerport();
                $select->add($new_socket);
                dprint("server: adding new client to pool: $pp");
                $skip_update_check{$pp} = 1;
            } else {
                my $pp = $socket->peerport() || "(N/A)";
                dprint("server: handling client connection ".
                       "for $pp");
                my $res =
                    $self->handle_client_connection($socket, $data_dir);
                if (not $res) {
                    dprint("server: request for $pp failed, closing");
                    $self->flush($socket);
                } else {
                    dprint("server: request for $pp succeeded");
                }
            }
        }
        my $new_last_update = (stat("$data_dir/snapshot.json"))[7] || 0;
        if ($new_last_update > $last_update) {
            my $now = time();
            if (($last_serial_notify + $serial_notify_period) > $now) {
                dprint("server: state has been updated, but rate ".
                       "limit has been reached, so cannot send ".
                       "serial notify");
                next;
            }
            $last_update = $new_last_update;
            $last_serial_notify = $now;
            dprint("server: state has been updated, send serial notify to clients");
            my $ss_path = "$data_dir/snapshot.json";
            my $data = read_file($ss_path);
            my $state =
                APNIC::RPKI::RTR::State->deserialise_json($data);
            $state->{'session_id'} = $self->{'session_id'};
            my $serial_number = $state->serial_number();
            for my $socket ($select->can_write(0)) {
                my $pp = $socket->peerport();
                if (not defined $pp) {
                    dprint("server: socket no longer available");
                    $self->flush($socket);
                    next;
                }
                if ($skip_update_check{$pp}) {
                    next;
                }
                dprint("server: sending serial notify to $pp ".
                       "($serial_number)");
                my $version = $self->{'versions'}->{$pp} || 0;
                my $pdu =
                    APNIC::RPKI::RTR::PDU::SerialNotify->new(
                        version       => $version,
                        session_id    => $self->{'session_id'},
                        serial_number => $serial_number,
                    );
                $socket->send($pdu->serialise_binary());
            }
        }
    }

    return 1;
}

sub flush
{
    my ($self, $client) = @_;

    my $peerport = $client->peerport();
    if (defined $peerport) {
        delete $self->{'versions'}->{$peerport};
    }

    $self->{'select'}->remove($client);
    $client->shutdown(SHUT_WR);
    $client->close();

    return 1;
}

sub handle_client_connection
{
    my ($self, $client, $data_dir) = @_;

    my $version = $self->{'max_supported_version'};
    my $versions = $self->{'versions'};
    my $res = 1;
    eval {
        my $peerhost = $client->peerhost();
        my $peerport = $client->peerport();
        my $client_address = $peerhost || '(N/A)';
        my $client_port    = $peerport || '(N/A)';
        dprint("server: connection from $client_address:$client_port");
        my $cv =
            ($peerport)
                ? $versions->{$peerport}
                : undef;

        my $pdu = parse_pdu($client);
        if (not $pdu) {
            dprint("server: socket ($peerport) is closed");
            $self->flush($client);
            # Socket is closed.
            return 0;
        }
        $version = $pdu->version();
        if ((defined $cv) and ($version != $cv)) {
            if ($pdu->type() == PDU_ERROR_REPORT()) {
                $self->flush($client);
                dprint("server: got error report PDU with unexpected version");
                $res = 0;
                goto FINISHED;
            }
            my $err_pdu =
                APNIC::RPKI::RTR::PDU::ErrorReport->new(
                    version          => $cv,
                    error_code       => ERR_UNEXPECTED_PROTOCOL_VERSION(),
                    encapsulated_pdu => $pdu,
                );
            $client->send($err_pdu->serialise_binary());
            $self->flush($client);
            dprint("server: got PDU with unexpected version");
            $res = 0;
            goto FINISHED;
        }
        if (not $self->{'sv_lookup'}->{$version}) {
            dprint("server: unsupported version '$version'");
            my $err_pdu =
                APNIC::RPKI::RTR::PDU::ErrorReport->new(
                    version          => $self->{'max_supported_version'},
                    error_code       => ERR_UNSUPPORTED_VERSION(),
                    encapsulated_pdu => $pdu,
                );
            $client->send($err_pdu->serialise_binary());
            $res = 0;
            goto FINISHED;
        }
        if (defined $client->peerport()) {
            $versions->{$client->peerport()} = $version;
        }
        my $type = $pdu->type();
        if ($type == PDU_RESET_QUERY()) {
            dprint("server: got reset query");
            my $ss_path = "$data_dir/snapshot.json";
            my $has_snapshot = -e $ss_path;
            if (not $self->{'no_ss_exists_check'} and not $has_snapshot) {
                dprint("server: no snapshot");
                my $err_pdu =
                    APNIC::RPKI::RTR::PDU::ErrorReport->new(
                        version          => $version,
                        error_code       => ERR_NO_DATA(),
                        encapsulated_pdu => $pdu,
                    );
                $client->send($err_pdu->serialise_binary());
                $res = 0;
                goto FINISHED;
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
                $state->{'session_id'} = $self->session_id();

                for my $pdu ($state->pdus()) {
                    if ($pdu->supported_in_version($version)) {
                        # For testing.
                        if ($ENV{'APNIC_RESET_ANNOUNCE_ZERO'}) {
                            $pdu->{'flags'} = 0;
                        }
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
                        session_id       => $self->session_id(),
                        serial_number    => $state->serial_number(),
                        refresh_interval => $self->{'refresh_interval'},
                        retry_interval   => $self->{'retry_interval'},
                        expire_interval  => $self->{'expire_interval'},
                    );
                dprint("server: sending end of data PDU: ".$eod_pdu->serialise_json());
                $client->send($eod_pdu->serialise_binary());
            }
        } elsif ($type == PDU_SERIAL_QUERY()) {
            dprint("server: got serial query");
            if (not $self->{'no_session_id_check'}) {
                if ($pdu->session_id() ne $self->session_id()) {
                    my $err_pdu =
                        APNIC::RPKI::RTR::PDU::ErrorReport->new(
                            version          => $version,
                            error_code       => ERR_CORRUPT_DATA(),
                            encapsulated_pdu => $pdu,
                        );
                    $client->send($err_pdu->serialise_binary());
                    $self->flush($client);
                    $res = 0;
                    goto FINISHED;
                }
            }

            my $ss_path = "$data_dir/snapshot.json";
            my $has_snapshot = -e $ss_path;
            if (not $self->{'no_ss_exists_check'} and not $has_snapshot) {
                dprint("server: no snapshot");
                my $err_pdu =
                    APNIC::RPKI::RTR::PDU::ErrorReport->new(
                        version          => $version,
                        error_code       => ERR_NO_DATA(),
                        encapsulated_pdu => $pdu,
                    );
                $client->send($err_pdu->serialise_binary());
                $res = 0;
                goto FINISHED;
            } else {
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
                if (not -e "$data_dir/changeset_$last_serial_number.json") {
                    # Assuming that the absence of this changeset
                    # means that truncation has occurred such that the
                    # client can't be sure they'll get the right data.
                    # (Strictly speaking, the absence of this
                    # changeset might not be an issue, but checking
                    # for the absence of the next changeset doesn't
                    # work, so this is the next-best option.)
                    my $cr_pdu =
                        APNIC::RPKI::RTR::PDU::CacheReset->new(
                            version => $version,
                        );
                    my $sb = $cr_pdu->serialise_binary();
                    dprint("server: sending cache reset: ".$cr_pdu->serialise_json());
                    $client->send($sb);
                    goto FINISHED;
                }
                my @changeset_paths;
                for (my $i = $last_serial_number + 1;; $i++) {
                    my $changeset_path = "$data_dir/changeset_$i.json";
                    if (-e $changeset_path) {
                        push @changeset_paths, $changeset_path;
                        if ($i == 4294967295) {
                            $i = 0;
                        }
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
                        session_id       => $self->session_id(),
                        serial_number    => $serial_number,
                        refresh_interval => $self->{'refresh_interval'},
                        retry_interval   => $self->{'retry_interval'},
                        expire_interval  => $self->{'expire_interval'},
                    );
                dprint("server: sending end of data PDU: ".$eod_pdu->serialise_json());
                $client->send($eod_pdu->serialise_binary());
            }
        } elsif ($pdu->type() == PDU_EXIT()) {
            dprint("server: client triggered exit");
            exit(0);
        } elsif ($pdu->type() == PDU_ERROR_REPORT()) {
            dprint("server: got error report from client: ".$pdu->serialise_json());
            $res = 0;
            goto FINISHED;
        } else {
            my $err_pdu =
                APNIC::RPKI::RTR::PDU::ErrorReport->new(
                    version          => $version,
                    error_code       => ERR_INVALID_REQUEST(),
                    encapsulated_pdu => $pdu,
                );
            $client->send($err_pdu->serialise_binary());
            dprint("server: invalid request from client: ".
                   $pdu->serialise_json());
            $self->flush($client);
            $res = 0;
            goto FINISHED;
        }
    };
    if (my $error = $@) {
        my $err_pdu =
            APNIC::RPKI::RTR::PDU::ErrorReport->new(
                version    => $version,
                error_code => ERR_INTERNAL_ERROR(),
            );
        $client->send($err_pdu->serialise_binary());
        dprint("server: failed to handle request/connection: $error");
        $self->flush($client);
        return 0;
    }

    FINISHED: {
        dprint("server: finished with client request");
    }

    return $res;
}

1;
