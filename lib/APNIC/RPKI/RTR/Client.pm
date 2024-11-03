package APNIC::RPKI::RTR::Client;

use warnings;
use strict;

use File::Slurp qw(write_file);
use IO::Select;
use IO::Socket qw(AF_INET SOCK_STREAM TCP_NODELAY IPPROTO_TCP);
use JSON::XS qw(encode_json decode_json);
use List::Util qw(max);
use Math::BigInt;
use Net::IP::XS qw(ip_inttobin ip_bintoip ip_compress_address);

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::State;
use APNIC::RPKI::RTR::PDU::Utils qw(parse_pdu
                                    error_type_to_string);
use APNIC::RPKI::RTR::PDU::ResetQuery;
use APNIC::RPKI::RTR::Utils qw(inet_ntop dprint);

our $VERSION = "0.1";

sub new
{
    my $class = shift;
    my %args = @_;

    my $server = $args{'server'};
    if (not $server) {
        die "A server must be provided.";
    }
    my @svs = @{$args{'supported_versions'} || [1, 2]};
    for my $sv (@svs) {
        if (not (($sv >= 0) and ($sv <= 2))) {
            die "Version '$sv' is not supported.";
        }
    }

    my $port = $args{'port'} || 323;

    my $self = {
        supported_versions    => \@svs,
        sv_lookup             => { map { $_ => 1 } @svs },
        max_supported_version => (max @svs),
        server                => $server,
        port                  => $port,
        debug                 => $args{'debug'},
        strict_send           => $args{'strict_send'},
        strict_receive        => $args{'strict_receive'},
        state_path            => $args{'state_path'}, 
    };
    bless $self, $class;
    return $self;
}

sub _init_socket
{
    my ($self) = @_;

    dprint("client: initialising socket");
    $self->_close_socket();

    my ($server, $port) = @{$self}{qw(server port)};
    my $socket = IO::Socket->new(
        Domain   => AF_INET,
        Type     => SOCK_STREAM,
        proto    => 'tcp',
        PeerHost => $server,
        PeerPort => $port,
    );
    if (not $socket) {
        die "Unable to create socket ($server:$port): $!";
    }
    $socket->setsockopt(IPPROTO_TCP, TCP_NODELAY, 1);

    if (not $socket) {
        die "Unable to connect to '$server:$port': $!";
    }

    $self->{'socket'} = $socket;

    return 1;
}

sub _init_socket_if_not_exists
{
    my ($self) = @_;

    if (not $self->{'socket'}) {
        $self->_init_socket();
    }

    return 1;
}

sub _close_socket
{
    my ($self) = @_;

    my $socket = $self->{'socket'};
    if ($socket) {
        dprint("client: closing existing socket");
        $socket->close();
    } else {
        dprint("client: no existing socket to close");
    }
    delete $self->{'socket'};

    return 1;
}

sub _send_reset_query
{
    my ($self, $version) = @_;

    dprint("client: sending reset query");
    my $socket = $self->{'socket'};
    my $reset_query =
        APNIC::RPKI::RTR::PDU::ResetQuery->new(
            version =>
                ((defined $version)
                    ? $version
                    : $self->{'max_supported_version'})
        );
    my $data = $reset_query->serialise_binary();
    my $res = $socket->send($data);
    if ($res != length($data)) {
        die "Got unexpected send result for reset query: '$res' ($!)";
    }
    dprint("client: sent reset query");

    return $res;
}

sub _send_serial_query
{
    my ($self) = @_;

    dprint("client: sending serial query");
    my $socket = $self->{'socket'};
    my $state = $self->{'state'};
    dprint("client: session ID is '".$state->session_id()."'");
    dprint("client: serial number is '".$state->{'serial_number'}."'");
    my $serial_query =
        APNIC::RPKI::RTR::PDU::SerialQuery->new(
            version       => $self->{'current_version'},
            session_id    => $state->session_id(),
            serial_number => $state->{'serial_number'},
        );
    my $data = $serial_query->serialise_binary();
    my $res = $socket->send($data);
    if ($res != length($data)) {
        die "Got unexpected send result for serial query: '$res' ($!)";
    }
    dprint("client: sent serial query");

    return $res;
}

sub _receive_cache_response
{
    my ($self) = @_;

    dprint("client: receiving cache response");
    my $socket = $self->{'socket'};
    my $pdu = parse_pdu($socket);

    my $type = $pdu->type();
    dprint("client: received PDU: ".$pdu->serialise_json());
    if ($type == PDU_CACHE_RESPONSE()) {
        dprint("client: received cache response PDU");
        my $state = $self->{'state'};
        if ($state and ($pdu->session_id() != $state->{'session_id'})) {
            my $err_pdu =
                APNIC::RPKI::RTR::PDU::ErrorReport->new(
                    version    => $self->{'current_version'},
                    error_code => ERR_CORRUPT_DATA(),
                );
            $socket->send($err_pdu->serialise_binary());
            die "client: got PDU with unexpected session";
        }
        delete $self->{'last_failure'};
        return $pdu;
    } elsif ($type == PDU_ERROR_REPORT()) {
        dprint("client: received error response PDU");
        $self->{'last_failure'} = time();
        $self->_close_socket();
        if ($pdu->error_code() == ERR_NO_DATA()) {
            die "Server has no data";
        } elsif ($pdu->error_code() == ERR_UNSUPPORTED_VERSION()) {
            my $max_version = $pdu->version();
            die "Server does not support client version ".
                "(maximum supported version is '$max_version')";
        } else {
            die "Got error response: ".$pdu->serialise_json();
        }
    } elsif ($type == PDU_SERIAL_NOTIFY()) {
        dprint("client: received serial notify, ignore");
        return $self->_receive_cache_response();
    } else {
        dprint("client: received unexpected PDU");
        $self->{'last_failure'} = time();
        die "Got unexpected PDU: ".$pdu->serialise_json();
    }
}

sub _process_responses
{
    my ($self) = @_;

    dprint("client: processing responses");

    my $socket  = $self->{'socket'};
    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my $serial_notify = 0;

    for (;;) {
        dprint("client: processing response");
        my $pdu = parse_pdu($socket);
        dprint("client: processing response: got PDU: ".$pdu->serialise_json());
        if ($pdu->version() != $self->{'current_version'}) {
            if ($pdu->type() == PDU_ERROR_REPORT()) {
                die "client: got error PDU with unexpected version";
            }
            my $err_pdu =
                APNIC::RPKI::RTR::PDU::ErrorReport->new(
                    version    => $self->{'current_version'},
                    error_code => ERR_UNEXPECTED_PROTOCOL_VERSION(),
                );
            $socket->send($err_pdu->serialise_binary());
            die "client: got PDU with unexpected version";
        }
        if ($changeset->can_add_pdu($pdu)) {
            $changeset->add_pdu($pdu);
        } elsif ($pdu->type() == PDU_END_OF_DATA()) {
            return (1, $changeset, $pdu);
        } elsif ($pdu->type() == PDU_ERROR_REPORT()) {
            return (0, $changeset, $pdu);
        } elsif ($pdu->type() == PDU_SERIAL_NOTIFY()) {
            $serial_notify = 1;
        } elsif ($pdu->type() == PDU_CACHE_RESET()) {
            dprint("client: got cache reset PDU");
            return (0, $changeset, $pdu);
        } else {
            my $err_pdu =
                APNIC::RPKI::RTR::PDU::ErrorReport->new(
                    version    => $self->{'current_version'},
                    error_code => ERR_UNSUPPORTED_PDU_TYPE(),
                );
            $socket->send($err_pdu->serialise_binary());
            die "client: got PDU of unexpected type";
        }
    }

    return 0;
}

sub reset
{
    my ($self, $force, $persist) = @_;

    if (not $force) {
        my $last_failure = $self->{'last_failure'};
        if ($last_failure) {
            my $eod = $self->{'eod'};
            if ($eod and ($self->{'current_version'} > 0)) {
                my $retry_interval = $eod->refresh_interval();
                my $min_retry_time = $last_failure + $retry_interval;
                if (time() < $min_retry_time) {
                    dprint("client: not retrying, retry interval not reached");
                    if ($persist) {
                        my $sleep = $min_retry_time - time();
                        dprint("client: sleeping for ${sleep}s before retrying");
                        sleep($sleep);
                        return $self->reset($force, $persist);
                    }
                }
            }
        }
    }

    $self->_init_socket_if_not_exists();
    $self->_send_reset_query();
    my $pdu = eval { $self->_receive_cache_response(); };
    if (my $error = $@) {
        delete $self->{'socket'};
        if ($error =~ /maximum supported version is '(\d+)'/) {
            my $version = $1;
            if ($self->{'sv_lookup'}->{$version}) {
                $self->_init_socket_if_not_exists();
                $self->_send_reset_query($version);
                # No point trying to catch the error here.
                $pdu = $self->_receive_cache_response();
            } else {
                die "Unsupported server version '$version'";
            }
        } else {
            die $error;
        }
    }
    my $version = $pdu->version();
    $self->{'current_version'} = $version;

    my $state =
        APNIC::RPKI::RTR::State->new(
            session_id => $pdu->session_id(),
        );
    $self->{'state'} = $state;

    my ($res, $changeset, $other_pdu) = $self->_process_responses();
    if (not $res) {
        if ($other_pdu) {
            warn $other_pdu->serialise_json(),"\n";
        }
        die "Failed to process cache responses";
    } else {
        my $error_pdu = $state->apply_changeset($changeset, $version);
        if ($error_pdu and ref $error_pdu) {
            my $socket = $self->{'socket'};
            $socket->send($error_pdu->serialise_binary());
            die "client: got error: ".
                error_type_to_string($error_pdu->error_code());
        }
        $self->{'eod'} = $other_pdu;
        $self->{'last_run'} = time();
        $state->{'serial_number'} = $other_pdu->serial_number();
    }

    if ($persist) {
        if (my $sp = $self->{'state_path'}) {
            my $data = $self->serialise_json();
            write_file($sp, $data);
        }
        return $self->refresh(0, $persist);
    } else {
        $self->_close_socket();
    }

    return 1;
}

sub refresh
{
    my ($self, $force, $persist, $version_override, $success_cb) = @_;

    if (not $force) {
        my $last_failure = $self->{'last_failure'};
        my $eod = $self->{'eod'};
        if ($last_failure and $eod and ($self->{'current_version'} > 0)) {
            my $retry_interval = $eod->refresh_interval();
            my $min_retry_time = $last_failure + $retry_interval;
            if (time() < $min_retry_time) {
                dprint("client: not retrying, retry interval not reached");
                if ($persist) {
                    my $current_time = time();
                    my $sleep = $min_retry_time - $current_time;
                    if (not $self->{'socket'}) {
                        # Force refresh in order to get a socket.
                        return $self->refresh(1, $persist,
                                              $version_override,
                                              $success_cb);
                    }
                    my $socket = $self->{'socket'};
                    dprint("client: blocking for ${sleep}s before refresh");
                    my $select = IO::Select->new();
                    $select->add($socket);
                    my ($ready) = $select->can_read($sleep);
                    my $wake_time = time();
                    my $diff_time = $wake_time - $current_time;
                    dprint("client: blocked for ${diff_time}s ".
                           "before server readable");
                    $select->remove($socket);
                    if ($ready) {
                        my $pdu = parse_pdu($socket);
                        if ($pdu->type() != PDU_SERIAL_NOTIFY()) {
                            die "Expected serial notify PDU";
                        }
                        return $self->refresh(1, $persist,
                                              $version_override,
                                              $success_cb);
                    }
                }
                return;
            }
        }
        if ($eod and ($self->{'current_version'} > 0)) {
            my $last_run = $self->{'last_run'};
            my $refresh_interval = $eod->refresh_interval();
            my $min_refresh_time = $last_run + $refresh_interval;
            if (time() < $min_refresh_time) {
                dprint("client: not refreshing, refresh interval not reached");
                if ($persist) {
                    my $current_time = time();
                    my $sleep = $min_refresh_time - $current_time;
                    if (not $self->{'socket'}) {
                        # Force refresh in order to get a socket.
                        return $self->refresh(1, $persist,
                                              $version_override,
                                              $success_cb);
                    }
                    my $socket = $self->{'socket'};
                    dprint("client: blocking for ${sleep}s before refresh");
                    my $select = IO::Select->new();
                    $select->add($socket);
                    my ($ready) = $select->can_read($sleep);
                    my $wake_time = time();
                    my $diff_time = $wake_time - $current_time;
                    dprint("client: blocked for ${diff_time}s ".
                           "before server readable");
                    $select->remove($socket);
                    if ($ready) {
                        my $pdu = parse_pdu($socket);
                        if ($pdu->type() != PDU_SERIAL_NOTIFY()) {
                            die "Expected serial notify PDU";
                        }
                        return $self->refresh(1, $persist,
                                              $version_override,
                                              $success_cb);
                    }
                }
                return;
            }
        }
    }

    $self->_init_socket_if_not_exists();
    $self->_send_serial_query();
    my $pdu = $self->_receive_cache_response();
    my $version = $pdu->version();
    $self->{'current_version'} = $version_override || $version;
    # todo: negotiation checks needed here.

    my ($res, $changeset, $other_pdu) = $self->_process_responses();
    if (not $res) {
        if ($other_pdu) {
            if ($other_pdu->type() == PDU_CACHE_RESET()) {
                # Cache reset PDU: call reset.
                $self->{'state'}    = undef;
                $self->{'eod'}      = undef;
                $self->{'last_run'} = undef;
                $self->{'socket'}   = undef;
                return $self->reset(1);
            }
            warn $other_pdu->serialise_json(),"\n";
        }
        die "Failed to process cache responses";
    } else {
        my $error_pdu = $self->{'state'}->apply_changeset($changeset, $version);
        if ($error_pdu and ref $error_pdu) {
            my $socket = $self->{'socket'};
            $socket->send($error_pdu->serialise_binary());
            die "client: got error: ".
                error_type_to_string($error_pdu->error_code());
        }
        $self->{'eod'} = $other_pdu;
        $self->{'last_run'} = time();
        $self->{'state'}->{'serial_number'} = $other_pdu->serial_number();
    }

    if ($persist) {
        if (my $sp = $self->{'state_path'}) {
            my $data = $self->serialise_json();
            write_file($sp, $data);
        }
        if ($success_cb) {
            $success_cb->();
        }
        return $self->refresh(0, $persist, $version_override, $success_cb);
    } else {
        $self->_close_socket();
    }

    return 1;
}

sub reset_if_required
{
    my ($self) = @_;

    my $eod          = $self->{'eod'};
    my $last_failure = $self->{'last_failure'};
    my $last_run     = $self->{'last_run'};

    if ($last_failure > $last_run) {
        my $last_use_time;
        if ($eod and ($self->{'current_version'} > 0)) {
            $last_use_time =
                $last_failure + $eod->expire_interval();
        } else {
            # It may be worth making this configurable, though it is
            # only useful for v0 clients.
            $last_use_time = $last_failure + 3600;
        }
        if (time() > $last_use_time) {
            dprint("client: removing state and resetting, reached expiry time");
            delete $self->{'state'};
            delete $self->{'eod'};
            delete $self->{'last_run'};
            delete $self->{'last_failure'};
            return $self->reset();
        }
    }

    return;
}

sub state
{
    my ($self) = @_;

    return $self->{'state'};
}

sub serialise_json
{
    my ($self) = @_;

    my $data = {
        (map {
            $self->{$_} ? ($_ => $self->{$_}->serialise_json()) : ()
        } qw(state eod)),
        (map {
            $self->{$_} ? ($_ => $self->{$_}) : ()
        } qw(server port last_run last_failure supported_versions
             sv_lookup max_supported_version current_version)),
    };
    return encode_json($data);
}

sub deserialise_json
{
    my ($class, $data) = @_;

    my $obj = decode_json($data);
    if ($obj->{'state'}) {
        $obj->{'state'} =
            APNIC::RPKI::RTR::State->deserialise_json($obj->{'state'});
    }
    if ($obj->{'eod'}) {
        $obj->{'eod'} =
            APNIC::RPKI::RTR::PDU::EndOfData->deserialise_json($obj->{'eod'});
    }
    bless $obj, $class;
    return $obj;
}

1;
