package APNIC::RPKI::RTR::PDU::ErrorReport;

use warnings;
use strict;

use JSON::XS qw(decode_json);

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Utils qw(dprint);
use APNIC::RPKI::RTR::PDU::Utils qw(parse_pdu);
use APNIC::RPKI::RTR::Utils qw(recv_all
                               encode_json_rtr);

use base qw(APNIC::RPKI::RTR::PDU);

sub new
{
    my $class = shift;
    my %args = @_;

    if (not defined $args{'version'}) {
        die "Version not defined";
    }

    my $self = {
        version          => $args{'version'},
        error_code       => $args{'error_code'},
        encapsulated_pdu => $args{'encapsulated_pdu'},
        error_text       => $args{'error_text'},
    };
    bless $self, $class;
    return $self;
}

sub type
{
    return PDU_ERROR_REPORT();
}

sub type_str
{
    return 'Error Report';
}

sub is_ip_type
{
    return 0;
}

sub version
{
    my ($self) = @_;

    return $self->{'version'};
}

sub error_code
{
    my ($self) = @_;
    
    return $self->{'error_code'};
}

sub encapsulated_pdu
{
    my ($self) = @_;
    
    return $self->{'encapsulated_pdu'};
}

sub error_text
{
    my ($self) = @_;
    
    return $self->{'error_text'};
}

sub serialise_binary
{
    my ($self) = @_;

    my $ep_data = "";
    my $ep_len = 0;
    my $encapsulated_pdu = $self->encapsulated_pdu();
    if ($encapsulated_pdu) {
        $ep_data = $encapsulated_pdu->serialise_binary();
        $ep_len = length($ep_data);
    }

    my $err_data = $self->error_text() || '';
    my $err_len = length($err_data) || 0;

    if ($ep_len and $err_len) {
        return pack("CCnNNa${ep_len}Na${err_len}",
                    $self->version(),
                    $self->type(),
                    $self->error_code(),
                    16 + $ep_len + $err_len,
                    $ep_len,
                    $ep_data,
                    $err_len,
                    $err_data);
    } elsif ($ep_len) {
        return pack("CCnNNa${ep_len}N",
                    $self->version(),
                    $self->type(),
                    $self->error_code(),
                    16 + $ep_len + $err_len,
                    $ep_len,
                    $ep_data,
                    $err_len);
    } elsif ($err_len) {
        return pack("CCnNNNa${err_len}",
                    $self->version(),
                    $self->type(),
                    $self->error_code(),
                    16 + $ep_len + $err_len,
                    $ep_len,
                    $err_len,
                    $err_data);
    } else {
        return pack("CCnNNN",
                    $self->version(),
                    $self->type(),
                    $self->error_code(),
                    16 + $ep_len + $err_len,
                    $ep_len,
                    $err_len);
    }
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    my $error_code = $session_id;

    my $encap_pdu_len_buf = recv_all($socket, 4);
    my $encap_pdu_len = unpack("N", $encap_pdu_len_buf);
    my $encap_pdu;
    if ($encap_pdu_len > 0) {
        $encap_pdu = APNIC::RPKI::RTR::PDU::Utils::parse_pdu($socket); 
    }

    my $err_text_len_buf = recv_all($socket, 4);
    my $err_text_len = unpack("N", $err_text_len_buf);
    my $err_text_buf = recv_all($socket, $err_text_len);
    my $actual_length = (16 + $encap_pdu_len + $err_text_len);
    if ($length != $actual_length) {
	warn "Error PDU size mismatch: expected '$length', was '$actual_length'";
    }

    return
        APNIC::RPKI::RTR::PDU::ErrorReport->new(
            version          => $version,
            error_code       => $error_code,
            encapsulated_pdu => $encap_pdu,
            error_text       => $err_text_buf,
        );
}

sub serialise_json
{
    my ($self) = @_;

    my $encap_pdu = $self->encapsulated_pdu();
    my $encap_pdu_json =
        ($encap_pdu)
            ? $encap_pdu->serialise_json()
            : undef;

    return encode_json_rtr({
        version          => $self->version(),
        type             => $self->type(),
        error_code       => $self->error_code(),
        error_text       => $self->error_text(),
        encapsulated_pdu => $encap_pdu_json,
    });
}

sub deserialise_json
{
    my ($class, $data) = @_;

    my $decoded_data = decode_json($data);
    delete $decoded_data->{'type'};
    my $encap_pdu;
    if (my $pdu_json = delete $decoded_data->{'encapsulated_pdu'}) {
        $encap_pdu =
            APNIC::RPKI::RTR::PDU::Utils::deserialise_json($pdu_json);
    }

    my $self = {
        %{$decoded_data},
        encapsulated_pdu => $encap_pdu,
    };

    bless $self, $class;
    return $self;
}

sub is_reversal_of
{
    return 0;
}

sub equals
{
    my ($self, $other) = @_;

    my $self_ep  = $self->encapsulated_pdu();
    my $other_ep = $other->encapsulated_pdu();

    if ($self->encapsulated_pdu() xor $other->encapsulated_pdu()) {
        return;
    }
    if ($self_ep) {
        if (not $self_ep->equals($other_ep)) {
            return;
        }
    }

    return (($self->type() == $other->type())
                and ($self->error_code() == $other->error_code())
                and (($self->error_text() || '') eq ($other->error_text() || '')));
}

sub supported_in_version
{
    my ($self, $version) = @_;

    return (($version >= 0) and ($version <= 2));
}

1;
