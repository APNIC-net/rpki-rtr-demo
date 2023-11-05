package APNIC::RPKI::RTR::PDU::IPv4Prefix;

use warnings;
use strict;

use JSON::XS qw(encode_json decode_json);

use APNIC::RPKI::RTR::Utils qw(inet_pton
                               inet_ntop
                               dprint
                               recv_all);

use base qw(APNIC::RPKI::RTR::PDU);

sub new
{
    my $class = shift;
    my %args = @_;

    if (not $args{'address'}) {
        die "Expected address";
    }

    my $self = {
        version       => $args{'version'},
        flags         => $args{'flags'},
        prefix_length => $args{'prefix_length'},
        max_length    => $args{'max_length'},
        address       => $args{'address'},
        asn           => $args{'asn'},
    };
    bless $self, $class;
    return $self;
}

sub type
{
    return 4;
}

sub type_str
{
    return 'IPv4 Prefix';
}

sub version
{
    my ($self) = @_;

    return $self->{'version'};
}

sub flags
{
    my ($self) = @_;

    return $self->{'flags'};
}

sub prefix_length
{
    my ($self) = @_;

    return $self->{'prefix_length'};
}

sub max_length
{
    my ($self) = @_;

    return $self->{'max_length'};
}

sub address
{
    my ($self) = @_;

    return $self->{'address'};
}

sub asn
{
    my ($self) = @_;

    return $self->{'asn'};
}

sub serialise_binary
{
    my ($self) = @_;

    return pack("CCnNCCCCNN",
                $self->version(),
                $self->type(),
                0,
                20,
                $self->flags(),
                $self->prefix_length(),
                $self->max_length(),
                0,
                inet_pton($self->address(), 4),
                $self->asn());
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    if ($length != 20) {
        die "Expected length of 20 for IPv4 Prefix PDU, ".
            "but got '$length'.";
    }

    my $buf = recv_all($socket, 12);
    my ($flags, $prefix_length, $max_length, undef,
	$ipv4_addr_num, $asn) =
	unpack("CCCCNN", $buf);
    my $ipv4_addr = inet_ntop($ipv4_addr_num, 4);

    return
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => $version,
            flags         => $flags,
            prefix_length => $prefix_length,
            max_length    => $max_length,
            address       => $ipv4_addr,
            asn           => $asn
        );
}

sub serialise_json
{
    my ($self) = @_;

    return encode_json({%{$self}, type => $self->type()});
}

sub deserialise_json
{
    my ($class, $data) = @_;

    my $self = decode_json($data);
    bless $self, $class;
    return $self;
}

sub is_reversal_of
{
    my ($self, $other) = @_;

    return ($other->type() == $self->type()
            and ($self->version() eq $other->version())
            and ($self->prefix_length() == $other->prefix_length())
            and ($self->max_length() == $other->max_length())
            and ($self->address() eq $other->address())
            and ($self->asn() == $other->asn())
            and ($self->flags() xor $other->flags()));
}

sub equals
{
    my ($self, $other) = @_;

    return ($other->type() == $self->type()
            and ($self->version() eq $other->version())
            and ($self->prefix_length() == $other->prefix_length())
            and ($self->max_length() == $other->max_length())
            and ($self->address() eq $other->address())
            and ($self->asn() == $other->asn())
            and ($self->flags() == $other->flags()));
}

sub supported_in_version
{
    my ($self, $version) = @_;

    return (($version == 1) or ($version == 2));
}

1;
