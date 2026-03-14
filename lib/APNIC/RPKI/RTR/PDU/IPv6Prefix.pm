package APNIC::RPKI::RTR::PDU::IPv6Prefix;

use warnings;
use strict;

use JSON::XS qw(decode_json);
use Net::IP::XS qw(ip_compress_address);

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Utils qw(inet_pton
                               inet_ntop
                               dprint
                               recv_all
                               get_zero
                               encode_json_rtr);

use base qw(APNIC::RPKI::RTR::PDU);

sub new
{
    my $class = shift;
    my %args = @_;

    my $self = {
        version       => $args{'version'},
        flags         => $args{'flags'},
        prefix_length => $args{'prefix_length'},
        max_length    => $args{'max_length'},
        address       => ip_compress_address($args{'address'}, 6),
        asn           => $args{'asn'},
    };
    bless $self, $class;
    return $self;
}

sub type
{
    return PDU_IPV6_PREFIX();
}

sub type_str
{
    return 'IPv6 Prefix';
}

sub is_ip_type
{
    return 1;
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

    my $bi = inet_pton($self->address(), 6);
    my $mask = Math::BigInt->new(1)->blsft(32)->bsub(1);
    my $ipv6_1 = $bi->copy()->brsft(96)->band($mask);
    my $ipv6_2 = $bi->copy()->brsft(64)->band($mask);
    my $ipv6_3 = $bi->copy()->brsft(32)->band($mask);
    my $ipv6_4 = $bi->copy()->band($mask);

    return pack("CCnNCCCCNNNNN",
                $self->version(),
                $self->type(),
                get_zero(16),
                32,
                $self->flags(),
                $self->prefix_length(),
                $self->max_length(),
                get_zero(8),
                $ipv6_1->bstr(),
                $ipv6_2->bstr(),
                $ipv6_3->bstr(),
                $ipv6_4->bstr(),
                $self->asn());
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    if ($length != 32) {
        die "Expected length of 32 for IPv6 Prefix PDU, ".
            "but got '$length'.";
    }

    my $buf = recv_all($socket, 24);
    my ($flags, $prefix_length, $max_length, undef,
	$ipv6_1, $ipv6_2, $ipv6_3, $ipv6_4, $asn) =
	unpack("CCCCNNNNN", $buf);
    my $bi1 = Math::BigInt->new($ipv6_1)->blsft(96);
    my $bi2 = Math::BigInt->new($ipv6_2)->blsft(64);
    my $bi3 = Math::BigInt->new($ipv6_3)->blsft(32);
    my $bi4 = Math::BigInt->new($ipv6_4);
    my $ipv6_bi = Math::BigInt->new($bi1)->badd($bi2)->badd($bi3)->badd($bi4);
    my $ipv6_addr = inet_ntop($ipv6_bi->bstr(), 6);

    return
        APNIC::RPKI::RTR::PDU::IPv6Prefix->new(
            version       => $version,
            flags         => $flags,
            prefix_length => $prefix_length,
            max_length    => $max_length,
            address       => $ipv6_addr,
            asn           => $asn
        );
}

sub serialise_json
{
    my ($self) = @_;

    return encode_json_rtr({%{$self}, type => $self->type()});
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

    return (($version >= 0) and ($version <= 2));
}

sub address_as_number
{
    my ($self) = @_;

    my $net_ip = Net::IP::XS->new($self->address());
    return $net_ip->intip();
}

1;
