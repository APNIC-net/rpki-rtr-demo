package APNIC::RPKI::RTR::State;

use warnings;
use strict;

use Math::BigInt;
use JSON::XS qw(encode_json decode_json);

use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::PDU::IPv6Prefix;
use APNIC::RPKI::RTR::Utils qw(dprint);

my $MAX_SERIAL_NUMBER = Math::BigInt->new(1)->blsft(32)->bsub(1);

sub new
{
    my $class = shift;
    my %args = @_;

    my $session_id = $args{'session_id'};
    if (not $session_id) {
        die "No session ID provided.";
    }
    if ($session_id !~ /^\d+$/) {
        die "Session ID must be a number.";
    }
    if (not ($session_id > 0 and $session_id <= 65535)) {
        die "Session ID must be 16-bit unsigned integer.";
    }

    my $serial_number = $args{'serial_number'};

    my $self = {
        session_id    => $session_id,
        serial_number => $serial_number,
        vrps          => $args{vrps},
        rks           => {},
        aspas         => {},
    };
    bless $self, $class;

    return $self;
}

sub serial_number
{
    my ($self) = @_;

    return $self->{'serial_number'};
}

sub session_id
{
    my ($self) = @_;

    return $self->{'session_id'};
}

sub apply_changeset
{
    my ($self, $changeset) = @_;

    dprint("state: applying changeset");
    my @pdus = @{$changeset->{'pdus'}};
    for my $pdu (@pdus) {
        if ($pdu->type() == 4 or $pdu->type() == 6) {
            my $asn        = $pdu->asn();
            my $addr       = $pdu->address(),
            my $length     = $pdu->prefix_length();
            my $max_length = $pdu->max_length();
            my $flags      = $pdu->flags();
            if ($flags == 1) {
                dprint("state: adding IP prefix: $asn, $addr/$length-$max_length");
                $self->{'vrps'}->{$asn}->{$addr}->{$length}->{$max_length} = 1;
            } elsif ($flags == 0) {
                dprint("state: removing IP prefix: $asn, $addr/$length-$max_length");
		delete $self->{'vrps'}->{$asn}->{$addr}->{$length}->{$max_length};
		if (keys %{$self->{'vrps'}->{$asn}->{$addr}->{$length}} == 0) {
		    delete $self->{'vrps'}->{$asn}->{$addr}->{$length};
		    if (keys %{$self->{'vrps'}->{$asn}->{$addr}} == 0) {
			delete $self->{'vrps'}->{$asn}->{$addr};
			if (keys %{$self->{'vrps'}->{$asn}} == 0) {
			    delete $self->{'vrps'}->{$asn};
			}
		    }
		}
            } else {
                warn "Unexpected flags value, skipping";
            }
        } elsif ($pdu->type() == 7) {
            my $ski = $pdu->ski();
            my $asn = $pdu->asn();
            my $spki = $pdu->spki();
            my $flags = $pdu->flags();
            if ($flags == 1) {
                $self->{'rks'}->{$asn}->{$ski->bstr()}->{$spki} = 1; 
            } elsif ($flags == 0) {
		delete $self->{'rks'}->{$asn}->{$ski->bstr()}->{$spki};
		if (keys %{$self->{'rks'}->{$asn}->{$ski->bstr()}} == 0) {
		    delete $self->{'rks'}->{$asn}->{$ski->bstr()};
		    if (keys %{$self->{'rks'}->{$asn}} == 0) {
			delete $self->{'rks'}->{$asn};
		    }
		} 
            } else {
                warn "Unexpected flags value, skipping";
            }
        } elsif ($pdu->type() == 11) {
            my $customer_asn = $pdu->customer_asn();
            my @provider_asns = @{$pdu->provider_asns()};
            my $flags = $pdu->flags();
            if ($flags == 1) {
                $self->{'aspas'}->{$customer_asn} = \@provider_asns;
            } else {
                delete $self->{'aspas'}->{$customer_asn};
            }
        } else {
            warn "Unexpected PDU type ".$pdu->type().", skipping";
        }
    }

    $self->{'serial_number'} = $changeset->{'last_serial_number'};

    return 1;
}

sub pdus
{
    my ($self) = @_;

    my @pdus;

    my $vrps = $self->{'vrps'};
    my @asns = keys %{$vrps};
    for my $asn (@asns) {
        my $asn_st = $vrps->{$asn};
        my @addrs = keys %{$asn_st};
        for my $addr (@addrs) {
            my $addr_st = $asn_st->{$addr};
            my @lens = keys %{$addr_st};
            for my $len (@lens) {
                my $len_st = $addr_st->{$len};
                my @mlens = keys %{$len_st};
                for my $mlen (@mlens) {
                    my $module =
                        ($addr =~ /:/)
                            ? 'APNIC::RPKI::RTR::PDU::IPv6Prefix'
                            : 'APNIC::RPKI::RTR::PDU::IPv4Prefix';
                    my $pdu = $module->new(
                        version       => 1,
                        flags         => 1,
                        prefix_length => $len,
                        max_length    => $mlen,
                        address       => $addr,
                        asn           => $asn
                    );
                    push @pdus, $pdu;
                }
            }
        }
    }

    my $aspas = $self->{'aspas'};
    @asns = keys %{$aspas};
    for my $asn (@asns) {
        my @provider_asns = @{$aspas->{$asn}};
        my $pdu =
            APNIC::RPKI::RTR::PDU::ASPA->new(
                version       => 2,
                flags         => 1,
                afi_flags     => 3,
                customer_asn  => $asn,
                provider_asns => \@provider_asns
            );
        push @pdus, $pdu;
    }

    return @pdus;
}

sub serialise_json
{
    my ($self) = @_;

    return encode_json({%{$self}});
}

sub deserialise_json
{
    my ($class, $data) = @_;

    my $self = decode_json($data);
    bless $self, $class;
    return $self;
}

1;
