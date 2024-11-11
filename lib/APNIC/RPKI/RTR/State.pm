package APNIC::RPKI::RTR::State;

use warnings;
use strict;

use Math::BigInt;
use JSON::XS qw(encode_json decode_json);

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::PDU::IPv6Prefix;
use APNIC::RPKI::RTR::PDU::Utils qw(order_pdus);
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
        session_id      => $session_id,
        serial_number   => $serial_number,
        vrps            => $args{vrps},
        rks             => {},
        aspas           => {},
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
    my ($self, $changeset, $version, $ignore_errors, $combine_aspas) = @_;

    my @pdus = @{$changeset->{'pdus'}};
    my $pdu_count = scalar @pdus;
    dprint("state: applying changeset ($pdu_count PDUs)");
    for my $pdu (@pdus) {
        if ($pdu->type() == PDU_IPV4_PREFIX()
                or $pdu->type() == PDU_IPV6_PREFIX()) {
            dprint("state: applying changeset: IP prefix");
            my $asn        = $pdu->asn();
            my $addr       = $pdu->address(),
            my $length     = $pdu->prefix_length();
            my $max_length = $pdu->max_length();
            my $flags      = $pdu->flags();
            if ($flags == 1) {
                dprint("state: adding IP prefix: $asn, $addr/$length-$max_length");
                if (not $ignore_errors) {
                    if (exists $self->{'vrps'}->{$asn}->{$addr}->{$length}->{$max_length}) {
                        dprint("state: addition of known record");
                        my $error_pdu =
                            APNIC::RPKI::RTR::PDU::ErrorReport->new(
                                version          => $version,
                                error_code       => ERR_DUPLICATE_ANNOUNCEMENT_RECEIVED(),
                                encapsulated_pdu => $pdu,
                            );
                        return $error_pdu;
                    } else {
                        dprint("state: addition of unknown record");
                    }
                }
                $self->{'vrps'}->{$asn}->{$addr}->{$length}->{$max_length} = 1;
            } elsif ($flags == 0) {
                dprint("state: removing IP prefix: $asn, $addr/$length-$max_length");
                if (not $ignore_errors) {
                    if (not exists $self->{'vrps'}->{$asn}->{$addr}->{$length}->{$max_length}) {
                        dprint("state: withdrawal of unknown record");
                        my $error_pdu =
                            APNIC::RPKI::RTR::PDU::ErrorReport->new(
                                version          => $version,
                                error_code       => ERR_WITHDRAWAL_OF_UNKNOWN_RECORD(),
                                encapsulated_pdu => $pdu,
                            );
                        return $error_pdu;
                    } else {
                        dprint("state: withdrawal of known record");
                    }
                }
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
        } elsif ($pdu->type() == PDU_ROUTER_KEY()) {
            dprint("state: applying changeset: router key");
            my $ski = Math::BigInt->new($pdu->ski());
            my $asn = $pdu->asn();
            my $spki = $pdu->spki();
            my $flags = $pdu->flags();
            if ($flags == 1) {
                if (not $ignore_errors) {
                    if (exists $self->{'rks'}->{$asn}->{$ski->bstr()}->{$spki}) {
                        dprint("state: addition of known record");
                        my $error_pdu =
                            APNIC::RPKI::RTR::PDU::ErrorReport->new(
                                version          => $version,
                                error_code       => ERR_DUPLICATE_ANNOUNCEMENT_RECEIVED(),
                                encapsulated_pdu => $pdu,
                            );
                        return $error_pdu;
                    } else {
                        dprint("state: addition of unknown record");
                    }
                }
                $self->{'rks'}->{$asn}->{$ski->bstr()}->{$spki} = 1; 
            } elsif ($flags == 0) {
                if (not $ignore_errors) {
                    if (not exists $self->{'rks'}->{$asn}->{$ski->bstr()}->{$spki}) {
                        dprint("state: withdrawal of unknown record");
                        my $error_pdu =
                            APNIC::RPKI::RTR::PDU::ErrorReport->new(
                                version          => $version,
                                error_code       => ERR_WITHDRAWAL_OF_UNKNOWN_RECORD(),
                                encapsulated_pdu => $pdu,
                            );
                        return $error_pdu;
                    } else {
                        dprint("state: withdrawal of known record");
                    }
                }
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
        } elsif ($pdu->type() == PDU_ASPA()) {
            dprint("state: applying changeset: ASPA");
            my $customer_asn = $pdu->customer_asn();
            my @provider_asns = @{$pdu->provider_asns()};
            my $flags = $pdu->flags();
            if ($flags == 1) {
                if (not $ignore_errors) {
                    if (not @provider_asns) {
                        dprint("state: no provider ASNs in ASPA announcement");
                        my $error_pdu =
                            APNIC::RPKI::RTR::PDU::ErrorReport->new(
                                version          => $version,
                                error_code       => ERR_ASPA_PROVIDER_LIST_ERROR(),
                                encapsulated_pdu => $pdu,
                            );
                        return $error_pdu;
                    }
                }
                if ($combine_aspas) {
                    $self->{'aspas'}->{$customer_asn} =
                        [sort uniq(
                            @{$self->{'aspas'}->{$customer_asn} || []},
                            @provider_asns)];
                } else {
                    $self->{'aspas'}->{$customer_asn} = \@provider_asns;
                }
            } else {
                if (not $ignore_errors) {
                    if (not exists $self->{'aspas'}->{$customer_asn}) {
                        dprint("state: withdrawal of unknown record");
                        my $error_pdu =
                            APNIC::RPKI::RTR::PDU::ErrorReport->new(
                                version          => $version,
                                error_code       => ERR_WITHDRAWAL_OF_UNKNOWN_RECORD(),
                                encapsulated_pdu => $pdu,
                            );
                        return $error_pdu;
                    } else {
                        dprint("state: withdrawal of known record");
                    }
                }
                # When combining ASPA records (only relevant when the
                # router is connecting to multiple caches), an empty
                # ASPA has no effect.
                if (not $combine_aspas) {
                    delete $self->{'aspas'}->{$customer_asn};
                }
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

    return order_pdus($self->_pdus());
}

sub _pdus
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

    my $rks = $self->{'rks'};
    @asns = keys %{$rks};
    for my $asn (@asns) {
        my $skis = $rks->{$asn};
        for my $ski (keys %{$skis}) {
            my @spkis = keys %{$skis->{$ski}};
            for my $spki (@spkis) {
                my $pdu =
                    APNIC::RPKI::RTR::PDU::RouterKey->new(
                        version => 1,
                        flags   => 1,
                        ski     => $ski,
                        asn     => $asn,
                        spki    => $spki
                    );
                push @pdus, $pdu;
            }
        }
    }

    return @pdus;
}

sub to_changeset
{
    my ($self) = @_;

    my @pdus = $self->pdus();

    my $data = {
        pdus                => \@pdus,
        first_serial_number => 1,
        last_serial_number  => 1,
    };
    bless $data, "APNIC::RPKI::RTR::Changeset";
    return $data;
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
