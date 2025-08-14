use strict;
use warnings;

use APNIC::RPKI::RTR::State;
use APNIC::RPKI::Validator::ASPA;

use Test::More tests => 25;

sub run_test
{
    my ($test_case) = @_;

    my $state = APNIC::RPKI::RTR::State->new(
        session_id    => 1,
        serial_number => 1,
        aspas         => $test_case->{'aspas'},
    );

    my $mapping = $test_case->{'mapping'};

    my $route = $test_case->{'route'};
    my @route_parts = split /\|/, $route;
    $route_parts[0] = $mapping->{$route_parts[0]};
    my @path = split /\s+/, $route_parts[2];
    @path = map { $mapping->{$_} } @path;
    $route_parts[2] = join " ", @path;
    $route = join "|", @route_parts;

    my $provider_asns = $test_case->{'provider_asns'};
    my %provider_asns_mapped;
    for my $key (keys %{$provider_asns}) {
        my $num = $mapping->{$key};
        my $value = $provider_asns->{$key};
        $provider_asns_mapped{$num} = $value;
    }

    my $rov_result =
        APNIC::RPKI::Validator::ASPA::validate(
            $state,
            \%provider_asns_mapped,
            "||||$route",
        );

    is($rov_result,
       $test_case->{'expected'},
       $test_case->{'name'});
}

# Except for the first test case, these tests are taken from
# https://github.com/ksriram25/IETF/blob/main/ASPA_path_verification_examples.pdf.

my %aspa_ltn = (
    A => 1,
    B => 2,
    C => 3,
    D => 4,
    E => 5,
    F => 6,
    G => 7,
    0 => 0,
);

my %aspa_state = (
    A => [qw(C D)],
    B => [qw(E)],
    C => [qw(F)],
    D => [qw(F G)],
    G => [0]
);

my %aspa_state_mapped =
    map { my $key = $_;
          my $num = $aspa_ltn{$key};
          my @nums =
              map { $aspa_ltn{$_} }
                  @{$aspa_state{$key}};
          $num => \@nums }
        keys %aspa_state;

my %c_aspa_ltn = (
    H => 1,
    J => 2,
    K => 3,
    L => 4,
    P => 5,
    Q => 6,
    R => 7,
    S => 8,
    0 => 0,
);

my %c_aspa_state = (
    H => [qw(0)],
    K => [qw(0)],
    L => [qw(K)],
    P => [qw(0)],
    Q => [qw(0)],
    R => [qw(Q)],
    S => [qw(R)],
);

my %c_aspa_state_mapped =
    map { my $key = $_;
          my $num = $c_aspa_ltn{$key};
          my @nums =
              map { $c_aspa_ltn{$_} }
                  @{$c_aspa_state{$key}};
          $num => \@nums }
        keys %c_aspa_state;

my @test_cases = (
    {
        aspas         => {},
        provider_asns => {},
        mapping       => \%aspa_ltn,
        route         => "A|10.0.0.0/24|A B C",
        expected      => 1,
        name          => "No ASPAs, so path is unknown",
    },

    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'G'}} },
        mapping       => \%aspa_ltn,
        route         => "F|10.0.0.0/24|F C A",
        expected      => 2,
        name          => "Upstream 1",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'G'}} },
        mapping       => \%aspa_ltn,
        route         => "D|10.0.0.0/24|D C A",
        expected      => 0,
        name          => "Upstream 2",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'G'}} },
        mapping       => \%aspa_ltn,
        route         => "D|10.0.0.0/24|D F C A",
        expected      => 1,
        name          => "Upstream 3",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'C'}} },
        mapping       => \%aspa_ltn,
        route         => "D|10.0.0.0/24|D E B",
        expected      => 1,
        name          => "Upstream 4",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'C'}} },
        mapping       => \%aspa_ltn,
        route         => "A|10.0.0.0/24|A D E B",
        expected      => 0,
        name          => "Upstream 5",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'C'}} },
        mapping       => \%aspa_ltn,
        route         => "A|10.0.0.0/24|A D G E B",
        expected      => 0,
        name          => "Upstream 6",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'D'}} },
        mapping       => \%aspa_ltn,
        route         => "A|10.0.0.0/24|A C F",
        expected      => 0,
        name          => "Upstream 7",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'D'}} },
        mapping       => \%aspa_ltn,
        route         => "A|10.0.0.0/24|A C F G",
        expected      => 0,
        name          => "Upstream 8",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'D'}} },
        mapping       => \%aspa_ltn,
        route         => "E|10.0.0.0/24|E B",
        expected      => 2,
        name          => "Upstream 9",
    },

    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'B'}} },
        mapping       => \%aspa_ltn,
        route         => "E|10.0.0.0/24|E G F C A",
        expected      => 1,
        name          => "Downstream 1",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'B'}} },
        mapping       => \%aspa_ltn,
        route         => "E|10.0.0.0/24|E G D A",
        expected      => 2,
        name          => "Downstream 2",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'B'}} },
        mapping       => \%aspa_ltn,
        route         => "E|10.0.0.0/24|E D C A",
        expected      => 1,
        name          => "Downstream 3",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'B'}} },
        mapping       => \%aspa_ltn,
        route         => "E|10.0.0.0/24|E G D C A",
        expected      => 0,
        name          => "Downstream 4",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'A'}} },
        mapping       => \%aspa_ltn,
        route         => "C|10.0.0.0/24|C F D G",
        expected      => 1,
        name          => "Downstream 5",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'A'}} },
        mapping       => \%aspa_ltn,
        route         => "D|10.0.0.0/24|D G E B",
        expected      => 2,
        name          => "Downstream 6",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'A'}} },
        mapping       => \%aspa_ltn,
        route         => "C|10.0.0.0/24|C D G E B",
        expected      => 0,
        name          => "Downstream 7",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'D'}} },
        mapping       => \%aspa_ltn,
        route         => "F|10.0.0.0/24|F C A",
        expected      => 2,
        name          => "Downstream 8",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'B'}} },
        mapping       => \%aspa_ltn,
        route         => "E|10.0.0.0/24|E A",
        expected      => 2,
        name          => "Downstream 9",
    },
    {
        aspas         => \%aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{'B'}} },
        mapping       => \%aspa_ltn,
        route         => "E|10.0.0.0/24|E C A",
        expected      => 2,
        name          => "Downstream 10",
    },

    {
        aspas         => \%c_aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$c_aspa_state{'K'}} },
        mapping       => \%c_aspa_ltn,
        route         => "J|10.0.0.0/24|J H",
        expected      => 0,
        name          => "Complex 1",
    },
    # 'Complex 2' is omitted, because for the purposes of this
    # validation logic it's a duplicate of 'Complex 1'.
    {
        aspas         => \%c_aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$c_aspa_state{'L'}} },
        mapping       => \%c_aspa_ltn,
        route         => "K|10.0.0.0/24|K J H",
        expected      => 0,
        name          => "Complex 3",
    },
    {
        aspas         => \%c_aspa_state_mapped,
        # Force upstream.
        provider_asns => {},
        mapping       => \%c_aspa_ltn,
        route         => "Q|10.0.0.0/24|Q P",
        expected      => 0,
        name          => "Complex 4",
    },
    {
        aspas         => \%c_aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$c_aspa_state{'R'}} },
        mapping       => \%c_aspa_ltn,
        route         => "Q|10.0.0.0/24|Q P",
        expected      => 2,
        name          => "Complex 5",
    },
    {
        aspas         => \%c_aspa_state_mapped,
        provider_asns => { map { $_ => 1 }
                               @{$c_aspa_state{'S'}} },
        mapping       => \%c_aspa_ltn,
        route         => "R|10.0.0.0/24|R Q P",
        expected      => 2,
        name          => "Complex 6",
    },
);

for my $test_case (@test_cases) {
    run_test($test_case);
}
