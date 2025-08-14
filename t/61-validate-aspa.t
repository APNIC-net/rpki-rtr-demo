use strict;
use warnings;

use APNIC::RPKI::RTR::State;
use APNIC::RPKI::Validator::ASPA;

use Test::More tests => 24;

sub run_test
{
    my ($test_case) = @_;

    my $mapping = $test_case->{'mapping'};

    my $aspas = $test_case->{'aspas'};
    my %aspas_mapped =
        map { my $key = $_;
              my $num = $mapping->{$key};
              my @nums =
                  map { $mapping->{$_} }
                      @{$aspas->{$key}};
              $num => \@nums }
            keys %{$aspas};

    my $state = APNIC::RPKI::RTR::State->new(
        session_id    => 1,
        serial_number => 1,
        aspas         => \%aspas_mapped
    );

    my @route =
        map { $mapping->{$_} }
            @{$test_case->{'route'}};
    my $peer = $route[0];
    my $route_str = join " ", @route;

    my $recipient = $test_case->{'recipient'};
    my %provider_asns =
        map { $mapping->{$_} => 1 }
            @{$aspas->{$recipient}};

    my $rov_result =
        APNIC::RPKI::Validator::ASPA::validate(
            $state,
            \%provider_asns,
            "||||$peer|10.0.0.0/24|$route_str",
        );

    is($rov_result,
       $test_case->{'expected'},
       $test_case->{'name'});
}

# These tests are taken from
# https://github.com/ksriram25/IETF/blob/main/ASPA_path_verification_examples.pdf.
# The first two variables are for the upstream/downstream tests, while
# the last two variables are for the complex peering tests.

my %aspa_mapping = (
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

my %c_aspa_mapping = (
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

my @test_cases = (
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'G',
        route         => [qw(F C A)],
        expected      => 2,
        name          => "Upstream 1",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'G',
        route         => [qw(D C A)],
        expected      => 0,
        name          => "Upstream 2",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'G',
        route         => [qw(D F C A)],
        expected      => 1,
        name          => "Upstream 3",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'C',
        route         => [qw(D E B)],
        expected      => 1,
        name          => "Upstream 4",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'C',
        route         => [qw(A D E B)],
        expected      => 0,
        name          => "Upstream 5",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'C',
        route         => [qw(A D G E B)],
        expected      => 0,
        name          => "Upstream 6",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'D',
        route         => [qw(A C F)],
        expected      => 0,
        name          => "Upstream 7",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'D',
        route         => [qw(A C F G)],
        expected      => 0,
        name          => "Upstream 8",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'D',
        route         => [qw(E B)],
        expected      => 2,
        name          => "Upstream 9",
    },

    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'B',
        route         => [qw(E G F C A)],
        expected      => 1,
        name          => "Downstream 1",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'B',
        route         => [qw(E G D A)],
        expected      => 2,
        name          => "Downstream 2",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'B',
        route         => [qw(E D C A)],
        expected      => 1,
        name          => "Downstream 3",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'B',
        route         => [qw(E G D C A)],
        expected      => 0,
        name          => "Downstream 4",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'A',
        route         => [qw(C F D G)],
        expected      => 1,
        name          => "Downstream 5",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'A',
        route         => [qw(D G E B)],
        expected      => 2,
        name          => "Downstream 6",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'A',
        route         => [qw(C D G E B)],
        expected      => 0,
        name          => "Downstream 7",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'D',
        route         => [qw(F C A)],
        expected      => 2,
        name          => "Downstream 8",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'B',
        route         => [qw(E A)],
        expected      => 2,
        name          => "Downstream 9",
    },
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'B',
        route         => [qw(E C A)],
        expected      => 2,
        name          => "Downstream 10",
    },

    {
        mapping       => \%c_aspa_mapping,
        aspas         => \%c_aspa_state,
        recipient     => 'K',
        route         => [qw(J H)],
        expected      => 0,
        name          => "Complex 1",
    },
    # 'Complex 2' is omitted, because for the purposes of this
    # validation logic it's a duplicate of 'Complex 1'.
    {
        mapping       => \%c_aspa_mapping,
        aspas         => \%c_aspa_state,
        recipient     => 'L',
        route         => [qw(K J H)],
        expected      => 0,
        name          => "Complex 3",
    },
    {
        mapping       => \%c_aspa_mapping,
        aspas         => \%c_aspa_state,
        # Recipient is L in the test from the PDF, but change to H to
        # force use of the upstream algorithm.
        recipient     => 'H',
        route         => [qw(Q P)],
        expected      => 0,
        name          => "Complex 4",
    },
    {
        mapping       => \%c_aspa_mapping,
        aspas         => \%c_aspa_state,
        recipient     => 'R',
        route         => [qw(Q P)],
        expected      => 2,
        name          => "Complex 5",
    },
    {
        mapping       => \%c_aspa_mapping,
        aspas         => \%c_aspa_state,
        recipient     => 'S',
        route         => [qw(R Q P)],
        expected      => 2,
        name          => "Complex 6",
    },
);

for my $test_case (@test_cases) {
    run_test($test_case);
}
