use strict;
use warnings;

use APNIC::RPKI::RTR::State;
use APNIC::RPKI::Validator::ASPA;

use Test::More tests => 1;

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

my %aspa_mapping = (
    A => 1,
    B => 2,
    C => 3,
    D => 4,
    E => 5,
    0 => 0,
);

my %aspa_state = (
    A => [qw(B)],
    B => [qw(C)],
    C => [qw(0)],
    D => [qw(C)],
    E => []
);

my @test_cases = (
    {
        mapping       => \%aspa_mapping,
        aspas         => \%aspa_state,
        recipient     => 'D',
        route         => [qw(E A)],
        expected      => 0,
        name          => "T1",
    },
);

for my $test_case (@test_cases) {
    run_test($test_case);
}
