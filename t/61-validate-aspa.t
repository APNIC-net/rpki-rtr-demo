use strict;
use warnings;

use APNIC::RPKI::RTR::State;
use APNIC::RPKI::Validator::ASPA;

use Test::More tests => 10;

sub run_test
{
    my ($test_case) = @_;

    my $state = APNIC::RPKI::RTR::State->new(
        session_id    => 1,
        serial_number => 1,
        aspas         => $test_case->{'aspas'},
    );

    my $rov_result =
        APNIC::RPKI::Validator::ASPA::validate(
            $state,
            $test_case->{'provider_asns'},
            "||||".$test_case->{'route'},
        );

    is($rov_result,
       $test_case->{'expected'},
       $test_case->{'name'});
}

my %upstream_aspa_state = (
    1 => [3, 4],
    2 => [5],
    3 => [6],
    4 => [6, 7],
    7 => [0]
);

my @test_cases = (
    {
        aspas         => {},
        provider_asns => {},
        route         => "1|10.0.0.0/24|1 2 3",
        expected      => 1,
        name          => "No ASPAs, so path is unknown",
    },
    {
        aspas         => \%upstream_aspa_state,
        provider_asns => { map { $_ => 1 }
                               $upstream_aspa_state{7} },
        route         => "6|10.0.0.0/24|6 3 1",
        expected      => 2,
        name          => "Each segment has an ASPA",
    },
    {
        aspas         => \%upstream_aspa_state,
        provider_asns => { map { $_ => 1 }
                               $upstream_aspa_state{7} },
        route         => "4|10.0.0.0/24|4 3 1",
        expected      => 0,
        name          => "4 is not a provider for 3",
    },
    {
        aspas         => \%upstream_aspa_state,
        provider_asns => { map { $_ => 1 }
                               $upstream_aspa_state{7} },
        route         => "4|10.0.0.0/24|4 6 3 1",
        expected      => 1,
        name          => "6 has no ASPA, so unknown",
    },
    {
        aspas         => \%upstream_aspa_state,
        provider_asns => { map { $_ => 1 }
                               $upstream_aspa_state{3} },
        route         => "4|10.0.0.0/24|4 5 2",
        expected      => 1,
        name          => "5 has no ASPA, so unknown",
    },
    {
        aspas         => \%upstream_aspa_state,
        provider_asns => { map { $_ => 1 }
                               $upstream_aspa_state{3} },
        route         => "1|10.0.0.0/24|1 4 5 2",
        expected      => 0,
        name          => "1 is not a provider for 4",
    },
    {
        aspas         => \%upstream_aspa_state,
        provider_asns => { map { $_ => 1 }
                               $upstream_aspa_state{3} },
        route         => "1|10.0.0.0/24|1 4 7 5 2",
        expected      => 0,
        name          => "1 is still not a provider for 4",
    },
    {
        aspas         => \%upstream_aspa_state,
        provider_asns => { map { $_ => 1 }
                               $upstream_aspa_state{4} },
        route         => "1|10.0.0.0/24|1 3 6",
        expected      => 0,
        name          => "1 is not a provider for 3",
    },
    {
        aspas         => \%upstream_aspa_state,
        provider_asns => { map { $_ => 1 }
                               $upstream_aspa_state{4} },
        route         => "1|10.0.0.0/24|1 3 6 7",
        expected      => 0,
        name          => "1 is still not a provider for 3",
    },
    {
        aspas         => \%upstream_aspa_state,
        provider_asns => { map { $_ => 1 }
                               $upstream_aspa_state{4} },
        route         => "5|10.0.0.0/24|5 2",
        expected      => 2,
        name          => "2-element path with ASPA segment is valid",
    },
);

for my $test_case (@test_cases) {
    run_test($test_case);
}
