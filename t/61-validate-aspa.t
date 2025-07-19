use strict;
use warnings;

use APNIC::RPKI::RTR::State;
use APNIC::RPKI::Validator::ASPA;

use Test::More tests => 20;

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

# Except for the first test case, these tests are taken from
# https://github.com/ksriram25/IETF/blob/main/ASPA_path_verification_examples.pdf.
# The letters in the PDF map to numbers here (A => 1, B => 2, and so
# on).

my %aspa_state = (
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
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{7}} },
        route         => "6|10.0.0.0/24|6 3 1",
        expected      => 2,
        name          => "Upstream 1",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{7}} },
        route         => "4|10.0.0.0/24|4 3 1",
        expected      => 0,
        name          => "Upstream 2",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{7}} },
        route         => "4|10.0.0.0/24|4 6 3 1",
        expected      => 1,
        name          => "Upstream 3",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{3}} },
        route         => "4|10.0.0.0/24|4 5 2",
        expected      => 1,
        name          => "Upstream 4",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{3}} },
        route         => "1|10.0.0.0/24|1 4 5 2",
        expected      => 0,
        name          => "Upstream 5",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{3}} },
        route         => "1|10.0.0.0/24|1 4 7 5 2",
        expected      => 0,
        name          => "Upstream 6",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{4}} },
        route         => "1|10.0.0.0/24|1 3 6",
        expected      => 0,
        name          => "Upstream 7",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{4}} },
        route         => "1|10.0.0.0/24|1 3 6 7",
        expected      => 0,
        name          => "Upstream 8",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{4}} },
        route         => "5|10.0.0.0/24|5 2",
        expected      => 2,
        name          => "Upstream 9",
    },

    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{2}} },
        route         => "5|10.0.0.0/24|5 7 6 3 1",
        expected      => 1,
        name          => "Downstream 1",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{2}} },
        route         => "5|10.0.0.0/24|5 7 4 1",
        expected      => 2,
        name          => "Downstream 2",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{2}} },
        route         => "5|10.0.0.0/24|5 4 3 1",
        expected      => 1,
        name          => "Downstream 3",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{2}} },
        route         => "5|10.0.0.0/24|5 7 4 3 1",
        expected      => 0,
        name          => "Downstream 4",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{1}} },
        route         => "3|10.0.0.0/24|3 6 4 7",
        expected      => 1,
        name          => "Downstream 5",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{1}} },
        route         => "4|10.0.0.0/24|4 7 5 2",
        expected      => 2,
        name          => "Downstream 6",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{1}} },
        route         => "3|10.0.0.0/24|3 4 7 5 2",
        expected      => 0,
        name          => "Downstream 7",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{4}} },
        route         => "6|10.0.0.0/24|6 3 1",
        expected      => 2,
        name          => "Downstream 8",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{2}} },
        route         => "5|10.0.0.0/24|5 1",
        expected      => 2,
        name          => "Downstream 9",
    },
    {
        aspas         => \%aspa_state,
        provider_asns => { map { $_ => 1 }
                               @{$aspa_state{2}} },
        route         => "5|10.0.0.0/24|5 3 1",
        expected      => 2,
        name          => "Downstream 10",
    },
);

for my $test_case (@test_cases) {
    run_test($test_case);
}
