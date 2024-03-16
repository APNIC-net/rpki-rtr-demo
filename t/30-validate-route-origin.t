use strict;
use warnings;

use APNIC::RPKI::RTR::State;
use APNIC::RPKI::Validator::ROA qw(ROV_INVALID ROV_UNKNOWN ROV_VALID);

use Test::More tests => 6;

sub run_test {
    my ($test_case) = @_;

    my $state = APNIC::RPKI::RTR::State->new(
        session_id    => 1,
        serial_number => 1,
        vrps          => $test_case->{vrps},
    );

    my $route = $test_case->{route};
    my $rov_result = APNIC::RPKI::Validator::ROA::validate(
        $state, $route->[0], $route->[1]
    );

    is($rov_result, $test_case->{expected_rov}, $test_case->{name});
}

my @test_cases = (
    {
        "vrps"         => {
            "1" => {
                "1.0.0.0" => {
                    "24" => {
                        "24" => 1
                    }
                }
            }
        },
        "route"        => [ "1", "1.0.0.0/24" ],
        "expected_rov" => ROV_VALID,
        "test_name"    => "Valid rov due to exact route and matching ASN",
    },
    {
        "vrps"         => {
            "1" => {
                "1.0.0.0" => {
                    "23" => {
                        "24" => 1
                    }
                }
            }
        },
        "route"        => [ "1", "1.0.1.0/24" ],
        "expected_rov" => ROV_VALID,
        "test_name"    => "Valid rov due to covering route and matching ASN",
    },
    {
        "vrps"         => {
            "2" => {
                "1.0.0.0" => {
                    "24" => {
                        "24" => 1
                    }
                }
            }
        },
        "route"        => [ "1", "1.0.0.0/24" ],
        "expected_rov" => ROV_INVALID,
        "test_name"    => "Invalid rov due to exact route and non-matching ASN",
    },
    {
        "vrps"         => {
            "2" => {
                "1.0.0.0" => {
                    "23" => {
                        "24" => 1
                    }
                }
            }
        },
        "route"        => [ "1", "1.0.1.0/24" ],
        "expected_rov" => ROV_INVALID,
        "test_name"    => "Invalid rov due to exact route and non-matching ASN",
    },
    {
        "vrps"         => {
            "2" => {
                "1.0.0.0" => {
                    "23" => {
                        "23" => 1
                    }
                }
            }
        },
        "route"        => [ "1", "1.0.1.0/24" ],
        "expected_rov" => ROV_INVALID,
        "test_name"    => "Unknown rov due to non-covering route and" .
            "non-matching ASN",
    },
    {
        "vrps"         => {
            "1" => {
                "1.0.0.0" => {
                    "23" => {
                        "23" => 1
                    }
                }
            }
        },
        "route"        => [ "1", "1.0.1.0/24" ],
        "expected_rov" => ROV_INVALID,
        "test_name"    => "Unknown rov due to non-covering route and" .
            "matching ASN",
    },
);

foreach my $test_case (@test_cases) {
    run_test($test_case);
}