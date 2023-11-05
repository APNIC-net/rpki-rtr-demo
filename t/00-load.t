#!/usr/bin/perl

use warnings;
use strict;

use Test::More tests => 2;

BEGIN {
    use_ok("APNIC::RPKI::RTR::Client");
    use_ok("APNIC::RPKI::RTR::Server");
}

1;
