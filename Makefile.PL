use strict;
use warnings;

use ExtUtils::MakeMaker;
use ExtUtils::MakeMaker::Config;

my $output = WriteMakefile(
    NAME           => 'APNIC::RPKI::RTR::Client',
    AUTHOR         => 'Software <software@apnic.net>',
    LICENSE        => 'bsd',
    VERSION_FROM   => 'lib/APNIC/RPKI/RTR/Client.pm',
    META_MERGE     => {
        resources => {
            repository => 'https://github.com/APNIC-net/rpki-rtr-demo'
        }
    },
    EXE_FILES      => [ qw(bin/rpki-rtr-client
                           bin/rpki-rtr-server
                           bin/rpki-rtr-server-mnt) ],
    PREREQ_PM      => { 'Test::More' => 0 },
);

1;
