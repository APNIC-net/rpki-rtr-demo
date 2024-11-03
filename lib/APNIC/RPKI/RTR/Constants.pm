package APNIC::RPKI::RTR::Constants;

use warnings;
use strict;

use constant {
    PDU_SERIAL_NOTIFY  => 0,
    PDU_SERIAL_QUERY   => 1,
    PDU_RESET_QUERY    => 2,
    PDU_CACHE_RESPONSE => 3,
    PDU_IPV4_PREFIX    => 4,
    PDU_IPV6_PREFIX    => 6,
    PDU_END_OF_DATA    => 7,
    PDU_CACHE_RESET    => 8,
    PDU_ROUTER_KEY     => 9,
    PDU_ERROR_REPORT   => 10,
    PDU_ASPA           => 11,
    PDU_EXIT           => 255,

    ERR_CORRUPT_DATA                    => 0,
    ERR_INTERNAL_ERROR                  => 1,
    ERR_NO_DATA                         => 2,
    ERR_INVALID_REQUEST                 => 3,
    ERR_UNSUPPORTED_VERSION             => 4,
    ERR_UNSUPPORTED_PDU_TYPE            => 5,
    ERR_WITHDRAWAL_OF_UNKNOWN_RECORD    => 6,
    ERR_DUPLICATE_ANNOUNCEMENT_RECEIVED => 7,
    ERR_UNEXPECTED_PROTOCOL_VERSION     => 8,
    ERR_ASPA_PROVIDER_LIST_ERROR        => 9,
};

use Exporter qw(import);

our @EXPORT = qw(
    PDU_SERIAL_NOTIFY
    PDU_SERIAL_QUERY
    PDU_RESET_QUERY
    PDU_CACHE_RESPONSE
    PDU_IPV4_PREFIX
    PDU_IPV6_PREFIX
    PDU_END_OF_DATA
    PDU_CACHE_RESET
    PDU_ROUTER_KEY
    PDU_ERROR_REPORT
    PDU_ASPA
    PDU_EXIT

    ERR_CORRUPT_DATA
    ERR_INTERNAL_ERROR
    ERR_NO_DATA
    ERR_INVALID_REQUEST
    ERR_UNSUPPORTED_VERSION
    ERR_UNSUPPORTED_PDU_TYPE
    ERR_WITHDRAWAL_OF_UNKNOWN_RECORD
    ERR_DUPLICATE_ANNOUNCEMENT_RECEIVED
    ERR_UNEXPECTED_PROTOCOL_VERSION
    ERR_ASPA_PROVIDER_LIST_ERROR
);

1;
