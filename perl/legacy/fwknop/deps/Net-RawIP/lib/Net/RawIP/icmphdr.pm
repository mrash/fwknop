package Net::RawIP::icmphdr;
use strict;
use warnings;
our $VERSION = '0.23';
use Class::Struct qw(struct);
our @icmphdr = qw(type code check gateway id sequence unused mtu data);
struct ( 'Net::RawIP::icmphdr' => [map { $_ => '$' } @icmphdr ] );

1;
