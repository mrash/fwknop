package Net::RawIP::ethhdr;
use strict;
use warnings;
our $VERSION = '0.23';
use Class::Struct qw(struct);
our @ethhdr = qw(dest source proto);
struct ( 'Net::RawIP::ethhdr' => [map { $_ => '$' } @ethhdr ] );

1;
