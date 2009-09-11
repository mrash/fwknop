package Net::RawIP::udphdr;
use strict;
use warnings;
our $VERSION = '0.23';
use Class::Struct qw(struct);
our @udphdr = qw(source dest len check data);
struct ( 'Net::RawIP::udphdr' => [map { $_ => '$' } @udphdr ] );

1;
