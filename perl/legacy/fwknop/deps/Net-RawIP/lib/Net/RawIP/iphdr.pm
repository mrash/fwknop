package Net::RawIP::iphdr;
use strict;
use warnings;
our $VERSION = '0.23';
use Class::Struct qw(struct);
our @iphdr
    = qw(version ihl tos tot_len id frag_off ttl protocol check saddr daddr);
struct ( 'Net::RawIP::iphdr' => [ map { $_ => '$' } @iphdr ] );

1;
