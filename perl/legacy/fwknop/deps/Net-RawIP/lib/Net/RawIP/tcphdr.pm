package Net::RawIP::tcphdr;
use strict;
use warnings;
our $VERSION = '0.23';
use Class::Struct qw(struct);
our @tcphdr = qw(source dest seq ack_seq doff res1 res2 urg ack psh rst syn
    fin window check urg_ptr data);
struct ( 'Net::RawIP::tcphdr' => [map { $_ => '$' } @tcphdr ] );

1;
