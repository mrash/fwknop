#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper qw(Dumper);
use English qw( -no_match_vars );
use Test::More;
my $tests;
plan tests => $tests;

my $warn;
BEGIN {
    $SIG{__WARN__} = sub { $warn = shift };
}

use Net::RawIP 		qw{ :pcap 	};

{
    if ($EUID) {
        like $warn, qr/Must have EUID == 0/, "root warning seen";
    } else {
        ok(not(defined $warn), "no root warning");
    }
    BEGIN { $tests += 1; }
}
$SIG{__WARN__} = 'DEFAULT';


is( test_undef(), 1, 'no_undefs' );
BEGIN { $tests += 1; }


sub test_undef {
	my $raw = Net::RawIP->new({
		icmp =>	{}
	});

	$raw->set({
		icmp => {
			type 	=> 8, 
			id 		=> $$
		},
	});

	return 0 if grep {!defined($_)} @{ $raw->{icmphdr} };

	return 1;
}
