#!/usr/bin/perl
use strict;
use warnings;

use Test::More;
my $tests;
plan tests => $tests;

use Data::Dumper qw(Dumper);
use English qw( -no_match_vars );

my $warn;
BEGIN {
    $SIG{__WARN__} = sub { $warn = shift; }
}
use Net::RawIP;

{
    if ($EUID) {
        like $warn, qr/Must have EUID == 0/, "root warning seen";
    } else {
        ok(not(defined $warn), "no root warning");
    }
    BEGIN { $tests += 1; }
}
$SIG{__WARN__} = 'DEFAULT';

{
    my $list = ifaddrlist;
    is( ref($list), 'HASH', 'ifaddrlist retursn HASH ref');

    ok(exists $list->{lo}, 'lo interface exists');
    is($list->{lo}, '127.0.0.1', 'lo interface is 127.0.0.1');

    # on my Linux machine this is 
    # lo -> 127.0.0.1
    # eth0 -> 192.168.2.2
    # How can we test it on other machines?

    diag "ifaddrelist returns: " . Dumper $list;
    BEGIN { $tests += 3; }
}

{
    is(rdev('127.0.0.1'), 'lo', 'rdev 127.0.0.1');
    is(rdev('localhost'), 'lo', 'rdev localhost');
    eval {
        rdev('ab cd');
    };
    like($@, qr{host_to_ip: failed}, 'rdev ab cd fails');
    # rdev will fail if there is not network connection
    ok(rdev('cisco.com'), 'rdev cisco.com'); # on my Linux machine this returns eth0
    BEGIN { $tests += 4; }
}


