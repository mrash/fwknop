#!/usr/bin/perl -w
#
# $Id: Fingerprint.t 389 2005-12-11 22:46:36Z mbr $
#

use strict;

use lib './t';
use MyTest;

use GnuPG::Fingerprint;

my $v1 = '5A29DAE3649ACCA7BF59A67DBAED721F334C9V14';
my $v2 = '4F863BBBA8166F0A340F600356FFD10A260C4FA3';

my $fingerprint = GnuPG::Fingerprint->new( as_hex_string => $v1 );

# deprecation test
TEST
{
    $fingerprint->hex_data() eq $v1;
};

# deprecation test
TEST
{
    $fingerprint->hex_data( $v2 );
    $fingerprint->as_hex_string() eq $v2;
};
