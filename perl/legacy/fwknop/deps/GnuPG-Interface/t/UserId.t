#!/usr/bin/perl -w
#
# $Id: UserId.t 389 2005-12-11 22:46:36Z mbr $
#

use strict;

use lib './t';
use MyTest;
use GnuPG::UserId;

my $v1 = 'Dekan';
my $v2 = 'Frank Tobin';

my $user_id = GnuPG::UserId->new( as_string => $v1 );

# deprecation test
TEST
{
    $user_id->user_id_string() eq $v1;
};

# deprecation test
TEST
{
    $user_id->user_id_string( $v2 );
    $user_id->as_string() eq $v2;
};
