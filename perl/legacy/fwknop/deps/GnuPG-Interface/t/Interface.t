#!/usr/bin/perl -w
#
# $Id: Interface.t 389 2005-12-11 22:46:36Z mbr $
#

use strict;

use lib './t';
use MyTest;

use GnuPG::Interface;

my $v1 = 'gpg';
my $v2 = 'gnupg';

my $gnupg = GnuPG::Interface->new( call => $v1 );

# deprecation test
TEST
{
    $gnupg->gnupg_call() eq $v1;
};

# deprecation test
TEST
{
    $gnupg->gnupg_call( $v2 );
    $gnupg->call() eq $v2;
};
