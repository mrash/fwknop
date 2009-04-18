##############################################################################
#
# File:    00_init.t
#
# Author:  Damien S. Stuart <dstuart@dstuart.org>
#
# Purpose: Test suite file for FKO perl module init functionality.
#
##############################################################################
#
use Test::More tests => 6;

# 1 - Use test.
#
BEGIN { use_ok('FKO') };

# Test support vars
#
my $test_spa_data = '/6jQlii54itZX2d7uQb0CzKgBEKk9T9dOD5COpZM6tdL7I95+GXvbjBgCoDObwTpBSWGEPPEpLmiVIe0iQoEMRT4bDWindoHopxggByzr3aOToQZAhBgEIsMfC+ucz6sragIieQORkmr3OjtOAHI1hZjSMXadiXKo';

my $test_spa_data_pw = 'sdf';

##############################################################################

# 2 - Require test
require_ok( FKO );

# 3 - Init empty
#
my $f1 = FKO->new();
isa_ok( $f1, 'FKO' );

# 4 - Destroy empty
#
$f1->destroy();
ok(!defined($f1->{_ctx}));

# 5 - Init with data
#
my $f2 = FKO->new($test_spa_data, $test_spa_data_pw);
isa_ok( $f2, 'FKO' );

# 6 - Destroy full
#
$f2->destroy();
ok(!defined($f2->{_ctx}));

###EOF###
