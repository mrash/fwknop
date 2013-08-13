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
my $test_spa_data = '';
my $test_spa_data_pw = 'test1234567890';
my $test_hmac_key    = '0987654321test this is only a test';

my $test_encryption_mode = $FKO::FKO_ENC_MODE_ECB;
my $test_hmac_type = $FKO::FKO_HMAC_SHA256;

my $test_spa_data_pw_len = length($test_spa_data_pw);
my $test_hmac_key_len = length($test_hmac_key);

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
my $f2 = FKO->new($test_spa_data, $test_spa_data_pw, $test_spa_data_pw_len,
				  $test_encryption_mode, $test_hmac_key, $test_hmac_key_len,
				  $test_hmac_type);
isa_ok( $f2, 'FKO' );


# 6 - Destroy full
#
$f2->destroy();
ok(!defined($f2->{_ctx}));

###EOF###
