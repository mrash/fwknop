##############################################################################
#
# File:    03_errors.t
#
# Author:  Damien S. Stuart <dstuart@dstuart.org>
#
# Purpose: Test suite file for FKO perl module functions.
#
##############################################################################
#
use FKO qw(:all);

use Test::More tests => 11;

# Test spa data support vars
#
my (
    $tsd, $tsd_pw, $tsd_rand, $tsd_user, $tsd_time, $tsd_ver,
    $tsd_msg_type, $tsd_msg, $tsd_nat_access, $tsd_server_auth,
    $tsd_client_timeout, $tsd_digest, $tsd_encoded,
    $tsd_digest_type, $tsd_encryption_type
);

# Preset for test
#
my $tuser      = 'bubba';
my $tuser_pw   = 'tsd-bubba';
my $thmac_key  = 'This is bubba\'s HMAC key.';


my $err;

##############################################################################

my $f1_now = time();
my $f1 = FKO->new();

# 1 -Try for invalid encryption type
#
$err = $f1->encryption_type(-11);
ok($err == FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL, "invalid encryption type error test: got($err)");

# 2 -Try for invalid digest type
#
$err = $f1->digest_type(-11);
ok($err == FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL, "invalid digest type error test: got($err)");

# 3 -Try for invalid spa message type
#
$err = $f1->spa_message_type(-11);
ok($err == FKO_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL, "invalid message type error test: got($err)");

# 4-5 - Bad rand value size
#
$err = $f1->rand_value('666');
ok($err == FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL, "rand val small error test: got($err)");
$err = $f1->rand_value('66666666666666666');
ok($err == FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL, "rand val big error test: got($err)");

# 6 - Final with bad data
#
$err = $f1->spa_data_final("xxx");
ok($err == FKO_ERROR_INCOMPLETE_SPA_DATA, "invalid spa_data_final error test: got($err)");

# 7 - Good spa data final for further tests.
#
$f1->spa_message("0.0.0.0,tcp/22");
$f1->encryption_mode(FKO_ENC_MODE_CBC);
$f1->hmac_type(FKO_HMAC_SHA256);

$err = $f1->spa_data_final($tuser_pw, $thmac_key);
ok($err == FKO_SUCCESS, "spa_data_final: got($err)");

# 8-10 - New object from f1 data with good pw, bad pw, then no pw
#
my $f2 = FKO->new($f1->spa_data(), $tuser_pw, FKO_ENC_MODE_CBC, $thmac_key, FKO_HMAC_SHA256);
ok(defined($f2), 'create fko object f2 (good pw)');

$f2->destroy();

$f2 = FKO->new($f1->spa_data(), 'bad_pw', FKO_ENC_MODE_CBC, $thmac_key, FKO_HMAC_SHA256);
is($f2, undef, 'create fko object f2 (bad pw)');

$f2->destroy() if($f2); #Just in case

$f2 = FKO->new($f1->spa_data(), undef, FKO_ENC_MODE_CBC, $thmac_key, FKO_HMAC_SHA256);
ok($f2, 'create fko object f2 (no pw)');

# 11 - Bad decrypt pw
#
$err = $f2->decrypt_spa_data('badpw');
ok($err == FKO_ERROR_DECRYPTION_FAILURE, "decrypt with bad pw: got($err)");



# TODO: add more error tests (and gpg tests and errors).

###EOF###
