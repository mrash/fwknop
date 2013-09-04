##############################################################################
#
# File:    01_functions.t
#
# Author:  Damien S. Stuart <dstuart@dstuart.org>
#
# Purpose: Test suite file for FKO perl module functions.
#
##############################################################################
#
use FKO;

use Test::More tests => 533;

# Test spa data support vars
#
my (
    $tsd, $tsd_pw, $tsd_hmac_key, $tsd_encryption_mode, $tsd_rand,
    $tsd_user, $tsd_time, $tsd_ver, $tsd_msg_type, $tsd_msg,
    $tsd_nat_access, $tsd_server_auth, $tsd_client_timeout,
    $tsd_digest, $tsd_encoded, $tsd_digest_type,
    $tsd_hmac_digest_type, $tsd_encryption_type
);

# Preset for test
#
$tuser      = 'bubba';
$tuser_pw   = 'tsd-bubba';
$thmac_key  = 'This is bubba\'s HMAC key.';

# Defaults
#
my $def_tsd_msg          = '0.0.0.0,tcp/22';
my $def_encryption_type  = FKO::FKO_ENCRYPTION_RIJNDAEL;
my $def_digest_type      = FKO::FKO_DIGEST_SHA256;
my $def_msg_type         = FKO::FKO_ACCESS_MSG;
my $def_hmac_digest_type = FKO::FKO_HMAC_UNKNOWN;
my $def_encryption_mode  = FKO::FKO_ENC_MODE_CBC;

my $test_hmac_key       = '0987654321test this is only a test';

my $test_encryption_mode = $FKO::FKO_ENC_MODE_ECB;
my $test_hmac_type = $FKO::FKO_HMAC_SHA256;

my $err;

##############################################################################

# 1 - Create
#
my $f1_now = time();
my $f1 = FKO->new();
ok($f1, 'Create f1');

# 2-9 - Check defaults exist and are correct value.
#
$tsd_rand = $f1->rand_value();
ok($tsd_rand =~ /^\d{16}$/, 'rand_value format');

$tsd_user = $f1->username();
ok($tsd_user =~ /^\w+/, 'username defined');

$tsd_time = $f1->timestamp();
ok($tsd_time =~ /^\d+$/, 'timestamp format');
ok(($tsd_time - $f1_now) < 2, 'default timestamp value');

$tsd_ver = $f1->version();
ok($tsd_ver =~ /^\d+\.\d+(:?\.\d+)?$/, 'version format');

$tsd_encryption_type = $f1->encryption_type();
ok($tsd_encryption_type == $def_encryption_type, 'default encryption type');

$tsd_digest_type = $f1->digest_type();
ok($tsd_digest_type == $def_digest_type, 'default digest type');

$tsd_msg_type = $f1->spa_message_type();
ok($tsd_msg_type == $def_msg_type, 'default message type');

$tsd_hmac_digest_type = $f1->hmac_type();
ok($tsd_hmac_digest_type == $def_hmac_digest_type, 'HMAC digest type');

$tsd_encryption_mode = $f1->encryption_mode();
ok($tsd_encryption_mode == $def_encryption_mode, 'Encryption mode');

# 10-11 - set and verify username
#
$err = $f1->username($tuser);
ok($err == 0, 'set username');
ok($f1->username() eq $tuser, 'set username value');

# 12-13 - set and verify spa message string
#
$err = $f1->spa_message($def_tsd_msg);
ok($err == 0, 'set spa message');
ok($f1->spa_message() eq $def_tsd_msg, 'set spa message value');

# Set the hmac digest stuff (none here)
$thmac_key = '';

# 14 - Finalize the spa data (encode fields , compute digest, encrypt,
#      and encode all)
#
$err = $f1->spa_data_final($tuser_pw, $thmac_key);
ok($err == 0, 'f1 spa data final');

# 15-16 - Get some of the current spa data for later tests.
#
$tsd = $f1->spa_data();
ok($tsd, 'f1 get spa data');
$tsd_digest = $f1->spa_digest();
ok($tsd_digest, 'f1 get spa digest');

#  17 - create a new object based on the spa data produced by f1.
#
my $f2 = FKO->new($tsd, $tuser_pw, $f1->encryption_mode(),
                  $thmac_key, $def_hmac_digest_type);
ok( $f2 );

# 18-31 - Ensure the f2 fields match the f1 fields
#
compare_fko($f1, $f2, 'f1-f2');

# 32-37 - Change digest_type and timestamp in f1 and recompute, then
#         make a new fko object based on f1's spa_data.
#
$err = $f1->digest_type(FKO::FKO_DIGEST_SHA1);
ok($err == 0, 'f1 set digest to sha1');
is($f1->digest_type(), FKO::FKO_DIGEST_SHA1, 'verify set digest sha1');
ok($f1->timestamp(5) == 0, 'reset timestamp 1');
isnt($f1->timestamp(), $f2->timestamp(), 'verify new timestamp 1');

ok($f1->spa_data_final($tuser_pw, $thmac_key) == 0,
    'f1 recompute spa data 1');

my $f3 = FKO->new($f1->spa_data(), $tuser_pw, $f1->encryption_mode(),
                  $thmac_key, $def_hmac_digest_type);
ok($f3, 'create fko object f3');

# 38-51 - Compare f1 and f3
#
compare_fko($f1, $f3, 'f1-f3');

# 52-57 - Change digest_type and timestamp in f1 and recompute, add an
#         HMAC key, then make a new fko object based on f1's spa_data.
#
$tuser_pw = 'metest';
$thmac_key = 'This is a bogus hmac key - 1234567890';
$tsd_hmac_digest_type = FKO::FKO_HMAC_SHA512;

$err = $f1->digest_type(FKO::FKO_DIGEST_MD5);
ok($err == 0, 'f1 set digest to md5');
is($f1->digest_type(), FKO::FKO_DIGEST_MD5, 'verify set digest md5');

$err = $f1->hmac_type($tsd_hmac_digest_type);
ok($err == 0, 'f1 set set HMAC digest to sha512');
is($f1->hmac_type(), $tsd_hmac_digest_type, 'verify set HMAC digest sha512');

my $tts = $f1->timestamp();
ok($f1->timestamp(10) == 0, 'reset timestamp 2');
isnt($f1->timestamp(), $tts, 'verify new timestamp 2');

ok($f1->spa_data_final($tuser_pw, $thmac_key) == 0,
    'f2 recompute spa data 1');

my $f4 = FKO->new($f1->spa_data(), $tuser_pw, $f1->encryption_mode(),
                  $thmac_key, $tsd_hmac_digest_type);
ok($f4, 'create fko object f4');

# 58-71 - Compare f1 and f4
#
compare_fko($f1, $f4, 'f1-f4');

# Clean up what we have so far
#
$f1->destroy();
$f2->destroy();
$f3->destroy();
$f4->destroy();

### General function tests.

# A fresh object to work with.
#
$f1 = FKO->new();
ok($f1, 'Create f1 #2');

# Force rand value.
#
ok($f1->rand_value('0123456789012345') == 0, 'force rand value');
is($f1->rand_value(), '0123456789012345', 'verify force rand_value');

# Iterate over setting message type
#
my @msg_types = (
    FKO::FKO_COMMAND_MSG,
    FKO::FKO_ACCESS_MSG,
    FKO::FKO_NAT_ACCESS_MSG,
    FKO::FKO_CLIENT_TIMEOUT_ACCESS_MSG,
    FKO::FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG,
    FKO::FKO_LOCAL_NAT_ACCESS_MSG,
    FKO::FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG
);

foreach my $mt ( @msg_types ) {
    ok($f1->spa_message_type($mt) == 0, "set msg_type to $mt");
    is($f1->spa_message_type(), $mt, "verify msg_type is $mt");
}

# SPA message
#
ok($f1->spa_message('1.1.1.1,udp/111') == 0, 'set spa message');
is($f1->spa_message(), '1.1.1.1,udp/111', 'verify spa message');

# Nat Access
#
ok($f1->spa_nat_access('1.2.1.1,211') == 0, 'set nat_access message');
is($f1->spa_nat_access(), '1.2.1.1,211', 'verify nat_access message');

# Server Auth
#
ok($f1->spa_server_auth('crypt,bubba') == 0, 'set server_auth message');
is($f1->spa_server_auth(), 'crypt,bubba', 'verify server_auth message');

# Client Timeout
#
ok($f1->spa_client_timeout(666) == 0, 'set client_timeout');
is($f1->spa_client_timeout(), 666, 'verify client_timeout');

# Now iterate over the various digest types and hmac digest types and
# Generate spa data for each.
#
#    @DIGEST_TYPES,         (1-5)
#    @HMAC_DIGEST_TYPES,    (1-5)
#    @ENCRYPTION_TYPES,     (1)
#    @ENCRYPTION_MODES,     (1-8)
foreach my $hmac_type (1..5) {
    next if($hmac_type < 1);
    ok($f1->hmac_type($hmac_type) == 0, "set HMAC type: $hmac_type");
    foreach my $digest_type (1..5) {
        next if($digest_type < 1);
        ok($f1->digest_type($digest_type) == 0, "set digest type: $digest_type");
        foreach my $enc_mode (1..8) {
            ok($f1->encryption_mode($enc_mode) == 0, "set encryption mode: $enc_mode");
            ok($f1->spa_data_final($tuser_pw, $test_hmac_key) == 0,
                "spad_data_final (HAMC:$hmac_type, DIGEST:$digest_type), ENC_MODE: $enc_mode");
        }
    }
}

##############################################################################

# Compare fko object fields for equality
# Runs 14 tests.
#
sub compare_fko {
    my ($fko1, $fko2, $tn) = @_;

    is($fko1->encryption_type(), $fko2->encryption_type(), "$tn encryption_type compare");
    is($fko1->digest_type(), $fko2->digest_type(), "$tn digest_type compare");
    is($fko1->rand_value(), $fko2->rand_value(), "$tn rand value compare");
    is($fko1->username(), $fko2->username(), "$tn username compare");
    is($fko1->timestamp(), $fko2->timestamp(), "$tn timestamp compare");
    is($fko1->version(), $fko2->version(), "$tn version compare");
    is($fko1->spa_message_type(), $fko2->spa_message_type(), "$tn spa_message_type compare");
    is($fko1->spa_message(), $fko2->spa_message(), "$tn spa_message compare");
    is($fko1->spa_nat_access(), $fko2->spa_nat_access(), "$tn spa_nat_access compare");
    is($fko1->spa_server_auth(), $fko2->spa_server_auth(), "$tn spa_server_auth compare");
    is($fko1->spa_client_timeout(), $fko2->spa_client_timeout(), "$tn spa_client_timeout compare");
    is($fko1->spa_digest(), $fko2->spa_digest(), "$tn spa_digest compare");
    is($fko1->encoded_data(), $fko2->encoded_data(), "$tn encoded_data compare");
    is($fko1->hmac_type(), $fko2->hmac_type(), "$tn hmac_type compare");
    is($fko1->encryption_mode(), $fko2->encryption_mode(), "$tn encryption_mode compare");
    # Using fko->new_with_data() does not recreate the hmac and append it to
    # spa data so we don't inlcude it in this check.
    #is($fko1->spa_data(), $fko2->spa_data(), "$tn spa_data compare");
}

sub create
###EOF###
