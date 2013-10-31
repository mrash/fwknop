##############################################################################
#
# File:    04_fuzzing.t
#
# Author:  Damien S. Stuart <dstuart@dstuart.org>, Michael Rash <mbr@cipherdyne.org>
#
# Purpose: Test suite file for FKO perl module fuzzing.  These tests are
#          useful not only to verify proper FKO operations under maliciously
#          contructed data, but also to do so running under Test::Valgrind
#          for proper memory usage testing.
#
##############################################################################
#
use FKO;

use Test::More tests => 593;

my $err;

##############################################################################

# Fuzzing data
my @fuzz_msg_types = (
    -1,
    -2,
    255,
);

my @fuzz_digest_types = (
    -1,
    -2,
    255,
);

my @fuzzing_client_timeouts = (
    -1,
    -10,
    -10000,
);

my @fuzzing_usernames = (
    'A'x1000,
    "-1",
    -1,
    '123%123',
    '123$123',
    '-user',
    '_user',
    '-User',
    ',User',
    'part1 part2',
    'a:b',
);

my @fuzzing_nat_access_msgs = (
    '1.2.3.4',
    '-1.2.3.4',
    '1.2.3.4.',
    '123.123.123.123',
    '923.123.123.123',
    '123.123.123.123.',
    '999.999.999.999',
    '1.2.3.4,tcp/2a2',
    '1.2.3.4,tcp/22,',
    '-1.2.3.4,tcp/22',
    '1.2.3.4,tcp/123456',
    '1.2.3.4,tcp/123456' . '9'x100,
    '1.2.3.4,tcp//22',
    '1.2.3.4,tcp/22/',
    'a23.123.123.123,tcp/12345',
    '999.999.999.999,tcp/22',
    '999.1.1.1,tcp/22',
    -1,
    1,
    'A',
    0x0,
    'A'x1000,
    '/'x1000,
    '%'x1000,
    ':'x1000,
    pack('a', ""),
    '',
    '1.1.1.p/12345',
    '1.1.1.2,,,,12345',
    '1.1.1.2,icmp/123',
    ',,,',
    '----',
    '1.3.4.5.5',
    '1.3.4.5,' . '/'x100,
    '1.3.4.5,' . '/'x100 . '22',
    '1.2.3.4,rcp/22',
    '1.2.3.4,udp/-1',
    '1.2.3.4,tcp/-1',
    '1.2.3.4,icmp/-1',
    pack('a', "") . '1.2.3.4,tcp/22',
    '1' . pack('a', "") . '.2.3.4,tcp/22',
    '1.2.3' . pack('a', "") . '.4,tcp/22',
    '1.2.3.' . pack('a', "") . '4,tcp/22',
    '1.2.3.4' . pack('a', "") . ',tcp/22',
    '1.2.3.4,' . pack('a', "") . 'tcp/22',
    '1.2.3.4,t' . pack('a', "") . 'cp/22',
    '1.2.3.4,tc' . pack('a', "") . 'p/22',
    '1.2.3.4,tcp' . pack('a', "") . '/22',
    '1.2.3.4,tcp/' . pack('a', "") . '22',
    '123.123.123' . pack('a', "") . '.123,tcp/22',
    '123.123.123.' . pack('a', "") . '123,tcp/22',
    '123.123.123.1' . pack('a', "") . '23,tcp/22',
    '123.123.123.12' . pack('a', "") . '3,tcp/22',
    '123.123.123.123' . pack('a', "") . ',tcp/22',
    '123.123.123.123,' . pack('a', "") . 'tcp/22',
    '123.123.123.123,t' . pack('a', "") . 'cp/22',
    '123.123.123.123,tc' . pack('a', "") . 'p/22',
    '123.123.123.123,tcp' . pack('a', "") . '/22',
    '123.123.123.123,tcp/' . pack('a', "") . '22',
    '1.2.3.4,t' . pack('a', "") . 'cp/22',
    '1.1.1.1,udp/1,tap/1,tcp/2,udp/3,tcp/4,tcp/12345',
    '1.1.1.1,udp/1,tcp/-11,tcp/2,udp/3,tcp/4,tcp/12345',
    '1.1.1.1,udp/1,tcp/1,tcp/2udp/3,tcp/4,tcp/12345',
    '1.1.1.1,udp/1,tcp/1,tcp/2,udp/3,tcp/4,tcp////12345',
    '1.1.1.1,udp/1,tcp/1,tcp/2udp/3,tcp/4,tcp////12345',
    '1.1.1.1,udp/1,tcp/1,tcp/2udp/3,tcp/4,tcp////12345',
    '1.1.1.1,udp/1,tcp/1,tcp/2udp/3*tcp/4,tcp////12345',
    '1.1.1.1,udp/1,tcp/1,tcp/2udp/3,tcb/4,tcp////12345',
    '1.1.1.1,udp/1,tcp/1tcp/2udp/3,tcp/4,tcp////12345',
    '123.123.123.123udp/1,tcp/1,tcp/2udp/3,tcp/4,tcp////12345////////////',
);

my @fuzzing_cmd_msgs = (
    ### must start with a valid IP, so test this
    -1,
    1,
    'A',
    0x0,
    'A'x1000,
    '/'x1000,
    '%'x1000,
    ':'x1000,
    '',
    pack('a', ""),
    ',,,',
    '----',
    '1.3.4.5.5',
    '999.3.4.5',
    '1.,',
    '1.2.,',
    '1.2.3.,',
    '1.2.3.4',
    '123.123.123.123',
    '1.2.3.4,',
    '1.2.3.4.',
    '123.123.123.123,' . 'A'x1000,
);

my @fuzzing_server_auth = (
    '',
    pack('a', ""),
    'A'x1000
);

my @fuzzing_enc_keys = (
    pack('a', "")x33,
    pack('a', "") . 'A'x32,
    'A'x32 . pack('a', ""),
    'A'x33,
    'A'x34,
    'A'x128,
    'A'x1000,
    'A'x2000,
    'asdfasdfsafsdafasdfasdfsafsdaffdjskalfjdsklafjsldkafjdsajdkajsklfdafsklfjjdkljdsafjdjd' .
    'sklfjsfdsafjdslfdkjdljsajdskjdskafjdldsljdkafdsljdslafdslaldldajdskajlddslajsl',
);

my @fuzzing_hmac_keys = (
    pack('a', "")x129,
    pack('a', "") . 'A'x128,
    'A'x128 . pack('a', ""),
    'A'x129,
    'A'x1000,
    'A'x2000,
);

# 1 - Create
#
$f1 = FKO->new();
ok($f1, 'Create f1');

# Iterate over setting invalid message types
#
foreach my $mt ( @fuzz_msg_types ) {
    ok($f1->spa_message_type($mt) == FKO::FKO_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL,
        "set invalid msg_type to $mt");
    isnt($f1->spa_message_type(), $mt, "verify msg_type is not $mt");
}

foreach my $dt ( @fuzz_digest_types ) {
    ok($f1->digest_type($dt) == FKO::FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL,
        "set invalid digest type to $dt");
    isnt($f1->digest_type(), $dt, "verify digest type is not $dt");
}

foreach my $dt ( @fuzz_digest_types ) {
    ok($f1->hmac_type($dt) == FKO::FKO_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL,
        "set invalid hmac type to $dt");
    isnt($f1->hmac_type(), $dt, "verify hmac type is not $dt");
}

# Iterate over setting invalid client timeouts
#
foreach my $tout ( @fuzzing_client_timeouts ) {
    ok($f1->spa_client_timeout($tout) == FKO::FKO_ERROR_INVALID_DATA_CLIENT_TIMEOUT_NEGATIVE,
        "set invalid client timeout to $tout");
    isnt($f1->spa_client_timeout(), $tout, "verify client timeout is not $tout");
}

# Iterate over setting invalid usernames
#
foreach my $user ( @fuzzing_usernames ) {
    $err = $f1->username($user);
    ok((length($user) > 100 ### long users get truncated
            or $err == FKO::FKO_ERROR_INVALID_DATA_USER_MISSING
            or $err == FKO::FKO_ERROR_INVALID_DATA_USER_FIRSTCHAR_VALIDFAIL
            or $err == FKO::FKO_ERROR_INVALID_DATA_USER_REMCHAR_VALIDFAIL),
        "set invalid username to $user");
    isnt($f1->username(), $user, "verify username is not $user");
}

# SPA message fuzzing
#
foreach my $msg ( @fuzzing_nat_access_msgs ) {  ### use the NAT fuzzing messages
    $err = $f1->spa_message($msg);
    ok(($err == FKO::FKO_ERROR_INVALID_DATA_MESSAGE_ACCESS_MISSING
            or $err == FKO::FKO_ERROR_INVALID_SPA_ACCESS_MSG
            or $err == FKO::FKO_ERROR_INVALID_ALLOW_IP
            or $err == FKO::FKO_ERROR_DATA_TOO_LARGE
            or $err == FKO::FKO_ERROR_INVALID_DATA_MESSAGE_EMPTY
            or $err == FKO::FKO_ERROR_INVALID_DATA_MESSAGE_PORTPROTO_MISSING
            or $err == FKO::FKO_ERROR_INVALID_DATA_MESSAGE_PORT_MISSING),
        "set invalid access message to $msg");
    isnt($f1->spa_message(), $msg, "verify access message is not $msg");
}

# Nat Access message fuzzing
#
foreach my $msg ( @fuzzing_nat_access_msgs ) {
    $err = $f1->spa_nat_access($msg);
    ok(($err == FKO::FKO_ERROR_INVALID_DATA_NAT_EMPTY
            or $err == FKO::FKO_ERROR_DATA_TOO_LARGE
            or $err == FKO::FKO_ERROR_INVALID_DATA_MESSAGE_NAT_MISSING
            or $err == FKO::FKO_ERROR_INVALID_SPA_NAT_ACCESS_MSG
            or $err == FKO::FKO_ERROR_MEMORY_ALLOCATION),
        "set invalid nat access message to $msg");
    isnt($f1->spa_nat_access(), $msg, "verify nat access message is not $msg");
}

# Command message fuzzing, must set message type first
#
$f1->spa_message_type(FKO::FKO_COMMAND_MSG);
foreach my $msg ( @fuzzing_cmd_msgs ) {
    $err = $f1->spa_message($msg);
    ok(($err == FKO::FKO_ERROR_INVALID_DATA_MESSAGE_CMD_MISSING
            or $err == FKO::FKO_ERROR_INVALID_SPA_COMMAND_MSG
            or $err == FKO::FKO_ERROR_INVALID_DATA_MESSAGE_EMPTY
            or $err == FKO::FKO_ERROR_DATA_TOO_LARGE
            or $err == FKO::FKO_ERROR_MEMORY_ALLOCATION),
        "set invalid command message to $msg");
    isnt($f1->spa_message(), $msg, "verify command message is not $msg");
}

# Server Auth fuzzing
#
$f1->spa_message_type(FKO::FKO_ACCESS_MSG);
foreach my $msg ( @fuzzing_server_auth ) {
    $err = $f1->spa_server_auth($msg);
    ok(($err == FKO::FKO_ERROR_INVALID_DATA_SRVAUTH_MISSING
            or $err == FKO::FKO_ERROR_DATA_TOO_LARGE),
        "set invalid server auth message to $msg");
    isnt($f1->spa_server_auth(), $msg, "verify server auth message is not $msg");
}

# Clean up
#
$f1->destroy();

# Test encryption and hmac keys
#
foreach my $key ( @fuzzing_enc_keys ) {
    $f1 = FKO->new();
    ok($f1, 'f1 encryption key fuzzing');
    ok($f1->spa_message('1.2.3.4,tcp/22') == FKO::FKO_SUCCESS, 'set spa_message');
    ok($f1->spa_data_final($key, '') != FKO::FKO_SUCCESS, "encrypt under invalid key: $key");
    $f1->destroy();
}

foreach my $hmac_key ( @fuzzing_hmac_keys ) {
    $f1 = FKO->new();
    ok($f1, 'f1 HMAC key fuzzing');
    ok($f1->spa_message('1.2.3.4,tcp/22') == FKO::FKO_SUCCESS, 'set spa_message');
    ok($f1->hmac_type(FKO::FKO_HMAC_SHA256) == FKO::FKO_SUCCESS, 'set HMAC algorithm');
    ok($f1->spa_data_final('testenckey', $hmac_key) != FKO::FKO_SUCCESS, "HMAC under invalid key: $hmac_key");
    $f1->destroy();
}

my $valid_enc_key  = 'A'x32;
my $valid_hmac_key = 'A'x128;
$f1 = FKO->new();
ok($f1, 'f1 valid encryption key NULL fuzzing');
ok($f1->spa_message('1.2.3.4,tcp/22') == FKO::FKO_SUCCESS, 'set spa_message');
$f1->encryption_mode(FKO::FKO_ENC_MODE_CBC);
$f1->hmac_type(FKO::FKO_HMAC_SHA256);
$err = $f1->spa_data_final($valid_enc_key, $valid_hmac_key);
ok($err == FKO::FKO_SUCCESS, "spa_data_final: got($err)");

# Test valid encryption key that is altered with embedded NULL bytes
#
for (my $i=0; $i<32; $i++) {
    my $bad_key = '';
    for (my $j=0; $j < $i; $j++) {
        $bad_key .= 'A';
    }
    $bad_key .= pack('A', "");
    for (my $j=$i+1; $j < 32; $j++) {
        $bad_key .= 'A';
    }
    my $f2 = FKO->new($f1->spa_data(), $bad_key, FKO::FKO_ENC_MODE_CBC, $valid_hmac_key, FKO::FKO_HMAC_SHA256);
    is($f2, undef, 'create fko object f2 (bad pw)');
    $f2->destroy() if $f2;
}

my $bad_key = 'A'x32 . pack('A', "");
my $f2 = FKO->new($f1->spa_data(), $bad_key, FKO::FKO_ENC_MODE_CBC, $valid_hmac_key, FKO::FKO_HMAC_SHA256);
is($f2, undef, 'create fko object f2 (bad pw)');
$f2->destroy() if $f2;

# Test valid HMAC key that is altered with embedded NULL bytes
#
for (my $i=0; $i<128; $i++) {
    my $bad_key = '';
    for (my $j=0; $j < $i; $j++) {
        $bad_key .= 'A';
    }
    $bad_key .= pack('A', "");
    for (my $j=$i+1; $j < 128; $j++) {
        $bad_key .= 'A';
    }
    my $f2 = FKO->new($f1->spa_data(), $valid_enc_key, FKO::FKO_ENC_MODE_CBC, $bad_key, FKO::FKO_HMAC_SHA256);
    is($f2, undef, 'create fko object f2 (bad HMAC key)');
    $f2->destroy() if $f2;
}

$bad_key = 'A'x128 . pack('A', "");
$f2 = FKO->new($f1->spa_data(), $valid_enc_key, FKO::FKO_ENC_MODE_CBC, $bad_key, FKO::FKO_HMAC_SHA256);
is($f2, undef, 'create fko object f2 (bad HMAC key)');
$f2->destroy() if $f2;

$f1->destroy();

##############################################################################

sub create
###EOF###
