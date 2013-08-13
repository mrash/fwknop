##############################################################################
#
# File:    01_constants.t
#
# Author:  Damien S. Stuart <dstuart@dstuart.org>
#
# Purpose: Test suite file for FKO perl module functions.
#
##############################################################################
#
BEGIN {
    use FKO qw(:all);
    our $tc_total = scalar(@FKO::MSG_TYPES)
                  + scalar(@FKO::DIGEST_TYPES)
                  + scalar(@FKO::HMAC_DIGEST_TYPES)
                  + scalar(@FKO::ENCRYPTION_TYPES)
                  + scalar(@FKO::ENCRYPTION_MODE)
                  + scalar(@FKO::ERROR_CODES);
}

use Test::More tests => $tc_total + 1;

my $tc_cnt = 0;

# Message type constants
#
foreach my $mt (@FKO::MSG_TYPES) {
    $tc_cnt++;
    my $val = eval $mt;
    ok(defined($val), "Message Type Constant: $mt");
} 

# Digest type constants
#
foreach my $dt (@FKO::DIGEST_TYPES) {
    $tc_cnt++;
    my $val = eval $dt;
    ok(defined($val), "Digest Type Constant: $dt");
} 

# HMAC digest type constants
#
foreach my $dt (@FKO::HMAC_DIGEST_TYPES) {
    $tc_cnt++;
    my $val = eval $dt;
    ok(defined($val), "HMAC digest Type Constant: $dt");
} 

# Encryption type constants
#
foreach my $et (@FKO::ENCRYPTION_TYPES) {
    $tc_cnt++;
    my $val = eval $et;
    ok(defined($val), "Encryption Type Constant: $et");
} 

# Encryption mode constants
#
foreach my $et (@FKO::ENCRYPTION_MODE) {
    $tc_cnt++;
    my $val = eval $et;
    ok(defined($val), "Encryption Mode Constant: $et");
} 

# - Encryption type constants
#
foreach my $ec (@FKO::ERROR_CODES) {
    $tc_cnt++;
    my $val = eval $ec;
    ok(defined($val), "Error Code Constant: $ec");
} 

# Did we test all of the constants?
#
is($tc_total, $tc_cnt, "Expected $tc_total constants: found $tc_cnt");

###EOF###
