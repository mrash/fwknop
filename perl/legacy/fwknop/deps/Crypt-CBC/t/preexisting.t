#!/usr/local/bin/perl

use strict;
use lib '..','../blib/lib','.','./blib/lib';

my (@mods,$cipherclass,$i,$c,$p,$test_data);

@mods = qw/Eksblowfish
	   Rijndael
           Blowfish
           Blowfish_PP
           IDEA
           DES
          /;

for my $mod (@mods) {
  if (eval "use Crypt::$mod(); 1") {
    $cipherclass = "Crypt::$mod";
    warn "Using $cipherclass for test\n";
    last;
  }
}

unless ($cipherclass) {
    print "1..0 # Skipped: No cryptographic module suitable for testing\n";
    exit;
}

print "1..33\n";

sub test {
    local($^W) = 0;
    my($num, $true,$msg) = @_;
    print($true ? "ok $num\n" : "not ok $num $msg\n");
}

$test_data = <<END;
Mary had a little lamb,
Its fleece was black as coal,
And everywere that Mary went,
That lamb would dig a hole.
END
    ;

eval "use Crypt::CBC";

test(1,!$@,"Couldn't load module");
my $bs = eval{$cipherclass->blocksize} || 8;
my $ks = eval{$cipherclass->keysize}   || $bs;

my $key    = Crypt::CBC->_get_random_bytes($ks);
my $cipher = $cipherclass eq 'Crypt::Eksblowfish' ? $cipherclass->new(8,Crypt::CBC->_get_random_bytes(16),$key) : $cipherclass->new($key);

test(2,$i = Crypt::CBC->new(-cipher=>$cipher),"Couldn't create new object");
test(3,$c = $i->encrypt($test_data),"Couldn't encrypt");
test(4,$p = $i->decrypt($c),"Couldn't decrypt");
test(5,$p eq $test_data,"Decrypted ciphertext doesn't match plaintext");

# now try various truncations of the whole
for (my $c=1;$c<=7;$c++) {
  substr($test_data,-$c) = '';  # truncate
  test(5+$c,$i->decrypt($i->encrypt($test_data)) eq $test_data);
}

# now try various short strings
for (my $c=0;$c<=18;$c++) {
  $test_data = 'i' x $c;
  test (13+$c,$i->decrypt($i->encrypt($test_data)) eq $test_data);
}


# make sure that strings that end in spaces or nulls are treated correctly
$test_data = "This string ends in a null\0";
test (32,$i->decrypt($i->encrypt($test_data)) eq $test_data);

$test_data = "This string ends in some spaces  ";
test (33,$i->decrypt($i->encrypt($test_data)) eq $test_data);
