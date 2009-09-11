#!/usr/bin/perl -w

use strict;
use lib '..','../blib/lib','.','./blib/lib';

sub test;

my (@mods,@pads,@in,$pad,$test_data,$mod,$tnum,$c,$i,$p);

@mods = qw/Rijndael
           Blowfish
           Blowfish_PP
           IDEA
           DES
          /;
@pads = qw/standard oneandzeroes space null/;

for $mod (@mods) {
   eval "use Crypt::$mod(); 1" && push @in,$mod;
}

unless ($#in > -1) {
   print "1..0 # Skipped: no cryptographic modules found\n";
   exit;
}

print '1..', 128*($#in + 1) * ($#pads + 1) + 1, "\n";

sub test {
    local($^W) = 0;
    my($num, $true,$msg) = @_;
    $$num++;
    print($true ? "ok $$num\n" : "not ok $$num $msg\n");
}

$tnum = 0;

eval "use Crypt::CBC";
test(\$tnum,!$@,"Couldn't load module");

for my $mod (@in) {
  for my $pad (@pads) {
    my $cipher = Crypt::CBC->new(-key     => 'secret',
				 -cipher  => $mod,
				 -padding => $pad,
				);
    for my $length (1..128) {
      my $test_data = 'a'x$length . '0';
      my $encrypted = $cipher->encrypt_hex($test_data);
      my $decrypted = $cipher->decrypt_hex($encrypted);
      test(\$tnum,$test_data eq $decrypted,"$mod/$pad: match failed on zero-terminated data length $length");
    }
  }
}

