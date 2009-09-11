#!/usr/local/bin/perl

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

# ($#in + 1): number of installed modules
# ($#pads + 1): number of padding methods
# 32: number of per-module, per-pad tests
# 1: the first test -- loading Crypt::CBC module

print '1..', ($#in + 1) * ($#pads + 1) * 32 + 1, "\n";

sub test {
    local($^W) = 0;
    my($num, $true,$msg) = @_;
    $$num++;
    print($true ? "ok $$num\n" : "not ok $$num $msg\n");
}

$tnum = 0;

eval "use Crypt::CBC";
test(\$tnum,!$@,"Couldn't load module");

for $mod (@in) {
   for $pad (@pads) {

      $test_data = <<END;
Mary had a little lamb,
Its fleece was black as coal,
And everywere that Mary went,
That lamb would dig a hole.
END
    ;

      test(\$tnum,$i = Crypt::CBC->new(-key => 'secret',
				       -cipher => $mod,
				       -padding => $pad,
                                      ),
                                      "Couldn't create new object");

      test(\$tnum,$c = $i->encrypt($test_data),"Couldn't encrypt");
      test(\$tnum,$p = $i->decrypt($c),"Couldn't decrypt");
      test(\$tnum,$p eq $test_data,"Decrypted ciphertext doesn't match plaintext");

# now try various truncations of the whole string.
# iteration 3 ends in ' ' so 'space should fail

      for ($c=1;$c<=7;$c++) {

         substr($test_data,-$c) = '';

         if ($c == 3 && $pad eq 'space') {
            test(\$tnum,$i->decrypt($i->encrypt($test_data)) ne $test_data);
         } else {
            test(\$tnum,$i->decrypt($i->encrypt($test_data)) eq $test_data);
         }
      }

# try various short strings

      for ($c=0;$c<=18;$c++) {
        $test_data = 'i' x $c;
        test(\$tnum,$i->decrypt($i->encrypt($test_data)) eq $test_data);
      }

# 'space' should fail. others should succeed.

      $test_data = "This string ends in some spaces  ";

      if ($pad eq 'space') { 
         test(\$tnum,$i->decrypt($i->encrypt($test_data)) ne $test_data);
      } else {
         test(\$tnum,$i->decrypt($i->encrypt($test_data)) eq $test_data);
      }

# 'null' should fail. others should succeed.

      $test_data = "This string ends in a null\0";

      if ($pad eq 'null') { 
         test(\$tnum,$i->decrypt($i->encrypt($test_data)) ne $test_data);
      } else {
         test(\$tnum,$i->decrypt($i->encrypt($test_data)) eq $test_data);
      }
   }
}
