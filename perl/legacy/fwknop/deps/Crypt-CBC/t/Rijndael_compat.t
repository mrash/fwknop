#!/usr/local/bin/perl

use strict;
use lib '..','../blib/lib','.','./blib/lib';

my ($i, $j, $test_data);

eval "use Crypt::Rijndael";
if ($@) {
    print "1..0 # Skipped: Crypt::Rijndael not installed\n";
    exit;
}

print "1..59\n";

sub test {
    local($^W) = 0;
    my($num, $true,$msg) = @_;
    print($true ? "ok $num\n" : "not ok $num $msg\n");
}

sub pad {
   my ($s,$decrypt) = @_;
   if ($decrypt eq 'd') {
     $s =~ s/10*$//s;
   } else {
      $s .= '1' . ('0' x (16 - length($s) % 16 - 1) );
   }
   return $s;
}

$test_data = <<END;
Mary had a little lamb,
Its fleece was black as coal,
And everywere that Mary went,
That lamb would dig a hole.
END
    ;

eval "use Crypt::CBC";

my $bs = Crypt::Rijndael->blocksize;
my $ks = Crypt::Rijndael->keysize;

test(1,!$@,"Couldn't load module");
test(2,$i = Crypt::CBC->new(-key         => 'a' x $ks,
			    -cipher      => 'Rijndael',
			    -iv          => 'f' x $bs,
			    -literal_key => 1,
			    -header      => 'none',
			    -padding     => 'rijndael_compat',
                           ),
                           "Couldn't create new object");
test(3,$j = Crypt::Rijndael->new('a' x $ks, Crypt::Rijndael->MODE_CBC),
                           "Couldn't create new object");
test(4,$j->set_iv('f' x $bs));

test(5,$i->decrypt($i->encrypt($test_data)) eq $j->decrypt($j->encrypt($test_data)),"Decrypt doesn't match");

test(6,$i->decrypt($j->encrypt($test_data)) eq $test_data,"Crypt::CBC can't decrypt Rijndael encryption");

test(7,$j->decrypt($i->encrypt($test_data)) eq $test_data,"Rijndael can't decrypt Crypt::CBC encryption");

# now try various truncations of the whole
my $t = $test_data;
for (my $c=1;$c<=7;$c++) {
  substr($t,-$c) = '';  # truncate
  test(7+$c,$t eq pad($i->decrypt($j->encrypt(pad($t,'e'))),'d'),"Crypt::CBC can't decrypt Rijndael encryption");
}

$t = $test_data;
for (my $c=1;$c<=7;$c++) {
  substr($t,-$c) = '';  # truncate
  test(14+$c,$t eq pad($j->decrypt($i->encrypt(pad($t,'e'))),'d'),"Rijndael can't decrypt Crypt::CBC encryption");
}

# now try various short strings
for (my $c=0;$c<=18;$c++) {
  my $t = 'i' x $c;
  test(22+$c,$t eq pad($j->decrypt($i->encrypt(pad($t,'e'))),'d'),"Rijndael can't decrypt Crypt::CBC encryption");
}

# now try various short strings
for (my $c=0;$c<=18;$c++) {
  my $t = 'i' x $c;
  test(41+$c,$t eq pad($j->decrypt($i->encrypt(pad($t,'e'))),'d'),"Rijndael can't decrypt Crypt::CBC encryption");
}

