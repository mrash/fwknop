#!/usr/local/bin/perl

use lib '..','../blib/lib','.','./blib/lib';

my (@mods,@pads,@in,$tnum);

@mods = qw/Rijndael
           Blowfish
           Blowfish_PP
           IDEA
           DES
          /;

for $mod (@mods) {
   eval "use Crypt::$mod(); 1" && push @in,$mod;
}

unless ($#in > -1) {
   print "1..0 # Skipped: no cryptographic modules found\n";
   exit;
} else {
    print "1..2\n";
}

sub test {
    local($^W) = 0;
    my($num, $true,$msg) = @_;
    $$num++;
    print($true ? "ok $$num\n" : "not ok $$num $msg\n");
}

$tnum = 0;

eval "use Crypt::CBC";
print STDERR "using Crypt\:\:$in[0] for testing\n";
test(\$tnum,!$@,"Couldn't load module");


my $cipher = Crypt::CBC->new(
			     -key    => 'aaab',
			     -cipher => $in[0],
			     -padding => "oneandzeroes",
);
my $string = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX';

my $work  = $cipher->encrypt($string); #Encrypt string
my $plain = $cipher->decrypt($work); #...and decrypt

test(\$tnum,$string eq $plain,"oneandzeroes padding not working\n");

