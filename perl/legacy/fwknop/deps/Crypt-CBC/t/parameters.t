#!/usr/bin/perl -w

use strict;
use lib '..','../blib/lib','.','./blib/lib';

sub test ($$$); 

my $plaintext = <<END;
Mary had a little lamb,
Its fleece was black as coal,
And everywere that Mary went,
That lamb would dig a hole.
END
    ;

print "1..63\n";

eval "use Crypt::CBC";
test(1,!$@,"Couldn't load module");

my ($crypt,$ciphertext1,$ciphertext2);

$crypt = eval {Crypt::CBC->new(-cipher => 'Crypt::Crypt8',
			       -key    => 'test key') };
test(2,defined $crypt,"$@Can't continue!");
test(3,$crypt->header_mode eq 'salt',"Default header mode is not 'salt'");
exit 0 unless $crypt;


# tests for the salt header
$crypt = eval {Crypt::CBC->new(-cipher => 'Crypt::Crypt8',
			       -key    => 'test key',
			       -header => 'salt') };
test(4,defined $crypt,"$@Can't continue!");
exit 0 unless $crypt;

test(5,!defined $crypt->iv,  "IV is defined after new() but it shouldn't be");
test(6,!defined $crypt->salt,"salt is defined after new() but it shouldn't be");
test(7,!defined $crypt->key, "key is defined after new() but it shouldn't be");

$ciphertext1 = $crypt->encrypt($plaintext);
test(8,$ciphertext1 =~ /^Salted__/s,"salted header not present");
test(9, defined $crypt->iv,   "IV not defined after encrypt");
test(10,defined $crypt->salt, "salt not defined after encrypt");
test(11,defined $crypt->key,  "key not defined after encrypt");

my ($old_iv,$old_salt,$old_key) = ($crypt->iv,$crypt->salt,$crypt->key);
$ciphertext2 = $crypt->encrypt($plaintext);
test(12,$ciphertext2 =~ /^Salted__/s,"salted header not present");
test(13,$old_iv   ne $crypt->iv,   "IV didn't change after an encrypt");
test(14,$old_salt ne $crypt->salt, "salt didn't change after an encrypt");
test(15,$old_key  ne $crypt->key,  "key didn't change after an encrypt");

test(16,$plaintext eq $crypt->decrypt($ciphertext1),"decrypted text doesn't match original");
test(17,$old_iv   eq $crypt->iv,    "original IV wasn't restored after decryption");
test(18,$old_salt eq $crypt->salt,  "original salt wasn't restored after decryption");
test(19,$old_key  eq $crypt->key,   "original key wasn't restored after decryption");

test(20,$crypt->passphrase eq 'test key',"get passphrase()");
$crypt->passphrase('new key');
test(21,$crypt->passphrase eq 'new key',"set passphrase()");

test(22,length($crypt->random_bytes(20)) == 20,"get_random_bytes()");

# tests for the randomiv header
$crypt = eval {Crypt::CBC->new(-cipher => 'Crypt::Crypt8',
			       -key    => 'test key',
			       -header => 'randomiv') };
test(23,defined $crypt,"$@\nCan't continue!");
exit 0 unless $crypt;

test(24,$crypt->header_mode eq 'randomiv',"wrong header mode");
test(25,!defined $crypt->iv,  "IV is defined after new() but it shouldn't be");
test(26,!defined $crypt->salt,"salt is defined after new() but it shouldn't be");
test(27,!defined $crypt->key, "key is defined after new() but it shouldn't be");

$ciphertext1 = $crypt->encrypt($plaintext);
test(28,$ciphertext1 =~ /^RandomIV/s,"RandomIV header not present");
test(29, defined $crypt->iv,   "IV not defined after encrypt");
test(30,!defined $crypt->salt, "salt defined after encrypt");
test(31,defined $crypt->key,  "key not defined after encrypt");

($old_iv,$old_salt,$old_key) = ($crypt->iv,$crypt->salt,$crypt->key);
$ciphertext2 = $crypt->encrypt($plaintext);
test(32,$ciphertext2 =~ /^RandomIV/s,"RandomIV header not present");
test(33,$old_iv   ne $crypt->iv,   "IV didn't change after an encrypt");
test(34,$old_key  eq $crypt->key,  "key changed after an encrypt");

test(35,$plaintext eq $crypt->decrypt($ciphertext1),"decrypted text doesn't match original");
test(36,$old_iv   eq $crypt->iv,    "original IV wasn't restored after decryption");

# tests for headerless operation
$crypt = eval {Crypt::CBC->new(-cipher => 'Crypt::Crypt8',
			       -key    => 'test key',
			       -iv     => '01234567',
			       -header => 'none') };
test(37,defined $crypt,"$@Can't continue!");
exit 0 unless $crypt;
test(38,$crypt->header_mode eq 'none',"wrong header mode");
test(39,$crypt->iv eq '01234567',  "IV doesn't match settings");
test(40,!defined $crypt->key, "key is defined after new() but it shouldn't be");
$ciphertext1 = $crypt->encrypt($plaintext);
test(41,length($ciphertext1) - length($plaintext) <= 8, "ciphertext grew too much");
test(42,$crypt->decrypt($ciphertext1) eq $plaintext,"decrypted ciphertext doesn't match plaintext");
my $crypt2 = Crypt::CBC->new(-cipher => 'Crypt::Crypt8',
			     -key    => 'test key',
			     -iv     => '01234567',
			     -header => 'none');
test(43,$crypt2->decrypt($ciphertext1) eq $plaintext,"decrypted ciphertext doesn't match plaintext");
$crypt2 = Crypt::CBC->new(-cipher => 'Crypt::Crypt8',
			  -key    => 'test key',
			  -iv     => '76543210',
			  -header => 'none');
test(44,$crypt2->decrypt($ciphertext1) ne $plaintext,"decrypted ciphertext matches plaintext but shouldn't");
test(45,$crypt->iv  eq '01234567',"iv changed and it shouldn't have");
test(46,$crypt2->iv eq '76543210',"iv changed and it shouldn't have");

# check various bad combinations of parameters that should cause a fatal error
my $good_key = Crypt::CBC->random_bytes(Crypt::Crypt8->keysize);
my $bad_key  = 'foo';
$crypt = eval {Crypt::CBC->new(-cipher => 'Crypt::Crypt8',
			       -header => 'randomiv',
			       -key    => $good_key,
			       -iv     => '01234567',
			       -literal_key => 1)};
test(47,defined $crypt,"$@Can't continue!");
exit 0 unless $crypt;
test(48,$crypt->key eq $good_key,"couldn't set literal key");
test(49,
     !eval{
       Crypt::CBC->new(-cipher => 'Crypt::Crypt8',
		       -header => 'randomiv',
		       -key    => $bad_key,
		       -iv     => '01234567',
		       -literal_key => 1)
       },
     "module accepted a literal key of invalid size");
test(50,
     !eval{
       Crypt::CBC->new(-cipher => 'Crypt::Crypt16',
		       -header => 'randomiv',
		       -key    => $good_key,
		       -iv     => '01234567',
		       -literal_key => 1)
       },
     "module accepted a literal key of invalid size");
test(51,
     !eval{
       Crypt::CBC->new(-cipher => 'Crypt::Crypt8',
		       -header => 'randomiv',
		       -key    => $good_key,
		       -iv     => '01234567891',
		       -literal_key => 1)
       },
     "module accepted an IV of invalid size");

test(52,
     !eval{
       Crypt::CBC->new(-cipher => 'Crypt::Crypt16',
		       -header => 'randomiv',
		       -key    => 'test key')
       },
     "module allowed randomiv headers with a 16-bit blocksize cipher");

$crypt =  Crypt::CBC->new(-cipher                  => 'Crypt::Crypt16',
			  -header                  => 'randomiv',
			  -key                     => 'test key',
			  -insecure_legacy_decrypt => 1);
test(53,defined $crypt,"module didn't honor the -insecure_legacy_decrypt flag:$@Can't continue!");
exit 0 unless $crypt;

test(54,$crypt->decrypt("RandomIV01234567".'a'x256),"module didn't allow legacy decryption");
test(55,!defined eval{$crypt->encrypt('foobar')},"module allowed legacy encryption and shouldn't have");


test(56,
     !defined eval {Crypt::CBC->new(-cipher                  => 'Crypt::Crypt16',
				    -header                  => 'salt',
				    -key                     => 'test key',
				    -salt                    => 'bad bad salt!');
		  },
     "module allowed setting of a bad salt");

test(57,
     defined eval {Crypt::CBC->new(-cipher                  => 'Crypt::Crypt16',
				   -header                  => 'salt',
				   -key                     => 'test key',
				   -salt                    => 'goodsalt');
		 },
     "module did not allow setting of a good salt");

test(58,
     Crypt::CBC->new(-cipher                  => 'Crypt::Crypt16',
		     -header                  => 'salt',
		     -key                     => 'test key',
		     -salt                    => 'goodsalt')->salt eq 'goodsalt',
     "module did not allow setting and retrieval of a good salt");

test(59,
     !defined eval {Crypt::CBC->new(-cipher                  => 'Crypt::Crypt16',
				    -header                  => 'badheadermethod',
				    -key                     => 'test key')},
     "module allowed setting of an invalid header method, and shouldn't have");

test(60,
     !defined eval {Crypt::CBC->new(-cipher                  => 'Crypt::Crypt16',
				    -header                  => 'none',
				    -key                     => 'a'x16)
     },
     "module allowed initialization of header_mode 'none' without an iv");

test(61,
     !defined eval {Crypt::CBC->new(-cipher                  => 'Crypt::Crypt16',
				    -header                  => 'none',
				    -iv                      => 'a'x16)
     },
     "module allowed initialization of header_mode 'none' without a key");

$crypt = eval {Crypt::CBC->new(-cipher         => 'Crypt::Crypt8',
			       -literal_key    => 1,
			       -header         => 'none',
			       -key            => 'a'x56,
			       -iv             => 'b'x8,
			      ) };
test(62,defined $crypt,"unable to create a Crypt::CBC object with the -literal_key option: $@");
test(63,$plaintext eq $crypt->decrypt($crypt->encrypt($plaintext)),'cannot decrypt encrypted data using -literal_key');

exit 0;

sub test ($$$){
    local($^W) = 0;
    my($num, $true,$msg) = @_;
    print($true ? "ok $num\n" : "not ok $num $msg\n");
}

package Crypt::Crypt16;

sub new       { return bless {},shift }
sub blocksize { return 16    }
sub keysize   { return 56    }
sub encrypt   { return $_[1] }
sub decrypt   { return $_[1] }

package Crypt::Crypt8;

sub new       { return bless {},shift }
sub blocksize { return 8     }
sub keysize   { return 56    }
sub encrypt   { return $_[1] }
sub decrypt   { return $_[1] }

