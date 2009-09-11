#!/usr/bin/perl 

use strict; 
use Crypt::Rijndael;
use Digest::MD5 qw(md5_hex);

use Test::More 'no_plan';

my $class = 'Crypt::Rijndael';

my $key       = 'abcdefghijklmnop';

my $in_plain  = 'a' x 32;

my $cipher = $class->new( $key, Crypt::Rijndael::MODE_CBC ); 
isa_ok( $cipher, $class );

$cipher->set_iv('a' x 16); 

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# encrypt
diag( "-" x 50 ) if $ENV{DEBUG};

my $crypt  = $cipher->encrypt( $in_plain );

diag( "Plain text: [$in_plain]" ) if $ENV{DEBUG};
diag( "Crypt text: [$crypt]" ) if $ENV{DEBUG};

my $digest = md5_hex( $crypt );
diag( "MD5 digest of crypt: [$digest]" ) if $ENV{DEBUG};

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# decrypt to see if we get back the same thing
{
diag( "-" x 50 ) if $ENV{DEBUG};

my $out_plain  = $cipher->decrypt( $crypt );

diag( "Crypt text: [$crypt]" ) if $ENV{DEBUG};
diag( "Plain text: [$out_plain]" ) if $ENV{DEBUG};

is( $out_plain, $in_plain, "Text comes back correctly" );
}