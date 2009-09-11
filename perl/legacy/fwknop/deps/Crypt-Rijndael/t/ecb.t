#!/usr/bin/perl

use Cwd;
use File::Spec;
use Test::More 'no_plan';

require_ok( File::Spec->catfile( cwd(), qw( t lib mode.pl ) ) );

use_ok( 'Crypt::Rijndael' );

ok( defined &Crypt::Rijndael::MODE_ECB );
diag( "MODE_ECB is @{ [Crypt::Rijndael::MODE_ECB()] }" ) if $ENV{DEBUG};

foreach my $a  ( 0 .. 10 ) 
	{
	my $hash = crypt_decrypt( Crypt::Rijndael::MODE_ECB() );
	
	is( $hash->{plain}, $hash->{data}, "Decrypted text matches plain text" );
	}