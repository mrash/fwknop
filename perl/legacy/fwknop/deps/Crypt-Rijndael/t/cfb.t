#!/usr/bin/perl

use Cwd;
use File::Spec;
use Test::More 'no_plan';

require_ok( File::Spec->catfile( cwd(), qw( t lib mode.pl ) ) );

use_ok( 'Crypt::Rijndael' );

ok( defined &Crypt::Rijndael::MODE_CFB );
diag( "MODE_CBFB is @{ [Crypt::Rijndael::MODE_CFB()] }" ) if $ENV{DEBUG};

foreach my $a  ( 0 .. 10 ) 
	{
	my $hash = crypt_decrypt( Crypt::Rijndael::MODE_CFB() );
	
	is( $hash->{plain}, $hash->{data}, "Decrypted text matches plain text" );
	}