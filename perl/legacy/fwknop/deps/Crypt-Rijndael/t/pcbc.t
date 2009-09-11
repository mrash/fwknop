#!/usr/bin/perl

use Cwd;
use File::Spec;
use Test::More 'no_plan';

require_ok( File::Spec->catfile( cwd(), qw( t lib mode.pl ) ) );

use_ok( 'Crypt::Rijndael' );

ok( defined &Crypt::Rijndael::MODE_PCBC );
diag( "MODE_PCBC is @{ [Crypt::Rijndael::MODE_PCBC()] }" ) if $ENV{DEBUG};

TODO: {
	local $TODO = "PCBC is not a legal mode (yet)";
	
my $value = eval {
	foreach my $a  ( 0 .. 10 ) 
		{
		my $hash = crypt_decrypt( Crypt::Rijndael::MODE_PCBC() );
		
		is( $hash->{plain}, $hash->{data}, "Decrypted text matches plain text" );
		}
	};

};