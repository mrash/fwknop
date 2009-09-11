#!/usr/bin/perl

use Test::More 'no_plan';

use_ok( 'Crypt::Rijndael' );

ok( defined &Crypt::Rijndael::blocksize );

is( Crypt::Rijndael->blocksize, 16 );