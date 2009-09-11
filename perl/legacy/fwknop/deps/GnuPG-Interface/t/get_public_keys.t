#!/usr/bin/perl -w
#
# $Id: get_public_keys.t 1125 2008-06-07 17:27:50Z mbr $
#

use strict;
use English qw( -no_match_vars );

use lib './t';
use MyTest;
use MyTestSpecific;

use GnuPG::ComparablePublicKey;
use GnuPG::ComparableSubKey;

my ( $given_key, $handmade_key );

TEST
{
    reset_handles();
    
    my @returned_keys = $gnupg->get_public_keys_with_sigs( '0xF950DA9C' );
    
    return 0 unless @returned_keys == 1;
    
    $given_key = shift @returned_keys;
    
    $handmade_key = GnuPG::ComparablePublicKey->new
      ( length                 => 1024,
	algo_num               => 17,
	hex_id                 => '53AE596EF950DA9C',
	creation_date_string   => '2000-02-06',
	expiration_date_string => '2002-02-05',
	owner_trust            => 'f',
      );
    
    $handmade_key->fingerprint
      ( GnuPG::Fingerprint->new( as_hex_string =>
				 '93AFC4B1B0288A104996B44253AE596EF950DA9C',
			       )
      );
    
    my $initial_self_signature = GnuPG::Signature->new
      ( algo_num       => 17,
	hex_id         => '53AE596EF950DA9C',
	date_string    => '2000-02-06',
      );
    
    my $uid2_signature = GnuPG::Signature->new
      ( algo_num       => 17,
        hex_id         => '53AE596EF950DA9C',
        date_string    => '2000-03-16',
      );
    
    my $ftobin_signature = GnuPG::Signature->new
      ( algo_num       => 17,
	hex_id         => '56FFD10A260C4FA3',
	date_string    => '2000-03-16',
	);
    
    my $subkey = GnuPG::SubKey->new
      ( validity                 => 'u',
	length                   => 768,
	algo_num                 => 16,
	hex_id                   => 'ADB99D9C2E854A6B',
	creation_date_string     => '2000-02-06',
	expiration_date_string   => '2002-02-05',
      );
    
    $subkey->fingerprint
      ( GnuPG::Fingerprint->new( as_hex_string =>
				 '7466B7E98C4CCB64C2CE738BADB99D9C2E854A6B'
			       )
      );
    
    $subkey->signature( $initial_self_signature );
    
    $handmade_key->push_subkeys( $subkey );
    
    $handmade_key->compare( $given_key );
};

TEST
{
    my $subkey1 = $given_key->subkeys()->[0];
    my $subkey2 = $handmade_key->subkeys()->[0];
    
    bless $subkey1, 'GnuPG::ComparableSubKey';

    my $equal = $subkey1->compare( $subkey2 );
    
    warn 'subkeys fail comparison; this is a known issue with GnuPG 1.0.1'
      if not $equal;
    
    return $equal;
};


TEST
{  
    $handmade_key->compare( $given_key, 1 );
};
