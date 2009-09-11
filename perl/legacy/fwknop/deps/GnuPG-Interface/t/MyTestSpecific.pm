#  MyTestSpecific.pm
#    - module for use with test scripts
#
#  Copyright (C) 2000 Frank J. Tobin <ftobin@cpan.org>
#
#  This module is free software; you can redistribute it and/or modify it
#  under the same terms as Perl itself.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#  $Id: MyTestSpecific.pm 1125 2008-06-07 17:27:50Z mbr $
#

use strict;
use English qw( -no_match_vars );
use Fatal qw/ open close /;
use IO::File;
use IO::Handle;
use IO::Seekable;
use File::Compare;
use Exporter;
use Class::Struct;

use GnuPG::Interface;
use GnuPG::Handles;

use vars qw( @ISA           @EXPORT
	     $stdin         $stdout           $stderr
	     $gpg_program   $handles          $gnupg
	     %texts
	   );

@ISA    = qw( Exporter );
@EXPORT = qw( stdin                  stdout          stderr
	      gnupg_program handles  reset_handles
	      texts                  file_match
	    );


$gpg_program = 'gpg';

$gnupg = GnuPG::Interface->new( gnupg_call  => $gpg_program,
				passphrase  => 'test',
			      );

$gnupg->options->hash_init( homedir              => 'test',
			    armor                => 1,
			    meta_interactive     => 0,
			    meta_signing_key_id  => '0xF950DA9C',
			    always_trust         => 1,
			  );

struct( Text => { fn => "\$", fh => "\$", data => "\$" } );

$texts{plain} = Text->new();
$texts{plain}->fn( 'test/plain.1.txt' );

$texts{encrypted} = Text->new();
$texts{encrypted}->fn( 'test/encrypted.1.gpg' );

$texts{signed} = Text->new();
$texts{signed}->fn( 'test/signed.1.asc' );

$texts{key} = Text->new();
$texts{key}->fn( 'test/key.1.asc' );

$texts{temp} = Text->new();
$texts{temp}->fn( 'test/temp' );


foreach my $name ( qw( plain encrypted signed key ) )
{
    my $entry = $texts{$name};
    my $filename = $entry->fn();
    my $fh = IO::File->new( $filename )
      or die "cannot open $filename: $ERRNO";
    $entry->data( [ $fh->getlines() ] );
}

sub reset_handles
{
    foreach ( $stdin, $stdout, $stderr )
    {
	$_ = IO::Handle->new();
    }
    
    $handles = GnuPG::Handles->new
      ( stdin   => $stdin,
	stdout  => $stdout,
	stderr  => $stderr
      );
    
    foreach my $name ( qw( plain encrypted signed key ) )
    {
	my $entry = $texts{$name};
	my $filename = $entry->fn();
	my $fh = IO::File->new( $filename )
	  or die "cannot open $filename: $ERRNO";
	$entry->fh( $fh );
    }
    
    {
	my $entry = $texts{temp};
	my $filename = $entry->fn();
	my $fh = IO::File->new( $filename, 'w' )
	  or die "cannot open $filename: $ERRNO";
	$entry->fh( $fh );
    }
}



sub file_match
{
    my ( $orig, @compares ) = @_;
    
    my $found_match = 0;
    
    foreach my $file ( @compares )
    {
	return 1
	  if compare( $file, $orig ) == 0;
    }
    
    return 0;
}



1;
