#  Handles.pm
#    - interface to the handles used by GnuPG::Interface
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
#  $Id: Handles.pm 389 2005-12-11 22:46:36Z mbr $
#


package GnuPG::Handles;

use strict;

use constant HANDLES => qw( stdin stdout stderr
			    status logger passphrase
			    command
			  );

use Class::MethodMaker
  get_set       => [ HANDLES ],
  hash          => [ qw( options ) ],
  new_with_init => 'new',
  new_hash_init => 'hash_init';


sub init
{
    my ( $self, %args ) = @_;
    # This is done for the user's convenience so that they don't
    # have to worry about undefined hashrefs
    foreach my $handle ( HANDLES ) { $self->options( $handle, {} ) }
    $self->hash_init( %args );
}



1;


=head1 NAME

GnuPG::Handles - GnuPG handles bundle

=head1 SYNOPSIS

  use IO::Handle;
  my ( $stdin, $stdout, $stderr,
       $status_fh, $logger_fh, $passphrase_fh,
     )
    = ( IO::Handle->new(), IO::Handle->new(), IO::Handle->new(),
        IO::Handle->new(), IO::Handle->new(), IO::Handle->new(),
      );
 
  my $handles = GnuPG::Handles->new
    ( stdin      => $stdin,
      stdout     => $stdout,
      stderr     => $stderr,
      status     => $status_fh,
      logger     => $logger_fh,
      passphrase => $passphrase_fh,
    );

=head1 DESCRIPTION

GnuPG::Handles objects are generally instantiated
to be used in conjunction with methods of objects
of the class GnuPG::Interface.  GnuPG::Handles objects
represent a collection of handles that are used to
communicate with GnuPG.

=head1 OBJECT METHODS

=head2 Initialization Methods

=over 4

=item new( I<%initialization_args> )

This methods creates a new object.  The optional arguments are
initialization of data members; the initialization is done
in a manner according to the method created as described
in L<Class::MethodMaker/"new_hash_init">.

=item hash_init( I<%args> ).

This method works as described in L<Class::MethodMaker/"new_hash_init">.

=back

=head1 OBJECT DATA MEMBERS

Note that these data members are interacted with via object methods
created using the methods described in L<Class::MethodMaker/"get_set">,
or L<Class::MethodMaker/"object">.
Please read there for more information.

=over 4

=item stdin

This handle is connected to the standard input of a GnuPG process.

=item stdout

This handle is connected to the standard output of a GnuPG process.

=item stderr

This handle is connected to the standard error of a GnuPG process.

=item status

This handle is connected to the status output handle of a GnuPG process.

=item logger

This handle is connected to the logger output handle of a GnuPG process.

=item passphrase

This handle is connected to the passphrase input handle of a GnuPG process.

=item command

This handle is connected to the command input handle of a GnuPG process.

=item options

This is a hash of hashrefs of settings pertaining to the handles
in this object.  The outer-level hash is keyed by the names of the
handle the setting is for, while the inner is keyed by the setting
being referenced.  For example, to set the setting C<direct> to true
for the filehandle C<stdin>, the following code will do:

    # assuming $handles is an already-created
    # GnuPG::Handles object, this sets all
    # options for the filehandle stdin in one blow,
    # clearing out all others
    $handles->options( 'stdin', { direct => 1 } );

    # this is useful to just make one change
    # to the set of options for a handle
    $handles->options( 'stdin' )->{direct} = 1;

    # and to get the setting...
    $setting = $handles->options( 'stdin' )->{direct};

    # and to clear the settings for stdin
    $handles->options( 'stdin', {} );

The currently-used settings are as follows:

=over 4

=item direct

If the setting C<direct> is true for a handle, the GnuPG
process spawned will access the handle directly.  This is useful for
having the GnuPG process read or write directly to or from
an already-opened file.

=back

=back

=head1 SEE ALSO

L<GnuPG::Interface>,
L<Class::MethodMaker>

=cut
