#  Key.pm
#    - providing an object-oriented approach to GnuPG keys
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
#  $Id: Key.pm 389 2005-12-11 22:46:36Z mbr $
#

package GnuPG::Key;

use strict;

use Class::MethodMaker
  get_set       => [ qw( length      algo_num     hex_id    hex_data
			 creation_date_string     expiration_date_string
			 fingerprint
		       ) ],
  new_hash_init => [ qw( new hash_init ) ];


sub short_hex_id
{
    my ( $self ) = @_;
    return substr $self->hex_id(), -8;
}

1;

__END__

=head1 NAME

GnuPG::Key - GnuPG Key Object

=head1 SYNOPSIS

  # assumes a GnuPG::Interface object in $gnupg
  my @keys = $gnupg->get_public_keys( 'ftobin' );

  # now GnuPG::PublicKey objects are in @keys

=head1 DESCRIPTION

GnuPG::Key objects are generally not instantiated on their
own, but rather used as a superclass of GnuPG::PublicKey,
GnuPG::SecretKey, or GnuPG::SubKey objects.

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

=item short_hex_id

This returns the commonly-used short, 8 character short hex id
of the key.

=back

=head1 OBJECT DATA MEMBERS

Note that these data members are interacted with via object methods
created using the methods described in L<Class::MethodMaker/"get_set">,
or L<Class::MethodMaker/"object">.
Please read there for more information.

=over 4

=item length

Number of bits in the key.

=item algo_num

They algorithm number that the Key is used for.

=item hex_data

The data of the key.

=item hex_id

The long hex id of the key.  This is not the fingerprint nor
the short hex id, which is 8 hex characters.

=item creation_date_string
=item expiration_date_string

Formatted date of the key's creation and expiration.

=item fingerprint

A GnuPG::Fingerprint object.

=back

=head1 SEE ALSO

L<GnuPG::Fingerprint>,
L<Class::MethodMaker>

=cut
