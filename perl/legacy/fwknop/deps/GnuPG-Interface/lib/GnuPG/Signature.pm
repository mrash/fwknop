#  Signature.pm
#    - providing an object-oriented approach to GnuPG key signatures
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
#  $Id: Signature.pm 389 2005-12-11 22:46:36Z mbr $
#

package GnuPG::Signature;

use strict;

use Class::MethodMaker
  get_set       => [ qw( algo_num    hex_id   user_id_string
			 date_string
		       ) ],
  new_hash_init => 'new';

1;

__END__

=head1 NAME

GnuPG::Signature - GnuPG Key Signature Objects

=head1 SYNOPSIS

  # assumes a GnuPG::SubKey object in $key
  my $signing_id = $key->signature->hex_id();

=head1 DESCRIPTION

GnuPG::Signature objects are generally not instantiated
on their own, but rather as part of GnuPG::Key objects.
They embody various aspects of a GnuPG signature on a key.

=head1 OBJECT METHODS

=over 4

=item new( I<%initialization_args> )

This methods creates a new object.  The optional arguments are
initialization of data members; the initialization is done
in a manner according to the method created as described
in L<Class::MethodMaker/"new_hash_init">.

=back

=head1 OBJECT DATA MEMBERS

Note that these data members are interacted with via object methods
created using the methods described in L<Class::MethodMaker/"get_set">,
L<Class::MethodMaker/"object">, or L<Class::MethodMaker/"list">.
Please read there for more information.

=over 4

=item algo_num

The number of the algorithm used for the signature.

=item hex_id

The hex id of the signing key.

=item user_id_string

The first user id string on the key that made the signature.
This may not be defined if the signing key is not on the local keyring.

=item date_string

The formatted date the signature was performed on.

=back

=head1 SEE ALSO

See also L<Class::MethodMaker>.

=cut
