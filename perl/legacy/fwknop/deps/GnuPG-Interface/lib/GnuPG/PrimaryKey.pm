#  PrimaryKey.pm
#      - objectified GnuPG primary keys (can have subkeys)
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
#  $Id: PrimaryKey.pm 389 2005-12-11 22:46:36Z mbr $
#

package GnuPG::PrimaryKey;

use strict;

use base qw( GnuPG::Key );

use Class::MethodMaker
  list          => [ qw( user_ids   subkeys  ) ],
  get_set       => [ qw( local_id   owner_trust ) ];

1;

__END__

=head1 NAME

GnuPG::PrimaryKey - GnuPG Primary Key Objects

=head1 SYNOPSIS

  # assumes a GnuPG::Interface object in $gnupg
  my @keys = $gnupg->get_public_keys( 'ftobin' );

  # or

  my @keys = $gnupg->get_secret_keys( 'ftobin' );

  # now GnuPG::PrimaryKey objects are in @keys

=head1 DESCRIPTION

GnuPG::PrimaryKey objects are generally instantiated
as GnuPG::PublicKey or GnuPG::SecretKey objects
through various methods of GnuPG::Interface.
They embody various aspects of a GnuPG primary key.

This package inherits data members and object methods
from GnuPG::Key, which is not described here, but rather
in L<GnuPG::Key>.

=head1 OBJECT DATA MEMBERS

Note that these data members are interacted with via object methods
created using the methods described in L<Class::MethodMaker/"get_set">,
L<Class::MethodMaker/"object">, or L<Class::MethodMaker/"list">.
Please read there for more information.

=over 4

=item user_ids

A list of GnuPG::UserId objects associated with this key.

=item subkeys

A list of GnuPG::SubKey objects associated with this key.

=item local_id

GnuPG's local id for the key.

=item owner_trust

The scalar value GnuPG reports as the ownertrust for this key.
See GnuPG's DETAILS file for details.

=back

=head1 SEE ALSO

L<GnuPG::Key>,
L<GnuPG::UserId>,
L<GnuPG::SubKey>,
L<Class::MethodMaker>

=cut
