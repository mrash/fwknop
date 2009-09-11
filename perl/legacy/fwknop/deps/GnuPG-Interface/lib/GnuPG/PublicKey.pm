#  PublicKey.pm
#    - providing an object-oriented approach to GnuPG public keys
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
#  $Id: PublicKey.pm 389 2005-12-11 22:46:36Z mbr $
#

package GnuPG::PublicKey;

use strict;

use base qw( GnuPG::PrimaryKey );

1;

__END__

=head1 NAME

GnuPG::PublicKey - GnuPG Public Key Objects

=head1 SYNOPSIS

  # assumes a GnuPG::Interface object in $gnupg
  my @keys = $gnupg->get_public_keys( 'ftobin' );

  # now GnuPG::PublicKey objects are in @keys

=head1 DESCRIPTION

GnuPG::PublicKey objects are generally instantiated
through various methods of GnuPG::Interface.
They embody various aspects of a GnuPG public key.

This package inherits data members and object methods
from GnuPG::PrimaryKey, which is described here, but rather
in L<GnuPG::PrimaryKey>.

Currently, this package is functionally no different
from GnuPG::PrimaryKey.

=head1 SEE ALSO

L<GnuPG::PrimaryKey>,

=cut
