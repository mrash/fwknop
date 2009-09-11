#  SecretKey.pm
#    - providing an object-oriented approach to GnuPG secret keys
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
#  $Id: SecretKey.pm 389 2005-12-11 22:46:36Z mbr $
#

package GnuPG::SecretKey;

use strict;

use base qw( GnuPG::PrimaryKey );

1;

__END__

=head1 NAME

GnuPG::SecretKey - GnuPG Secret Key Objects

=head1 SYNOPSIS

  # assumes a GnuPG::Interface object in $gnupg
  my @keys = $gnupg->get_secret_keys( 'ftobin' );

  # now GnuPG::SecretKey objects are in @keys

=head1 DESCRIPTION

GnuPG::SecretKey objects are generally instantiated
through various methods of GnuPG::Interface.
They embody various aspects of a GnuPG secret key.

This package inherits data members and object methods
from GnuPG::PrimaryKey, which is described here, but rather
in L<GnuPG::PrimaryKey>.

Currently, this package is functionally no different
from GnuPG::PrimaryKey.

=head1 SEE ALSO

L<GnuPG::PrimaryKey>,

=cut
