#  ComparableSecretKey.pm
#    - Comparable GnuPG::SecretKey
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
#  $Id: ComparableSecretKey.pm 389 2005-12-11 22:46:36Z mbr $
#

package GnuPG::ComparableSecretKey;

use strict;

use base qw( GnuPG::SecretKey GnuPG::ComparablePrimaryKey );

1;
