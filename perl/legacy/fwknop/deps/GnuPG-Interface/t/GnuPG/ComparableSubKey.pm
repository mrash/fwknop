#  ComparableSubKey.pm
#    - comparable GnuPG::SubKey
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
#  $Id: ComparableSubKey.pm 389 2005-12-11 22:46:36Z mbr $
#

package GnuPG::ComparableSubKey;

use strict;
use GnuPG::ComparableSignature;
use GnuPG::ComparableFingerprint;

use base qw( GnuPG::SubKey GnuPG::ComparableKey );

sub compare
{
    my ( $self, $other, $deep ) = @_;
    
    if ( $deep )
    {
	bless $self->signature, 'GnuPG::ComparableSignature'
	  if $self->signature();
	bless $self->fingerprint, 'GnuPG::ComparableFingerprint'
	  if $self->fingerprint();
	
	foreach my $field ( qw( signature fingerprint ) )
	{
	    my $f1 = $self->$field();
	    my $f2 = $other->$field();
	    
	    # if neither are filled in, don't compare this
	    next if not $f1 or not $f2;
	    
	    # if one is filled in, but not the other
	    # we say they are different
	    return 0 if $f1 xor $f2;
	    
	    $f1->compare( $f2, 1 );
	}
    }
    
    return $self->SUPER::compare( $other, $deep )
}

1;
