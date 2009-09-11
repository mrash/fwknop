#  Fingerprint.pm
#    - providing an object-oriented approach to GnuPG key fingerprints
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
#  $Id: Fingerprint.pm 389 2005-12-11 22:46:36Z mbr $
#

package GnuPG::Fingerprint;

use strict;

use Class::MethodMaker
  get_set       => [ qw( as_hex_string ) ],
  new_hash_init => 'new';

# DEPRECATED
sub hex_data
{
    my ( $self, $v ) = @_;
    $self->as_hex_string( $v ) if defined $v;
    return $self->as_hex_string();
}

1;

__END__

=head1 NAME

GnuPG::Fingerprint - GnuPG Fingerprint Objects

=head1 SYNOPSIS

  # assumes a GnuPG::Key in $key
  my $fingerprint = $key->fingerprint->as_hex_string();

=head1 DESCRIPTION

GnuPG::Fingerprint objects are generally part of GnuPG::Key
objects, and are not created on their own.

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

=item as_hex_string

This is the hex value of the fingerprint that the object embodies,
in string format.

=back

=head1 SEE ALSO

L<GnuPG::Key>,
L<Class::MethodMaker>

=cut
