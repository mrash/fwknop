# (X)Emacs mode: -*- cperl -*-

package Class::MethodMaker::Constants;

=head1 NAME

Class::MethodMaker::Constants

=head1 SYNOPSIS

Z<>

=head1 DESCRIPTION

Z<>

=cut

# ----------------------------------------------------------------------------

# Pragmas -----------------------------

require 5.006;
use strict;
use warnings;

use Exporter;
our @EXPORT_OK = qw( INTEGER );

# ----------------------------------------------------------------------------

# CLASS METHODS --------------------------------------------------------------

# -------------------------------------
# CLASS CONSTANTS
# -------------------------------------

=head1 CLASS CONSTANTS

Z<>

=cut

use constant INTEGER => '+INTEGER'; # Prefix to ensure clients don't just
                                    # assume the string: this value may well
                                    # change in the future

# ----------------------------------------------------------------------------

=head1 EXAMPLES

Z<>

=head1 BUGS

Z<>

=head1 REPORTING BUGS

Email the development mailing list C<class-mmaker-devel@lists.sourceforge.net>

=head1 AUTHOR

Martyn J. Pearce

=head1 COPYRIGHT

Copyright (c) 2003 Martyn J. Pearce.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

Z<>

=cut

1; # keep require happy.

__END__
