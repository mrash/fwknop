#!/usr/bin/perl -W

# Pragmas -----------------------------

use strict;

use Fatal                 qw( open close );
use File::Basename        qw( basename );
use File::Spec::Functions qw( catdir catfile );
use FindBin               qw( $Bin );

use lib qw( lib );
use Class::MethodMaker::OptExt qw( OPTEXT );

# Constants ---------------------------

use constant COMP_DIR  => catdir $Bin, 'components';

# Utility -----------------------------

# Main -----------------------------------------------------------------------

sub min {
  my $Result;

  for (@_) {
    $Result = $_
      if ! defined $Result or $Result > $_;
  }

  return $Result;
}

sub read_file {
  my ($fn) = @_;
  open my $fh, '<', $fn;
  local $/ = undef;
  my $text = <$fh>;
  close $fh;
  return $text;
}

# Parse in methods file ---------------

my %methods;
{
  for my $fn (@ARGV) {
    open my $methods, '<', $fn;
    local $/ = "\n";
    my $methname;
    my ($doc, $text) = ('') x 2;
    my ($pod, $code) = (0)  x 2;
    while (<$methods>) {
      chomp;
      if ( $pod ) {
        $doc .= "$_\n";
        $pod = 0
          if /^=cut\b/;
      } elsif ( /^=(?:pod|head\d?)\b/ ) {
        $pod = 1;
        $doc .= "$_\n";
      } elsif ( $code ) {
        if ( /^}\s*$/ ) {
          $code = 0;
        } else {
          $text .= "$_\n";
        }
      } elsif ( /^\s*sub\s+([a-z_]+)\s+\{(.*)$/ms ) {
        my $protometh = $1;
        my $prototext = $2;

        if ( defined $methname ) {
          $methods{$methname}->{text} = $text;
          $methods{$methname}->{doc}  = $doc;
          $text = $doc = '';
        }

        $methname = $protometh;
        if ( length($prototext) and $prototext !~ /^\s*$/ ) {
          $text = "$prototext\n";
        } else {
          $text = '';
        }
        $code = 1;
      }
    }

    if ( defined $methname ) {
      $methods{$methname}->{text} = $text;
      $methods{$methname}->{doc}  = $doc;
      $text = $doc = '';
    }
  }
}

my @storage_names = Class::MethodMaker::OptExt->option_names;

# Write out methods -------------------

my %import;

while ( my ($meth, $value) = each %methods ) {
  print "package Class::MethodMaker::", basename($ARGV[0], '.m'), ";\n";

  print <<'END';
use strict;
use warnings;

use AutoLoader 5.57  qw( AUTOLOAD );
our @ISA = qw( AutoLoader );

use Carp qw( carp croak cluck );

use constant DEBUG => $ENV{_CMM_DEBUG} ? 1 : 0;

__END__
END

  # Print doc
  if ( exists $value->{doc} ) {
    my $doc = $value->{doc};
    $doc =~ s/^=cut\n=pod\n//mg;
    print "\n", $doc, "\n";
  }

  # Print each storage type
  for my $idx (0..2**@storage_names-1) {
    my @st = map $storage_names[$_], grep $idx & 2**$_, 0..$#storage_names;
    my ($suffix, undef) = Class::MethodMaker::OptExt->encode($meth, \@st);
    next
      if ! defined $suffix;

    my $name = substr($meth, 0, 4) . $suffix;
    my $code = $value->{text};
    my %replace = Class::MethodMaker::OptExt->replace(\@st);

    # Do Imports ----------------------

    $code =~ s/^(.*)%%IMPORT\((.*)\)%%/
               my ($i, $fn) = ($1, $2);
               my $t;
               if ( exists $import{$fn} ) {
                 $t = $import{$fn};
               } else {
                 $t = $import{$fn} =
                   read_file(catfile COMP_DIR, "${fn}.pm");
               }

               $t =~ s!^!$i!mg
                 if $i =~ m!^\s+$!;
               $t/meg;

    # Handle V1/V2 differences --------
    my $v1_compat = grep $_ eq 'v1_compat', @st;
    my $default = grep /default/, @st;
    # This needs to be done first because defchk (potentially) refers to
    # storage
    # Duplicate changes at YYY below
    # XXX
    $code =~ s/%%V1COMPAT_ON%%(.*?)%%V1COMPAT_OFF%%/$v1_compat ? $1 : ''/mseg;
    $code =~ s/%%V2ONLY_ON%%(.*?)%%V2ONLY_OFF%%/$v1_compat ? '' : $1/mseg;
    $code =~ s/%%DEFAULT_ON%%(.*?)%%DEFAULT_OFF%%/$default ? $1 : ''/mseg;
    $code =~ s/^(.*?)\s*%%V1COMPAT%%\s*$/$v1_compat ? $1 : ''/meg;
    $code =~ s/^(.*?)\s*%%V2ONLY%%\s*$/$v1_compat ? '' : $1/meg;
    $code =~ s/^(.*?)\s*%%DEFAULTONLY%%\s*$/$default ? $1 : ''/meg;

    # Handle callback invocations -----

    $code =~ s/^(.*)%%READ(\d)\((\S+)\)%%/
               my ($i, $n, $v) = ($1, $2, $3);
               (my $t = $replace{read}->[$n]) =~
                 s!(?<=.)^!' ' x length($i)!mseg;
               $t =~ s!__VALUE__!$v!g;
               "$i$t";
              /meg;

    $code =~ s/^(.*)%%DEFCHECK([@%\$])(.*)%%/
               my ($i, $s, $j) = ($1, $2, $3);
               (my $t = $replace{predefchk} . $replace{defchk}) =~ s!(?<=.)^!' ' x length($i)!mseg;
               $t =~ s!%%STORAGE%%!$j!g
                 if length $j;
               $t =~ s!__SIGIL__!$s!g;
               "$i$t"/meg;

    my $store = grep $_ eq 'store_cb', @st;
    $code =~ s/%%IFSTORE\((.*?),(.*?)\)%%/$store ? $1 : $2/meg;

    # ASGNCHK needs to come before STORAGE because it might well refer to
    # STORAGE
    $code =~ s/^(.*)%%ASGNCHK([@%\$])\((.*?)\)%%/
               my ($i, $s, $f) = ($1, $2, $3);
               (my $t = $replace{asgnchk} . $replace{postac}) =~
                 s!(?<=.)^!' ' x length($i)!mseg;
               $t =~ s!__FOO__!$f!g;
               $t =~ s'__ATTR__'$name'g;
               $t =~ s!__SIGIL__!$s!g;
               "$i$t"/meg;

    $code =~ s/^(.*)%%STORE\((.*?),\s*(.*?)(?:,\s*(.*?))?\)%%/
               my ($i, $m, $n, $o) = ($1, $2, $3, $4);
               my $p = substr($n,0,1) eq '$' ? $n : "$n";
               $o = '' if ! defined $o;
               (my $t = $replace{store}) =~ s!(?<=.)^!' ' x length($i)!mseg;
               $t =~ s!__NAME__!$n!g;
               $t =~ s!__NAMEREF__!$p!g;
               $t =~ s!__VALUE__!$m!g;
               $t =~ s!__ALL__!$o!g;
               "$i$t"/meg;

    # READINIT used for performing, e.g., ties even when no assignment has
    # occurred (because looking up a value into play is enough to justify the
    # tie, since the tie may provide a value (e.g., a persistent disk cache)
    $code =~ s/^(.*)%%READINIT([@%\$])%%/
               my ($i, $s) = ($1, $2);
               (my $t = $replace{postac}) =~
                 s!(?<=.)^!' ' x length($i)!mseg;
               $t =~ s'__ATTR__'$name'g;
               $t =~ s'__TYPE__'$type'g;
               $t =~ s!__SIGIL__!$s!g;
               "$i$t"/meg;
    # REFER needs to come before STORAGE because it might well refer to
    # STORAGE
    $code =~ s/^(.*)%%RESET([@%\$]?)(?:\((.*?)\))?%%/
               my ($i, $s, $f) = ($1, $2, $3);
               die "Parameterized RESET not yet handled!\n"
                 if defined $f and length $f;
               die "RESET takes a terminating sigil\n"
                 unless length $s;
               (my $t = $replace{reset}) =~
                 s!(?<=.)^!' ' x length($i)!mseg;
               $t =~ s!__SIGIL__!$s!g;
               "$i$t"/meg;
    $code =~ s/%%STORAGE(?:\((.*)\))?%%/
               my $f = $1;
               my $t = $replace{refer};
               $t = "$f\{$t\}"
                 # Special case for $ because scalars are stored direct as
                 # scalars rather than as references to scalars (whereas
                 # arrays, for example, are stored as references to arrays).
                 # Although this arrangement is less seamless than using
                 if defined $f and length $f and $f ne '$';
               $t;
              /eg;
    $code =~ s/%%STORDECL%%/$replace{decl}/g;

    # And again, because some replaced code uses this too!
    # Duplicate changes at XXX above
    # YYY
    $code =~ s/%%V1COMPAT_ON%%(.*?)%%V1COMPAT_OFF%%/$v1_compat ? $1 : ''/mseg;
    $code =~ s/%%V2ONLY_ON%%(.*?)%%V2ONLY_OFF%%/$v1_compat ? '' : $1/mseg;
    $code =~ s/^(.*?)\s*%%V2ONLY%%\s*$/$v1_compat ? '' : $1/meg;
    $code =~ s/^(.*?)\s*%%V1COMPAT%%\s*$/$v1_compat ? $1 : ''/meg;

    $code =~ s/(%%\S+)/warn "%% sequence unreplaced: $1\n";$1/eg;

    # Untabify
    1 while $code =~ s/\t+/' ' x (length($&) * 8 - length($`) % 8)/e;
    # Trim trailing whitespace
    $code =~ s/ +$//mg;
    # Tidy identation
    my $strip = min map length, $code =~ /^ +/mg;
    $code =~ s/^ {$strip}//mg;
    $code =~ s/\A\s*(.*?)\s*\Z/$1/ms;
    $code =~ s!^(.*)$!
      $_ = $1;
      my $pod = /^=pod/../^=cut/;
      $pod ? $_ : "  $_";
    !emg;
    print  "\n", '#', '-' x 18, "\n";
    print '# ', $meth, ' ', join(' - ', @st), "\n";
    print "\nsub $name {\n$code\n}\n";
  }

  print  "\n", '#', '-' x 36, "\n";
  print "\n";
}

# Add trailing doc --------------------

print "1; # keep require happy\n";



__END__
