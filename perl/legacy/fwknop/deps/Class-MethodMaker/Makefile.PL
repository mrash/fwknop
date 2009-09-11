require 5.006;
use strict;

use Config                qw( %Config );
use ExtUtils::MakeMaker   qw( WriteMakefile );
use File::Basename        qw( basename );
use File::Find            qw( find );
use File::Spec::Functions qw( catfile );
use Getopt::Long          qw( GetOptions );

use constant RAW_COMPS    => map(join('.', basename($_, '.m'), 'pm'),
                                 glob(catfile qw(components *.m)));
use constant COMPONENTS   =>
  +{map {catfile('components', join('.',basename($_,'.pm'),'m')) =>
         catfile(qw(MethodMaker), $_)} RAW_COMPS};
use constant OPTEXT       => catfile qw( lib Class MethodMaker OptExt.pm );

use constant MACOSX_INST  => +{
                               INSTALLDIRS => "vendor",
                               INSTALLVENDORBIN     => $Config{installbin}     || $Config{installvendorbin}  || $Config{installsitebin},
                               INSTALLVENDORARCH    => $Config{installarchlib} || $Config{installvendorarch} || $Config{installsitearch},
                               INSTALLVENDORLIB     => $Config{installprivlib} || $Config{installvendorlib}  || $Config{installsitelib},
                               INSTALLVENDORMAN1DIR => $Config{installman1dir},
                               INSTALLVENDORMAN3DIR => $Config{installman3dir},
                              };

my $macosx;
# my OS X installation only works if given some wacky paths :-(
GetOptions( 'macosx' => \$macosx )
  or die "options parsing failed\n";

my %pm;
find (sub {
        $File::Find::prune = 1, return
          if -d $_ and $_ eq 'CVS';
        return unless /\.pm$/;
        (my $target = $File::Find::name) =~
          s!^$File::Find::topdir/Class!\$(INST_LIBDIR)!;
        $pm{$File::Find::name} = $target;
      },
      'lib');

$pm{catfile qw( lib Class ), $_} = catfile '$(INST_LIBDIR)', $_
#$pm{catfile 'lib', $_} = $_
  for values %{COMPONENTS()};

my %MakefileArgs = (
  NAME         => 'Class::MethodMaker',
  DISTNAME     => 'Class-MethodMaker',
  VERSION      => '2.11',
  AUTHOR       => 'Martyn J. Pearce ',
  ABSTRACT     => 'a module for creating generic methods',
  PREREQ_PM    => +{ },
  EXE_FILES    => [ ],
  # Need this to stop Makefile treating Build.PL as a producer of Build as a
  # target for 'all'.
  PL_FILES     => +{},
  PM           => \%pm,
  clean        => +{ FILES => join(' ', qw( Build _build ),
                                   map(catfile(qw(lib Class MethodMaker), $_),
                                       RAW_COMPS),
                                   catfile(qw(lib Class MethodMaker.bs)),
                                  )
                   },
  depend       => +{
                    map({;catfile(qw( lib Class ), COMPONENTS->{$_}) =>
                          join(' ', 'cmmg.pl', %_, OPTEXT) . "\n\t" .
                          join(' ', '$(PERL)', 'cmmg.pl', $_, '>', '$@')
                         }
                        keys %{COMPONENTS()}
                       )
                   },
 );

if ( $macosx ) {
  while ( my($k,$v) = each %{MACOSX_INST()} ) {
    $MakefileArgs{$k} = $v;
  }
}

WriteMakefile( %MakefileArgs );
