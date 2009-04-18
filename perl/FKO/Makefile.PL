use lib 'inc';
use Devel::CheckLib;
use 5.008008;
use ExtUtils::MakeMaker;

my $fkolib_dir;

my @libdirs = qw(
    /usr/lib64
    /usr/lib
    /usr/local/lib64
    /usr/local/lib
    /usr/lib64/fko
    /usr/lib/fko
    /usr/local/lib64/fko
    /usr/local/lib/fko
    /opt/fko/lib64
    /opt/fko/lib
);

check_lib_or_exit(
    lib     => [qw( fko )],
    libpath => \@libdirs
);

WriteMakefile(
    NAME              => 'FKO',
    VERSION_FROM      => 'lib/FKO.pm',
    PREREQ_PM         => {},
    ($] >= 5.005 ?
      (ABSTRACT_FROM  => 'lib/FKO.pm',
       AUTHOR         => 'Damien S. Stuart <dstuart@dstuart.org>') : ()),
    LIBS              => ['-lfko'],
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.',
	# Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
);
