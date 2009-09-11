use 5.005;

use strict;
use English qw( -no_match_vars );
use ExtUtils::MakeMaker;

use File::Find;
use File::Spec;

$WARNING = 1;

my $gnupg_base = 'lib/GnuPG';
my $gnupg_install_base = "\$(INST_LIBDIR)";
my %pm_install_hash = ();

my $gpg_find = 'which gpg';
print "$gpg_find ... ";
system($gpg_find);
if ($CHILD_ERROR != 0)
{
    die "gpg (GnuPG) not found";
}

find( \&set_pm_install_hash, $gnupg_base );

sub set_pm_install_hash
{
    return unless /\.pm$/;
    
    my $install_path = $File::Find::name;
    $install_path =~ s/$gnupg_base/$gnupg_install_base/;
    $pm_install_hash{$File::Find::name} = $install_path;
}


WriteMakefile
  ( AUTHOR       => 'Frank J. Tobin',
    ABSTRACT     => 'supply object methods for interacting with GnuPG',
    NAME         => 'GnuPG::Interface',
    VERSION_FROM => File::Spec->catfile( $gnupg_base, 'Interface.pm' ),
    
    PREREQ_PM    => {
		     'Class::MethodMaker' => 1.00,
		    },
    
    PM           => { %pm_install_hash },
    
    dist         => {
		     COMPRESS => 'gzip',
		     SUFFIX   => 'gz',
		    },
    clean        => { FILES => "test/*-keys*/*.out test/random_seed test/trustdb.gpg test/temp" }
  );

