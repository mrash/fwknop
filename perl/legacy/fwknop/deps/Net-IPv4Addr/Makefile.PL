use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Net::IPv4Addr',
    'VERSION_FROM' => 'IPv4Addr.pm', # finds $VERSION
    'EXE_FILES'  => [ ipv4calc ],
);
