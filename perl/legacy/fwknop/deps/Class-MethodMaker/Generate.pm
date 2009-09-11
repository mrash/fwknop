package Generate;

use File::Spec::Functions qw( catfile );
use File::Basename        qw( basename );

use base qw( Exporter );
our @EXPORT_OK = qw( %GENERATE );

our %GENERATE = ( map {; ($output = basename $_) =~ s/\.m/.pm/;
                       $_ => catfile 'lib', 'Class', 'MethodMaker', $output }
                  grep /\.m$/, glob(catfile 'components', '*') );

