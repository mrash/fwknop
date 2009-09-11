use Getopt::Long          qw( GetOptions );

use lib '.';
use Generate qw( %GENERATE );

my $dump = 0;
GetOptions( 'dump' => \$dump )
  or die "options parsing failed\n";

if ( $dump ) {
  print "$_\t$GENERATE{$_}\n"
    for sort keys %GENERATE;
  exit 0;
}

while ( my ($input, $output) = each %GENERATE ) {
  my @cmd = ('./cmmg.pl', $input, '>', $output);
  my $cmd = join ' ', @cmd;
  print "$cmd\n";
  system $cmd
    and die "$cmd failed: $?\n";
}
