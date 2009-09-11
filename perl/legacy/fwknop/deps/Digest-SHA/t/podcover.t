my $MODULE;

BEGIN {
	$MODULE = (-d "src") ? "Digest::SHA" : "Digest::SHA::PurePerl";
	eval "require $MODULE" || die $@;
	$MODULE->import(qw());
}

BEGIN {
	if ($ENV{PERL_CORE}) {
		chdir 't' if -d 't';
		@INC = '../lib';
	}
}

BEGIN {
	eval "use Test::More";
	if ($@) {
		print "1..0 # Skipped: Test::More not installed\n";
		exit;
	}
}

eval "use Test::Pod::Coverage 0.08";
plan skip_all => "Test::Pod::Coverage 0.08 required for testing POD coverage" if $@;

my @privfcns = ();

if ($MODULE eq "Digest::SHA") {
	@privfcns = qw(
		Addfile
		B64digest
		Hexdigest
		shaclose
		shadump
		shadup
		shaload
		shaopen
		sharewind
		shawrite
	);
}

all_pod_coverage_ok( { also_private => \@privfcns } );
