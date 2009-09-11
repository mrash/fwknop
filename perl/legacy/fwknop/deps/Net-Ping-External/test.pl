# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; $num_tests = 6; print "1..$num_tests\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::Ping::External qw(ping);
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

%test_names = (1 => "use Net::Ping::External qw(ping)",
	       2 => "ping(host => '127.0.0.1')",
	       3 => "ping(host => '127.0.0.1', timeout => 5)",
	       4 => "ping(host => 'some.non.existent.host')",
	       5 => "ping(host => '127.0.0.1', count => 10)",
	       6 => "ping(host => '127.0.0.1', size => 32)"
	      );

@passed = ();
@failed = ();
push @passed, 1 if $loaded;
push @failed, 1 unless $loaded;

eval{ $ret = ping(host => '127.0.0.1') };
if (!$@ && $ret) {
  print "ok 2\n";
  push @passed, 2;
}
else {
  print "not ok 2\n";
  push @failed, 2;
}

eval { $ret = ping(host => '127.0.0.1', timeout => 5) };
if (!$@ && $ret) {
  print "ok 3\n";
  push @passed, 3;
} 
else {
  print "not ok 3\n";
  push @failed, 3;
}

eval { $ret = ping(host => 'some.non.existent.host') };
if (!$@ && !$ret) {
  print "ok 4\n";
  push @passed, 4;
}
else {
  print "not ok 4\n";
  push @failed, 4;
}

eval { $ret = ping(host => '127.0.0.1', count => 2) };
if (!$@ && $ret) {
  print "ok 5\n";
  push @passed, 5;
}
else {
  print "not ok 5\n";
  push @failed, 5;
}

eval { $ret = ping(host => '127.0.0.1', size => 32) };
if (!$@ && $ret) {
  print "ok 6\n";
  push @passed, 6;
}
else {
  print "not ok 6\n";
  push @failed, 6;
}

print "\nRunning a more verbose test suite.";
print "\n-------------------------------------------------\n";
print "Net::Ping::External version: ", $Net::Ping::External::VERSION, "\n";
print scalar(@passed), "/$num_tests tests passed.\n\n";

if (@passed) {
  print "Successful tests:\n";
  foreach (@passed) {
    print "$test_names{$_}\n";
  }
}

if (@failed) {
  print "\nFailed tests:\n";
  foreach (@failed) {
    print "$test_names{$_}\n";
  }
}

print "\nOperating system according to perl: ", $^O, "\n";
print "Operating system according to `uname -a` (if available):\n";
print `uname -a`;
print "Perl version: ";
@output = `perl -v`;
print @output[1..1];
print "-------------------------------------------------\n";
print "If any of the above tests failed, please e-mail the bits between the dashed\n";
print "lines to colinm\@cpan.org. This will help me in fixing this code for maximum\n";
print "portability to your platform. Thanks!\n";


