#!/usr/bin/perl -w

use Data::Dumper;
use Getopt::Long 'GetOptions';
use strict;

#==================== config =====================
my $logfile    = 'test.log';
my $output_dir = 'output';
my $conf_dir   = 'conf';

my $fwknopCmd  = '../client/.libs/fwknop';
my $fwknopdCmd = '../server/.libs/fwknopd';
#================== end config ===================

my $passed = 0;
my $failed = 0;
my $executed = 0;
my $test_include = '';
my @tests_to_include = ();
my $test_exclude = '';
my @tests_to_exclude = ();
my $list_mode = 0;
my $loopback_intf = 'lo';  ### default on linux
my $prepare_results = 0;
my $current_test_file = '';
my $help = 0;
my $YES = 1;
my $NO  = 0;
my $APPEND = 1;
my $CREATE = 0;
my $PRINT_LEN = 68;
my $REQUIRED = 1;
my $OPTIONAL = 0;

exit 1 unless GetOptions(
    'Prepare-results'   => \$prepare_results,
    'fwknop-path=s'     => \$fwknopCmd,
    'fwknopd-path=s'    => \$fwknopdCmd,
    'loopback-intf=s'   => \$loopback_intf,
    'test-include=s'    => \$test_include,
    'include=s'         => \$test_include,  ### synonym
    'test-exclude=s'    => \$test_exclude,
    'exclude=s'         => \$test_exclude,  ### synonym
    'List-mode'         => \$list_mode,
    'help'              => \$help
);

&usage() if $help;

### main array that defines the tests we will run
my @tests = (
    {
        'category' => 'build',
        'detail'   => 'recompile and look for compilation warnings',
        'err_msg'  => 'compile warnings exist',
        'function' => \&compile_warnings,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'new binary exists',
        'err_msg'  => 'binary not found',
        'function' => \&binary_exists_fwknop_client,
        'fatal'    => $YES
    },
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'new binary exists',
        'err_msg'  => 'binary not found',
        'function' => \&binary_exists_fwknopd_server,
        'fatal'    => $YES
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'Position Independent Executable (PIE)',
        'err_msg'  => 'non PIE binary (fwknop client)',
        'function' => \&pie_binary_fwknop_client,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'Position Independent Executable (PIE)',
        'err_msg'  => 'non PIE binary (fwknopd server)',
        'function' => \&pie_binary_fwknopd_server,,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'stack protected binary',
        'err_msg'  => 'non stack protected binary (fwknop client)',
        'function' => \&stack_protected_binary_fwknop_client,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'stack protected binary',
        'err_msg'  => 'non stack protected binary (fwknopd server)',
        'function' => \&stack_protected_binary_fwknopd_server,,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'fortify source functions',
        'err_msg'  => 'source functions not fortified (fwknop client)',
        'function' => \&fortify_source_functions_binary_fwknop_client,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'fortify source functions',
        'err_msg'  => 'source functions not fortified (fwknopd server)',
        'function' => \&fortify_source_functions_binary_fwknopd_server,,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'read-only relocations',
        'err_msg'  => 'no read-only relocations (fwknop client)',
        'function' => \&read_only_relocations_binary_fwknop_client,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'read-only relocations',
        'err_msg'  => 'no read-only relocations (fwknopd server)',
        'function' => \&read_only_relocations_binary_fwknopd_server,,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'immediate binding',
        'err_msg'  => 'no immediate binding (fwknop client)',
        'function' => \&immediate_binding_binary_fwknop_client,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'immediate binding',
        'err_msg'  => 'no immediate binding (fwknopd server)',
        'function' => \&immediate_binding_binary_fwknopd_server,,
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'detail'   => 'client SPA packet generation',
        'err_msg'  => 'could not generate SPA packet',
        'function' => \&generate_basic_spa_packet,
        'fatal'    => $YES
    }
);

my %test_keys = (
    'category'    => $REQUIRED,
    'subcategory' => $OPTIONAL,
    'detail'      => $REQUIRED,
    'function'    => $REQUIRED,
    'fatal'       => $OPTIONAL,
);

### make sure everything looks as expected before continuing
&init();

&logr("\n");

for my $test_hr (@tests) {
    &run_test($test_hr);
}

&logr("\n[+] passed/failed/executed: $passed/$failed/$executed tests\n\n");

exit 0;

#===================== end main =======================

sub run_test() {
    my $test_hr = shift;

    return unless &process_include_exclude($test_hr);

    $executed++;

    $current_test_file = "$output_dir/$executed.test";

    my $msg = "[$test_hr->{'category'}]";
    $msg .= " [$test_hr->{'subcategory'}]" if $test_hr->{'subcategory'};
    $msg .= " $test_hr->{'detail'}";

    if ($list_mode) {
        print $msg, "\n";
        return;
    }

    &dots_print($msg);

    if (&{$test_hr->{'function'}}) {
        &logr("pass ($executed)\n");
        $passed++;
    } else {
        &logr("fail ($executed)\n");
        $failed++;

        if ($test_hr->{'fatal'} eq $YES) {
            die "[*] required test failed, exiting.";
        }
    }

    return;
}

sub process_include_exclude() {
    my $test_hr = shift;

    ### inclusions/exclusions
    if (@tests_to_include) {
        my $found = 0;
        for my $test (@tests_to_include) {
            if ($test_hr->{'category'} =~ /$test)/) {
                $found = 1;
                last;
            }
        }
        return 1 unless $found;
    }
    if (@tests_to_exclude) {
        my $found = 0;
        for my $test (@tests_to_exclude) {
            if ($test_hr->{'category'} =~ /$test/) {
                $found = 1;
                last;
            }
        }
        return 0 if $found;
    }
    return 1;
}

sub generate_basic_spa_packet() {
    return 1;
}

sub compile_warnings() {

    return 0 unless &run_cmd('make -C .. clean', $CREATE);
    return 0 unless &run_cmd('make -C ..', $APPEND);

    ### look for compilation warnings - something like:

    ### warning: ‘test’ is used uninitialized in this function
    return 0 if &file_find_regex([qr/\swarning:\s/], $current_test_file);

    return 1;
}

sub binary_exists_fwknop_client() {
    return 0 unless -e $fwknopCmd and -x $fwknopCmd;
    return 1;
}

sub binary_exists_fwknopd_server() {
    return 0 unless -e $fwknopdCmd and -x $fwknopdCmd;
    return 1;
}

### check for PIE
sub pie_binary_fwknop_client() {
    return 0 unless &run_cmd("./hardening-check $fwknopCmd", $CREATE);
    return 0 if &file_find_regex([qr/Position\sIndependent.*:\sno/i],
        $current_test_file);
    return 1;
}

sub pie_binary_fwknopd_server() {
    return 0 unless &run_cmd("./hardening-check $fwknopdCmd", $CREATE);
    return 0 if &file_find_regex([qr/Position\sIndependent.*:\sno/i],
        $current_test_file);
    return 1;
}

### check for stack protection
sub stack_protected_binary_fwknop_client() {
    return 0 unless &run_cmd("./hardening-check $fwknopCmd", $CREATE);
    return 0 if &file_find_regex([qr/Stack\sprotected.*:\sno/i],
        $current_test_file);
    return 1;
}

sub stack_protected_binary_fwknopd_server() {
    return 0 unless &run_cmd("./hardening-check $fwknopdCmd", $CREATE);
    return 0 if &file_find_regex([qr/Stack\sprotected:\sno/i],
        $current_test_file);
    return 1;
}

### check for fortified source functions
sub fortify_source_functions_binary_fwknop_client() {
    return 0 unless &run_cmd("./hardening-check $fwknopCmd", $CREATE);
    return 0 if &file_find_regex([qr/Fortify\sSource\sfunctions:\sno/i],
        $current_test_file);
    return 1;
}

sub fortify_source_functions_binary_fwknopd_server() {
    return 0 unless &run_cmd("./hardening-check $fwknopdCmd", $CREATE);
    return 0 if &file_find_regex([qr/Fortify\sSource\sfunctions:\sno/i],
        $current_test_file);
    return 1;
}

### check for read-only relocations
sub read_only_relocations_binary_fwknop_client() {
    return 0 unless &run_cmd("./hardening-check $fwknopCmd", $CREATE);
    return 0 if &file_find_regex([qr/Read.only\srelocations:\sno/i],
        $current_test_file);
    return 1;
}

sub read_only_relocations_binary_fwknopd_server() {
    return 0 unless &run_cmd("./hardening-check $fwknopdCmd", $CREATE);
    return 0 if &file_find_regex([qr/Read.only\srelocations:\sno/i],
        $current_test_file);
    return 1;
}

### check for immediate binding
sub immediate_binding_binary_fwknop_client() {
    return 0 unless &run_cmd("./hardening-check $fwknopCmd", $CREATE);
    return 0 if &file_find_regex([qr/Immediate\sbinding:\sno/i],
        $current_test_file);
    return 1;
}

sub immediate_binding_binary_fwknopd_server() {
    return 0 unless &run_cmd("./hardening-check $fwknopdCmd", $CREATE);
    return 0 if &file_find_regex([qr/Immediate\sbinding:\sno/i],
        $current_test_file);
    return 1;
}

sub run_cmd() {
    my ($cmd, $file_mode) = @_;

    if ($file_mode == $APPEND) {
        open F, ">> $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        print F "CMD: $cmd\n";
        close F;
    } else {
        open F, "> $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        print F "CMD: $cmd\n";
        close F;
    }
    my $rv = ((system "$cmd >> $current_test_file 2>&1") >> 8);
    if ($rv == 0) {
        return 1;
    }
    return 0;
}

sub pass() {
    return;
}

sub dots_print() {
    my $msg = shift;
    &logr($msg);
    my $dots = '';
    for (my $i=length($msg); $i < $PRINT_LEN; $i++) {
        $dots .= '.';
    }
    &logr($dots);
    return;
}

sub init() {

    ### validate test hashes
    my $hash_num = 0;
    for my $test_hr (@tests) {
        for my $key (keys %test_keys) {
            if ($test_keys{$key} == $REQUIRED) {
                die "[*] Missing '$key' element in hash: $hash_num"
                    unless defined $test_hr->{$key};
            } else {
                $test_hr->{$key} = '' unless defined $test_hr->{$key};
            }
        }
        $hash_num++;
    }

    $|++; ### turn off buffering

    $< == 0 && $> == 0 or
        die "[*] $0: You must be root (or equivalent ",
            "UID 0 account) to effectively test fwknop";

    die "[*] $conf_dir directory does not exist." unless -d $conf_dir;
    unless (-d $output_dir) {
        mkdir $output_dir or die "[*] Could not mkdir $output_dir: $!";
    }

    for my $file (glob("$output_dir/*.test")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    if (-e $logfile) {
        unlink $logfile or die $!;
    }

    unless ((&find_command('cc') or &find_command('gcc')) and &find_command('make')) {
        ### disable compilation checks
        push @tests_to_exclude, 'compile';
    }

    if ($test_include) {
        @tests_to_include = split /\s*,\s*/, $test_include;
    }
    if ($test_exclude) {
        @tests_to_exclude = split /\s*,\s*/, $test_exclude;
    }

    return;
}

sub file_find_regex() {
    my ($re_ar, $file) = @_;

    my $found = 0;

    open F, "< $file" or die "[*] Could not open $file: $!";
    LINE: while (<F>) {
        my $line = $_;
        for my $re (@$re_ar) {
            if ($line =~ $re) {
                $found = 1;
                last LINE;
            }
        }
    }
    close F;
    
    return $found;
}

sub find_command() {
    my $cmd = shift;

    my $found = 0;
    open C, "which $cmd |" or die "[*] Could not execute: which $cmd: $!";
    while (<C>) {
        if (m|/.*$cmd$|) {
            $found = 1;
            last;
        }
    }
    close C;
    return $found;
}

sub logr() {
    my $msg = shift;
    print STDOUT $msg;
    open F, ">> $logfile" or die $!;
    print F $msg;
    close F;
    return;
}
