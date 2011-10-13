#!/usr/bin/perl -w

use Data::Dumper;
use Getopt::Long 'GetOptions';
use strict;

#==================== config =====================
my $logfile    = 'test.log';
my $output_dir = 'output';
my $conf_dir   = 'conf';

my $default_conf        = "$conf_dir/default_fwknopd.conf";
my $default_access_conf = "$conf_dir/default_access.conf";

my $fwknopCmd  = '../client/.libs/fwknop';
my $fwknopdCmd = '../server/.libs/fwknopd';
my $libfko_bin = '../lib/.libs/libfko.so.0.0.3';
#================== end config ===================

my $passed = 0;
my $failed = 0;
my $executed = 0;
my $test_include = '';
my @tests_to_include = ();
my $test_exclude = '';
my @tests_to_exclude = ();
my $list_mode = 0;
my $firewall = '';
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
    'firewall=s'        => \$firewall,
    'libfko-path=s'     => \$libfko_bin,
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
        'function' => \&binary_exists,
        'binary'   => $fwknopCmd,
        'fatal'    => $YES
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'Position Independent Executable (PIE)',
        'err_msg'  => 'non PIE binary (fwknop client)',
        'function' => \&pie_binary,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'stack protected binary',
        'err_msg'  => 'non stack protected binary (fwknop client)',
        'function' => \&stack_protected_binary,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'fortify source functions',
        'err_msg'  => 'source functions not fortified (fwknop client)',
        'function' => \&fortify_source_functions,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'read-only relocations',
        'err_msg'  => 'no read-only relocations (fwknop client)',
        'function' => \&read_only_relocations,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'immediate binding',
        'err_msg'  => 'no immediate binding (fwknop client)',
        'function' => \&immediate_binding,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },

    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'new binary exists',
        'err_msg'  => 'binary not found',
        'function' => \&binary_exists,
        'binary'   => $fwknopdCmd,
        'fatal'    => $YES
    },

    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'Position Independent Executable (PIE)',
        'err_msg'  => 'non PIE binary (fwknopd server)',
        'function' => \&pie_binary,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'stack protected binary',
        'err_msg'  => 'non stack protected binary (fwknopd server)',
        'function' => \&stack_protected_binary,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'fortify source functions',
        'err_msg'  => 'source functions not fortified (fwknopd server)',
        'function' => \&fortify_source_functions,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'read-only relocations',
        'err_msg'  => 'no read-only relocations (fwknopd server)',
        'function' => \&read_only_relocations,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'immediate binding',
        'err_msg'  => 'no immediate binding (fwknopd server)',
        'function' => \&immediate_binding,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },

    {
        'category' => 'build',
        'subcategory' => 'libfko',
        'detail'   => 'new binary exists',
        'err_msg'  => 'binary not found',
        'function' => \&binary_exists,
        'binary'   => $libfko_bin,
        'fatal'    => $YES
    },
    {
        'category' => 'build',
        'subcategory' => 'libfko',
        'detail'   => 'stack protected binary',
        'err_msg'  => 'non stack protected binary (libfko)',
        'function' => \&stack_protected_binary,
        'binary'   => $libfko_bin,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'libfko',
        'detail'   => 'fortify source functions',
        'err_msg'  => 'source functions not fortified (libfko)',
        'function' => \&fortify_source_functions,
        'binary'   => $libfko_bin,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'libfko',
        'detail'   => 'read-only relocations',
        'err_msg'  => 'no read-only relocations (libfko)',
        'function' => \&read_only_relocations,
        'binary'   => $libfko_bin,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'libfko',
        'detail'   => 'immediate binding',
        'err_msg'  => 'no immediate binding (libfko)',
        'function' => \&immediate_binding,
        'binary'   => $libfko_bin,
        'fatal'    => $NO
    },

    {
        'category' => 'preliminaries',
        'subcategory' => 'client',
        'detail'   => 'usage info',
        'err_msg'  => 'could not get usage info',
        'function' => \&usage_info,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'preliminaries',
        'subcategory' => 'client',
        'detail'   => 'getopt() no such argument',
        'err_msg'  => 'getopt() allowed non-existant argument',
        'function' => \&no_such_arg,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'preliminaries',
        'subcategory' => 'client',
        'detail'   => 'expected code version',
        'err_msg'  => 'code version mis-match',
        'function' => \&expected_code_version,
        'cmdline'  => "$fwknopCmd --version",
        'fatal'    => $NO
    },

    {
        'category' => 'preliminaries',
        'subcategory' => 'server',
        'detail'   => 'usage info',
        'err_msg'  => 'could not get usage info',
        'function' => \&usage_info,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'preliminaries',
        'subcategory' => 'server',
        'detail'   => 'getopt() no such argument',
        'err_msg'  => 'getopt() allowed non-existant argument',
        'function' => \&no_such_arg,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'preliminaries',
        'subcategory' => 'server',
        'detail'   => 'expected code version',
        'err_msg'  => 'code version mis-match',
        'function' => \&expected_code_version,
        'cmdline'  => "$fwknopdCmd -c $default_conf -a $default_access_conf --version",
        'fatal'    => $NO
    },
    {
        'category' => 'preliminaries',
        'detail'   => 'collecting system specifics',
        'err_msg'  => 'could not get complete system specs',
        'function' => \&specs,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'detail'   => 'dump config',
        'err_msg'  => 'could not dump configuration',
        'function' => \&dump_config,
        'cmdline'  => "$fwknopdCmd -c $default_conf -a $default_access_conf --dump-config",
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
    'binary'      => $OPTIONAL,
    'cmdline'     => $OPTIONAL,
    'fatal'       => $OPTIONAL,
);

### make sure everything looks as expected before continuing
&init();

&logr("\n[+] Starting the fwknop test suite (firewall: $firewall)...\n\n");

for my $test_hr (@tests) {
    &run_test($test_hr);
}

&logr("\n[+] passed/failed/executed: $passed/$failed/$executed tests\n\n");

exit 0;

#===================== end main =======================

sub run_test() {
    my $test_hr = shift;

    return unless &process_include_exclude($test_hr);

    my $msg = "[$test_hr->{'category'}]";
    $msg .= " [$test_hr->{'subcategory'}]" if $test_hr->{'subcategory'};
    $msg .= " $test_hr->{'detail'}";

    if ($list_mode) {
        print $msg, "\n";
        return;
    }

    &dots_print($msg);

    $executed++;
    $current_test_file = "$output_dir/$executed.test";

    if (&{$test_hr->{'function'}}($test_hr)) {
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

return 1;
    return 0 unless &run_cmd('make -C .. clean', $CREATE);
    return 0 unless &run_cmd('make -C ..', $APPEND);

    ### look for compilation warnings - something like:

    ### warning: ‘test’ is used uninitialized in this function
    return 0 if &file_find_regex([qr/\swarning:\s/], $current_test_file);

    return 1;
}

sub binary_exists() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    return 0 unless -e $test_hr->{'binary'} and -x $test_hr->{'binary'};
    return 1;
}

sub expected_code_version() {
    my $test_hr = shift;

    unless (-e '../VERSION') {
        &write_test_file("[-] ../VERSION file does not exist.\n", $CREATE);
        return 0;
    }

    open F, "< ../VERSION" or die $!;
    my $line = <F>;
    close F;
    if ($line =~ /(\d.*\d)/) {
        my $version = $1;
        return 0 unless &run_cmd($test_hr->{'cmdline'}, $APPEND);
        return 1 if &file_find_regex([qr/$version/], $current_test_file);
    }
    return 0;
}

sub dump_config() {
    my $test_hr = shift;

    return 0 unless &run_cmd($test_hr->{'cmdline'}, $CREATE);
    return 1;
}

sub usage_info() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    return 0 unless &run_cmd("$test_hr->{'binary'} -h", $CREATE);
    return 1;
}

sub no_such_arg() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    return 0 if &run_cmd("$test_hr->{'binary'} --no-such-arg", $CREATE);
    return 1;
}

### check for PIE
sub pie_binary() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}", $CREATE);
    return 0 if &file_find_regex([qr/Position\sIndependent.*:\sno/i],
        $current_test_file);
    return 1;
}

### check for stack protection
sub stack_protected_binary() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}", $CREATE);
    return 0 if &file_find_regex([qr/Stack\sprotected.*:\sno/i],
        $current_test_file);
    return 1;
}

### check for fortified source functions
sub fortify_source_functions() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}", $CREATE);
    return 0 if &file_find_regex([qr/Fortify\sSource\sfunctions:\sno/i],
        $current_test_file);
    return 1;
}

### check for read-only relocations
sub read_only_relocations() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}", $CREATE);
    return 0 if &file_find_regex([qr/Read.only\srelocations:\sno/i],
        $current_test_file);
    return 1;
}

### check for immediate binding
sub immediate_binding() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}", $CREATE);
    return 0 if &file_find_regex([qr/Immediate\sbinding:\sno/i],
        $current_test_file);
    return 1;
}

sub specs() {
    my $cmd = '';
    if ($firewall eq 'iptables') {
        $cmd = "iptables -v -n -L";
    } else {
        $cmd = "ipfw list";
    }
    &run_cmd($cmd, $CREATE);
    for my $cmd (
        'uname -a',
        'uptime',
        'ifconfig -a',
        'ls -l /etc', 'if [ -e /etc/issue ]; then cat /etc/issue; fi',
        'if [ `which iptables` ]; then iptables -V; fi',
        'if [ -e /proc/cpuinfo ]; then cat /proc/cpuinfo; fi',
        'if [ -e /proc/config.gz ]; then zcat /proc/config.gz; fi',
        'if [ `which gpg` ]; then gpg --version; fi',
        'if [ `which tcpdump` ]; then ldd `which tcpdump`; fi',
        "ldd $fwknopCmd",
        "ldd $fwknopdCmd",
        "ldd $libfko_bin",
        'ls -l /usr/lib/*pcap*',
        'ls -l /usr/local/lib/*pcap*',
        'ls -l /usr/lib/*fko*',
        'ls -l /usr/local/lib/*fko*',
    ) {
        &run_cmd($cmd, $APPEND);
    }
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
    die "[*] default config $default_conf does not exist" unless -e $default_conf;
    die "[*] default access config $default_access_conf does not exist"
        unless -e $default_access_conf;

    unless (-d $output_dir) {
        mkdir $output_dir or die "[*] Could not mkdir $output_dir: $!";
    }

    for my $file (glob("$output_dir/*.test")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    if (-e $logfile) {
        unlink $logfile or die $!;
    }

    if ($test_include) {
        @tests_to_include = split /\s*,\s*/, $test_include;
    }
    if ($test_exclude) {
        @tests_to_exclude = split /\s*,\s*/, $test_exclude;
    }

    ### make sure no fwknopd instance is currently running
    die "[*] Please stop the running fwknopd instance."
        if &is_fwknopd_running();

    unless ((&find_command('cc') or &find_command('gcc')) and &find_command('make')) {
        ### disable compilation checks
        push @tests_to_exclude, 'build';
    }

    ### detect the installed firewall
    &detect_firewall();

    return;
}

sub is_fwknopd_running() {

    my $cmd = "$fwknopdCmd -c $default_conf -a $default_access_conf --status";

    my $is_running = 1;
    open C, "$cmd |" or die "[*] Could not execute $cmd: $!";
    while (<C>) {
        if (/no\s+running/i) {
            $is_running = 0;
            last;
        }
    }
    close C;

    return $is_running;
}

sub detect_firewall() {
    unless ($firewall) {
        for my $fw qw/iptables pf ipfw/ {
            my $path = &find_command($fw);
            if ($path) {
                $firewall = $path;
                last;
            }
        }
    }

    unless ($firewall) {
        die "[*] Could not find firewall binary, use --firewall";
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

    my $path = '';
    open C, "which $cmd |" or die "[*] Could not execute: which $cmd: $!";
    while (<C>) {
        if (m|^(/.*$cmd)$|) {
            $path = $1;
            last;
        }
    }
    close C;
    return $path;
}

sub write_test_file() {
    my ($msg, $file_mode) = @_;

    if ($file_mode == $APPEND) {
        open F, ">> $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        print F $msg;
        close F;
    } else {
        open F, "> $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        print F $msg;
        close F;
    }
    return;
}

sub logr() {
    my $msg = shift;
    print STDOUT $msg;
    open F, ">> $logfile" or die $!;
    print F $msg;
    close F;
    return;
}
