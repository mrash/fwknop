#!/usr/bin/perl -w

use IO::Socket;
use Data::Dumper;
use Getopt::Long 'GetOptions';
use strict;

#==================== config =====================
my $logfile        = 'test.log';
my $local_key_file = 'local_spa.key';
my $output_dir     = 'output';
my $lib_dir        = '../lib/.libs';
my $conf_dir       = 'conf';
my $run_dir        = 'run';
my $configure_path = '../configure';
my $cmd_out_tmp    = 'cmd.out';
my $server_cmd_tmp = 'server_cmd.out';

my $default_conf        = "$conf_dir/default_fwknopd.conf";
my $default_access_conf = "$conf_dir/default_access.conf";
my $default_digest_file = "$run_dir/digest.cache";
my $default_pid_file    = "$run_dir/fwknopd.pid";

my $fwknopCmd  = '../client/.libs/fwknop';
my $fwknopdCmd = '../server/.libs/fwknopd';
my $libfko_bin = "$lib_dir/libfko.so.0.0.3";

my $sniff_alarm = 20;

my $loopback_ip = '127.0.0.1';
my $fake_ip     = '127.0.0.2';
my $default_spa_port = 62201;
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
my $current_test_file  = "$output_dir/init";
my $server_output_file = '';
my $enable_recompilation_warnings_check = 0;
my $sudo_path = '';
my $help = 0;
my $YES = 1;
my $NO  = 0;
my $PRINT_LEN = 68;
my $FORCE_STOP = 1;
my $NO_FORCE_STOP = 2;
my $USE_PREDEF_PKTS = 1;
my $USE_CLIENT = 2;
my $REQUIRE_FW_RULE = 1;
my $NO_FW_RULE = 2;
my $REQUIRED = 1;
my $OPTIONAL = 0;

exit 1 unless GetOptions(
    'Prepare-results'   => \$prepare_results,
    'fwknop-path=s'     => \$fwknopCmd,
    'fwknopd-path=s'    => \$fwknopdCmd,
    'libfko-path=s'     => \$libfko_bin,
    'loopback-intf=s'   => \$loopback_intf,
    'test-include=s'    => \$test_include,
    'include=s'         => \$test_include,  ### synonym
    'test-exclude=s'    => \$test_exclude,
    'exclude=s'         => \$test_exclude,  ### synonym
    'enable-recompile-check' => \$enable_recompilation_warnings_check,
    'List-mode'         => \$list_mode,
    'help'              => \$help
);

&usage() if $help;

my $default_client_args = "$fwknopCmd -A tcp/22 -a $fake_ip " .
    "-D $loopback_ip --get-key $local_key_file --verbose";

my $default_server_conf_args = "-c $default_conf -a $default_access_conf " .
    "-d $default_digest_file -p $default_pid_file";

### point the compiled binaries at the local libary path
### instead of any installed libfko instance
$ENV{'LD_LIBRARY_PATH'} = $lib_dir;

### main array that defines the tests we will run
my @tests = (
    {
        'category' => 'recompilation',
        'detail'   => 'recompile and look for compilation warnings',
        'err_msg'  => 'compile warnings exist',
        'function' => \&compile_warnings,
        'fatal'    => $NO
    },
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'binary exists',
        'err_msg'  => 'binary not found',
        'function' => \&binary_exists,
        'binary'   => $fwknopCmd,
        'fatal'    => $YES
    },
    {
        'category' => 'build security',
        'subcategory' => 'client',
        'detail'   => 'Position Independent Executable (PIE)',
        'err_msg'  => 'non PIE binary (fwknop client)',
        'function' => \&pie_binary,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
        'subcategory' => 'client',
        'detail'   => 'stack protected binary',
        'err_msg'  => 'non stack protected binary (fwknop client)',
        'function' => \&stack_protected_binary,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
        'subcategory' => 'client',
        'detail'   => 'fortify source functions',
        'err_msg'  => 'source functions not fortified (fwknop client)',
        'function' => \&fortify_source_functions,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
        'subcategory' => 'client',
        'detail'   => 'read-only relocations',
        'err_msg'  => 'no read-only relocations (fwknop client)',
        'function' => \&read_only_relocations,
        'binary'   => $fwknopCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
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
        'detail'   => 'binary exists',
        'err_msg'  => 'binary not found',
        'function' => \&binary_exists,
        'binary'   => $fwknopdCmd,
        'fatal'    => $YES
    },

    {
        'category' => 'build security',
        'subcategory' => 'server',
        'detail'   => 'Position Independent Executable (PIE)',
        'err_msg'  => 'non PIE binary (fwknopd server)',
        'function' => \&pie_binary,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
        'subcategory' => 'server',
        'detail'   => 'stack protected binary',
        'err_msg'  => 'non stack protected binary (fwknopd server)',
        'function' => \&stack_protected_binary,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
        'subcategory' => 'server',
        'detail'   => 'fortify source functions',
        'err_msg'  => 'source functions not fortified (fwknopd server)',
        'function' => \&fortify_source_functions,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
        'subcategory' => 'server',
        'detail'   => 'read-only relocations',
        'err_msg'  => 'no read-only relocations (fwknopd server)',
        'function' => \&read_only_relocations,
        'binary'   => $fwknopdCmd,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
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
        'detail'   => 'binary exists',
        'err_msg'  => 'binary not found',
        'function' => \&binary_exists,
        'binary'   => $libfko_bin,
        'fatal'    => $YES
    },
    {
        'category' => 'build security',
        'subcategory' => 'libfko',
        'detail'   => 'stack protected binary',
        'err_msg'  => 'non stack protected binary (libfko)',
        'function' => \&stack_protected_binary,
        'binary'   => $libfko_bin,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
        'subcategory' => 'libfko',
        'detail'   => 'fortify source functions',
        'err_msg'  => 'source functions not fortified (libfko)',
        'function' => \&fortify_source_functions,
        'binary'   => $libfko_bin,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
        'subcategory' => 'libfko',
        'detail'   => 'read-only relocations',
        'err_msg'  => 'no read-only relocations (libfko)',
        'function' => \&read_only_relocations,
        'binary'   => $libfko_bin,
        'fatal'    => $NO
    },
    {
        'category' => 'build security',
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
        'cmdline'  => "$fwknopdCmd -c $default_conf -a " .
            "$default_access_conf --version",
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
        'cmdline'  => "$fwknopdCmd -c $default_conf " .
            "-a $default_access_conf --dump-config",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'detail'   => 'override config',
        'err_msg'  => 'could not override configuration',
        'function' => \&override_config,
        'cmdline'  => "$fwknopdCmd $default_server_conf_args " .
            "-O $conf_dir/override_fwknopd.conf --dump-config",
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '--get-key path validation',
        'err_msg'  => 'accepted improper --get-key path',
        'function' => \&non_get_key_path,
        'cmdline'  => "$fwknopCmd -A tcp/22 -s $fake_ip " .
            "-D $loopback_ip --get-key not/there",
        'fatal'    => $YES
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'require [-s|-R|-a]',
        'err_msg'  => 'allowed null allow IP',
        'function' => \&no_allow_ip,
        'cmdline'  => "$fwknopCmd -D $loopback_ip",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '--allow-ip <IP> valid IP',
        'err_msg'  => 'permitted invalid --allow-ip arg',
        'function' => \&invalid_allow_ip,
        'cmdline'  => "$fwknopCmd -A tcp/22 -a invalidIP -D $loopback_ip",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '-A <proto>/<port> specification',
        'err_msg'  => 'permitted invalid -A <proto>/<port>',
        'function' => \&invalid_proto,
        'cmdline'  => "$fwknopCmd -A invalid/22 -a $fake_ip -D $loopback_ip",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'generate SPA packet',
        'err_msg'  => 'could not generate SPA packet',
        'function' => \&generate_spa_packet,
        'cmdline'  => $default_client_args,
        'fatal'    => $YES
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'list current fwknopd fw rules',
        'err_msg'  => 'could not list current fwknopd fw rules',
        'function' => \&fw_list,
        'cmdline'  => "$fwknopdCmd $default_server_conf_args --fw-list",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'list all current fw rules',
        'err_msg'  => 'could not list all current fw rules',
        'function' => \&fw_list_all,
        'cmdline'  => "$fwknopdCmd $default_server_conf_args --fw-list-all",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'flush current firewall rules',
        'err_msg'  => 'could not flush current fw rules',
        'function' => \&fw_flush,
        'cmdline'  => "$fwknopdCmd $default_server_conf_args --fw-flush",
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'start',
        'err_msg'  => 'start error',
        'function' => \&server_start,
        'fwknopd_cmdline'  => "$fwknopdCmd $default_server_conf_args " .
            "-i $loopback_intf --foreground --verbose",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'stop',
        'err_msg'  => 'stop error',
        'function' => \&server_stop,
        'fwknopd_cmdline'  => "$fwknopdCmd $default_server_conf_args " .
            "-i $loopback_intf --foreground --verbose",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'write PID',
        'err_msg'  => 'did not write PID',
        'function' => \&write_pid,
        'fwknopd_cmdline'  => "$fwknopdCmd $default_server_conf_args " .
            "-i $loopback_intf --foreground --verbose",
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => '--packet-limit 1 exit',
        'err_msg'  => 'did not exit after one packet',
        'function' => \&server_packet_limit,
        'fwknopd_cmdline'  => "$fwknopdCmd $default_server_conf_args " .
            "-i $loopback_intf --packet-limit 1 --foreground --verbose",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'ignore packets < min SPA len (140)',
        'err_msg'  => 'did not ignore small packets',
        'function' => \&server_ignore_small_packets,
        'fwknopd_cmdline'  => "$fwknopdCmd $default_server_conf_args " .
            "-i $loopback_intf --packet-limit 1 --foreground --verbose",
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA ops',
        'subcategory' => 'client+server',
        'detail'   => 'complete SPA cycle',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&basic_rijndael_spa,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "$fwknopdCmd $default_server_conf_args " .
            "-i $loopback_intf --foreground --verbose",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA ops',
        'subcategory' => 'client+server',
        'detail'   => 'replay attack detection',
        'err_msg'  => 'could not detect replay attack',
        'function' => \&replay_detection_rijndael,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "$fwknopdCmd $default_server_conf_args " .
            "-i $loopback_intf --foreground --verbose",
        'fatal'    => $NO
    },


);

my %test_keys = (
    'category'        => $REQUIRED,
    'subcategory'     => $OPTIONAL,
    'detail'          => $REQUIRED,
    'function'        => $REQUIRED,
    'binary'          => $OPTIONAL,
    'cmdline'         => $OPTIONAL,
    'fwknopd_cmdline' => $OPTIONAL,
    'fatal'           => $OPTIONAL,
);

### make sure everything looks as expected before continuing
&init();

&logr("\n[+] Starting the fwknop test suite...\n\n");

### main loop through all of the tests
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
    $current_test_file  = "$output_dir/$executed.test";
    $server_output_file = "$output_dir/${executed}_fwknopd.test";

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
            if ($test_hr->{'category'} =~ /$test/) {
                $found = 1;
                last;
            }
        }
        return 0 unless $found;
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

sub compile_warnings() {

    if ($sudo_path) {
        my $username = getpwuid((stat($configure_path))[4]);
        die "[*] Could not determine $configure_path owner"
            unless $username;

        return 0 unless &run_cmd("$sudo_path -u $username make -C .. clean",
            $cmd_out_tmp, $current_test_file);
        return 0 unless &run_cmd("$sudo_path -u $username make -C ..",
            $cmd_out_tmp, $current_test_file);

    } else {

        return 0 unless &run_cmd('make -C .. clean',
            $cmd_out_tmp, $current_test_file);
        return 0 unless &run_cmd('make -C ..',
            $cmd_out_tmp, $current_test_file);

    }

    ### look for compilation warnings - something like:
    ###     warning: ‘test’ is used uninitialized in this function
    return 0 if &file_find_regex([qr/\swarning:\s/], $current_test_file);

    ### the new binaries should exist
    unless (-e $fwknopCmd and -x $fwknopCmd) {
        &write_test_file("[-] $fwknopCmd does not exist or not executable.\n");
    }
    unless (-e $fwknopdCmd and -x $fwknopdCmd) {
        &write_test_file("[-] $fwknopdCmd does not exist or not executable.\n");
    }

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
        &write_test_file("[-] ../VERSION file does not exist.\n");
        return 0;
    }

    open F, '< ../VERSION' or die $!;
    my $line = <F>;
    close F;
    if ($line =~ /(\d.*\d)/) {
        my $version = $1;
        return 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);
        return 1 if &file_find_regex([qr/$version/], $current_test_file);
    }
    return 0;
}

sub dump_config() {
    my $test_hr = shift;

    return 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);

    ### search for one of the config vars (basic check)
    return 0 unless &file_find_regex([qr/SYSLOG_IDENTITY/],
        $current_test_file);

    return 1;
}

sub override_config() {
    my $test_hr = shift;

    return 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);

    ### search for the altered config value
    return 0 unless &file_find_regex([qr/ENABLE_PCAP_PROMISC.*\'Y\'/],
        $current_test_file);

    return 1;
}

sub non_get_key_path() {
    my $test_hr = shift;

    return 0 if &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);
    return 0 unless &file_find_regex([qr/could\snot\sopen/i],
        $current_test_file);
    return 1;
}

sub no_allow_ip() {
    my $test_hr = shift;

    return 0 if &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);
    return 0 unless &file_find_regex([qr/must\suse\sone\sof/i],
        $current_test_file);
    return 1;
}

sub invalid_allow_ip() {
    my $test_hr = shift;

    return 0 if &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);
    return 0 unless &file_find_regex([qr/Invalid\sallow\sIP\saddress/i],
        $current_test_file);
    return 1;
}

sub invalid_proto() {
    my $test_hr = shift;

    return 0 if &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);
    return 0 unless &file_find_regex([qr/Invalid\sSPA\saccess\smessage/i],
        $current_test_file);
    return 1;
}

sub generate_spa_packet() {
    my $test_hr = shift;

    &write_key('fwknoptest', $local_key_file);

    return 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);
    return 0 unless &file_find_regex([qr/final\spacked/i],
        $current_test_file);

    return 1;
}

sub basic_rijndael_spa() {
    my $test_hr = shift;

    my $rv = &client_server_interaction($test_hr, [],
            $USE_CLIENT, $REQUIRE_FW_RULE, $NO_FORCE_STOP);

    sleep 2;

    ### the firewall rule should be timed out (3 second timeout
    ### as defined in the access.conf file
    if (&run_cmd("$fwknopdCmd $default_server_conf_args " .
            "--fw-list | grep $fake_ip |grep _exp_",
            $cmd_out_tmp, $current_test_file)) {
        &write_test_file("[-] new fw rule not timed out.\n");
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule timed out.\n");
    }

    if (&is_fwknopd_running()) {
        &stop_fwknopd();
        unless (&file_find_regex([qr/Got\sSIGTERM/],
                $server_output_file)) {
            $rv = 0;
        }
    } else {
        &write_test_file("[-] server is not running.\n");
        $rv = 0;
    }

    return $rv;
}

sub replay_detection_rijndael() {
    my $test_hr = shift;

    ### do a complete SPA cycle and then parse the SPA packet out of the
    ### current test file and re-send

    return 0 unless &basic_rijndael_spa($test_hr);

    my $spa_pkt = &get_spa_packet_from_file($current_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $current_test_file\n");
        return 0;
    }

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => $spa_pkt,
        },
    );

    my $rv = &client_server_interaction($test_hr, \@packets,
            $USE_PREDEF_PKTS, $NO_FW_RULE, $NO_FORCE_STOP);

    if (&is_fwknopd_running()) {
        &stop_fwknopd();
        unless (&file_find_regex([qr/Got\sSIGTERM/],
                $server_output_file)) {
            $rv = 0;
        }
    } else {
        &write_test_file("[-] server is not running.\n");
        $rv = 0;
    }

    unless (&file_find_regex([qr/Replay\sdetected\sfrom\ssource\sIP/i],
            $server_output_file)) {
        $rv = 0;
    }

    return $rv;
}

sub server_start() {
    my $test_hr = shift;

    my $rv = &client_server_interaction($test_hr, [],
            $USE_PREDEF_PKTS, $NO_FW_RULE, $NO_FORCE_STOP);

    if (&is_fwknopd_running()) {
        &stop_fwknopd();
        unless (&file_find_regex([qr/Got\sSIGTERM/],
                $server_output_file)) {
            $rv = 0;
        }
    } else {
        &write_test_file("[-] server is not running.\n");
        $rv = 0;
    }

    unless (&file_find_regex([qr/Starting\sfwknopd\smain\sevent\sloop/],
            $server_output_file)) {
        $rv = 0;
    }

    return $rv;
}

sub server_stop() {
    my $test_hr = shift;

    my $rv = &client_server_interaction($test_hr, [],
            $USE_PREDEF_PKTS, $NO_FW_RULE, $NO_FORCE_STOP);

    if (&is_fwknopd_running()) {
        &stop_fwknopd();
        unless (&file_find_regex([qr/Got\sSIGTERM/],
                $server_output_file)) {
            $rv = 0;
        }
    } else {
        &write_test_file("[-] server is not running, nothing to stop.\n");
        $rv = 0;
    }

    return $rv;

    return $rv;
}

sub server_packet_limit() {
    my $test_hr = shift;

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => 'A'x700,
        },
    );

    my $rv = &client_server_interaction($test_hr, \@packets,
            $USE_PREDEF_PKTS, $NO_FW_RULE, $FORCE_STOP);

    unless (&file_find_regex([qr/count\slimit\sof\s1\sreached/],
            $server_output_file)) {
        $rv = 0;
    }

    unless (&file_find_regex([qr/Shutting\sDown\sfwknopd/i],
            $server_output_file)) {
        $rv = 0;
    }

    return $rv;
}

sub server_ignore_small_packets() {
    my $test_hr = shift;

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => 'A'x130,  ### < MIN_SPA_DATA_SIZE
        },
    );

    my $rv = &client_server_interaction($test_hr, \@packets,
        $USE_PREDEF_PKTS, $NO_FW_RULE, $NO_FORCE_STOP);

    if (&file_find_regex([qr/count\slimit\sof\s1\sreached/],
            $server_output_file)) {
        $rv = 0;
    }

    if (&is_fwknopd_running()) {
        &stop_fwknopd();
    } else {
        $rv = 0;
    }

    return $rv;
}

sub client_server_interaction() {
    my ($test_hr, $pkts_hr, $spa_client_flag,
            $fw_rules_flag, $enforce_stop_flag) = @_;

    my $rv = 1;

    ### start fwknopd to monitor for the SPA packet over the loopback interface
    my $fwknopd_parent_pid = &start_fwknopd($test_hr);

    ### give fwknopd a chance to parse its config and start sniffing
    ### on the loopback interface
    sleep 1;

    ### send the SPA packet(s) to the server either manually using IO::Socket or
    ### with the fwknopd client
    if ($spa_client_flag == $USE_CLIENT) {
        unless (&generate_spa_packet($test_hr)) {
            &write_test_file("[-] fwknop client execution error.\n");
            $rv = 0;
        }
    } else {
        &send_packets($pkts_hr);
    }

    if ($fw_rules_flag == $REQUIRE_FW_RULE) {
        ### check to see if the SPA packet resulted in a new fw access rule
        sleep 1;
        unless (&run_cmd("$fwknopdCmd $default_server_conf_args " .
                "--fw-list | grep $fake_ip |grep _exp_",
                $cmd_out_tmp, $current_test_file)) {
            &write_test_file("[-] new fw rules does not exist.\n");
            $rv = 0;
        }
    }

    if ($enforce_stop_flag == $FORCE_STOP) {
        local $SIG{'ALRM'} = sub {die "[*] Sniff packet alarm.\n"};
        ### on some systems and libpcap combinations, it is possible for fwknopd
        ### to not receive packet data, so setting an alarm allows us to recover
        alarm $sniff_alarm;
        eval {
            ### fwknopd will exit after receiving the cached packet (--Count 1)
            waitpid($fwknopd_parent_pid, 0);
        };
        alarm 0;
        if ($@) {
            &dump_pids();
            &stop_fwknopd();
            if (kill 0, $fwknopd_parent_pid) {
                kill 9, $fwknopd_parent_pid unless kill 15, $fwknopd_parent_pid;
            }
            $rv = 0;
        }
    }
    return $rv;
}

sub get_spa_packet_from_file() {
    my $file = shift;

    my $spa_pkt = '';

    my $found_trigger_line = 0;
    open F, "< $file" or die "[*] Could not open file $file: $!";
    while (<F>) {
        if (/final\spacked/i) {
            $found_trigger_line = 1;
            next;
        }
        next unless $found_trigger_line;

        ### the next line with non whitespace is the SPA packet
        if (/(\S+)/) {
            $spa_pkt = $1;
            last;
        }
    }
    close F;

    return $spa_pkt;
}

sub send_packets() {
    my $pkts_ar = shift;

    open F, ">> $current_test_file" or die $!;
    print F "[+] send_packets(): Sending the following packets...\n";
    print F Dumper $pkts_ar;
    close F;

    for my $pkt_hr (@$pkts_ar) {
        if ($pkt_hr->{'proto'} eq 'tcp' or $pkt_hr->{'proto'} eq 'udp') {
            my $socket = IO::Socket::INET->new(
                PeerAddr => $pkt_hr->{'dst_ip'},
                PeerPort => $pkt_hr->{'port'},
                Proto    => $pkt_hr->{'proto'},
                Timeout  => 1
            ) or die "[*] Could not acquire $pkt_hr->{'proto'}/$pkt_hr->{'port'} " .
                "socket to $pkt_hr->{'dst_ip'}: $!";

            $socket->send($pkt_hr->{'data'});
            undef $socket;

        } elsif ($pkt_hr->{'proto'} eq 'http') {
            ### FIXME
        } elsif ($pkt_hr->{'proto'} eq 'icmp') {
            ### FIXME
        }

        sleep $pkt_hr->{'delay'} if defined $pkt_hr->{'delay'};
    }
    return;
}

sub fw_list() {
    my $test_hr = shift;

    return 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);
    return 1;
}

sub fw_list_all() {
    my $test_hr = shift;

    return 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);
    return 1;
}

sub fw_flush() {
    my $test_hr = shift;

    return 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);
    return 1;
}

sub usage_info() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    return 0 unless &run_cmd("$test_hr->{'binary'} -h",
            $cmd_out_tmp, $current_test_file);
    return 1;
}

sub no_such_arg() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    return 0 if &run_cmd("$test_hr->{'binary'} --no-such-arg",
            $cmd_out_tmp, $current_test_file);
    return 1;
}

### check for PIE
sub pie_binary() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $current_test_file);
    return 0 if &file_find_regex([qr/Position\sIndependent.*:\sno/i],
        $current_test_file);
    return 1;
}

### check for stack protection
sub stack_protected_binary() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $current_test_file);
    return 0 if &file_find_regex([qr/Stack\sprotected.*:\sno/i],
        $current_test_file);
    return 1;
}

### check for fortified source functions
sub fortify_source_functions() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $current_test_file);
    return 0 if &file_find_regex([qr/Fortify\sSource\sfunctions:\sno/i],
        $current_test_file);
    return 1;
}

### check for read-only relocations
sub read_only_relocations() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $current_test_file);
    return 0 if &file_find_regex([qr/Read.only\srelocations:\sno/i],
        $current_test_file);
    return 1;
}

### check for immediate binding
sub immediate_binding() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $current_test_file);
    return 0 if &file_find_regex([qr/Immediate\sbinding:\sno/i],
        $current_test_file);
    return 1;
}

sub specs() {

     &run_cmd("$fwknopdCmd $default_server_conf_args --fw-list-all",
            $cmd_out_tmp, $current_test_file);

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
        &run_cmd($cmd, $cmd_out_tmp, $current_test_file);
    }
    return 1;
}

sub write_pid() {
    my $test_hr = shift;

    open F, "> $default_pid_file" or die $!;
    print F "1\n";
    close F;

    &server_start($test_hr);

    open F, "< $default_pid_file" or die $!;
    my $pid = <F>;
    chomp $pid;
    close F;

    if ($pid != 1) {
        return 1;
    }

    return 0;
}

sub start_fwknopd() {
    my $test_hr = shift;

    my $pid = fork();
    die "[*] Could not fork: $!" unless defined $pid;

    if ($pid == 0) {

        ### we are the child, so start fwknopd
        exit &run_cmd($test_hr->{'fwknopd_cmdline'},
            $server_cmd_tmp, $server_output_file);
    }
    return $pid;
}

sub write_key() {
    my ($key, $file) = @_;

    open K, "> $file" or die "[*] Could not open $file: $!";
    print K "$loopback_ip: $key\n";
    print K "localhost: $key\n";
    print K "some.host.through.proxy.com: $key\n";
    close K;
    return;
}

sub dump_pids() {
    open C, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print C "\n" . localtime() . " [+] PID dump:\n";
    close C;
    &run_cmd("ps auxww | grep knop |grep -v grep",
        $cmd_out_tmp, $current_test_file);
    return;
}

sub run_cmd() {
    my ($cmd, $cmd_out, $file) = @_;

    if (-e $file) {
        open F, ">> $file"
            or die "[*] Could not open $file: $!";
        print F localtime() . " CMD: $cmd\n";
        close F;
    } else {
        open F, "> $file"
            or die "[*] Could not open $file: $!";
        print F localtime() . " CMD: $cmd\n";
        close F;
    }

    my $rv = ((system "$cmd > $cmd_out 2>&1") >> 8);

    open C, "< $cmd_out" or die "[*] Could not open $cmd_out: $!";
    my @cmd_lines = <C>;
    close C;

    open F, ">> $file" or die "[*] Could not open $file: $!";
    print F $_ for @cmd_lines;
    close F;

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
    die "[*] $lib_dir directory does not exist." unless -d $lib_dir;
    die "[*] $run_dir directory does not exist." unless -d $run_dir;
    die "[*] default config $default_conf does not exist" unless -e $default_conf;
    die "[*] default access config $default_access_conf does not exist"
        unless -e $default_access_conf;
    die "[*] configure script does not exist" unless -e $configure_path;

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

    unless ($enable_recompilation_warnings_check) {
        push @tests_to_exclude, 'recompilation';
    }

    $sudo_path = &find_command('sudo');

    unless ((&find_command('cc') or &find_command('gcc')) and &find_command('make')) {
        ### disable compilation checks
        push @tests_to_exclude, 'recompilation';
    }

    return;
}

sub is_fwknopd_running() {

    &run_cmd("$fwknopdCmd $default_server_conf_args --status",
        $cmd_out_tmp, $current_test_file);

    return 0 if &file_find_regex([qr/no\s+running/i], $cmd_out_tmp);

    return 1;
}

sub stop_fwknopd() {

    &run_cmd("$fwknopdCmd $default_server_conf_args -K",
        $cmd_out_tmp, $current_test_file);

    sleep 1;

    return;
}

sub file_find_regex() {
    my ($re_ar, $file) = @_;

    my $found = 0;
    my @write_lines = ();

    open F, "< $file" or die "[*] Could not open $file: $!";
    LINE: while (<F>) {
        my $line = $_;
        next LINE if $line =~ /file_file_regex\(\)/;
        for my $re (@$re_ar) {
            if ($line =~ $re) {
                push @write_lines, "[.] file_find_regex() " .
                    "Matched '$re' with line: $line";
                $found = 1;
                last LINE;
            }
        }
    }
    close F;

    if ($found) {
        for my $line (@write_lines) {
            &write_test_file($line);
        }
    } else {
        &write_test_file("[.] find_find_regex() Did not " .
            "match any regex in: '@$re_ar'\n");
    }

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
    my $msg = shift;

    if (-e $current_test_file) {
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
