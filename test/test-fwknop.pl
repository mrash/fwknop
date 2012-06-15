#!/usr/bin/perl -w

use File::Copy;
use File::Path;
use IO::Socket;
use Data::Dumper;
use Cwd;
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
my $gpg_client_home_dir = "$conf_dir/client-gpg";

my $nat_conf            = "$conf_dir/nat_fwknopd.conf";
my $default_conf        = "$conf_dir/default_fwknopd.conf";
my $default_access_conf = "$conf_dir/default_access.conf";
my $ecb_mode_access_conf = "$conf_dir/ecb_mode_access.conf";
my $ctr_mode_access_conf = "$conf_dir/ctr_mode_access.conf";
my $cfb_mode_access_conf = "$conf_dir/cfb_mode_access.conf";
my $ofb_mode_access_conf = "$conf_dir/ofb_mode_access.conf";
my $expired_access_conf = "$conf_dir/expired_stanza_access.conf";
my $future_expired_access_conf = "$conf_dir/future_expired_stanza_access.conf";
my $expired_epoch_access_conf = "$conf_dir/expired_epoch_stanza_access.conf";
my $invalid_expire_access_conf = "$conf_dir/invalid_expire_access.conf";
my $force_nat_access_conf = "$conf_dir/force_nat_access.conf";
my $gpg_access_conf     = "$conf_dir/gpg_access.conf";
my $default_digest_file = "$run_dir/digest.cache";
my $default_pid_file    = "$run_dir/fwknopd.pid";
my $open_ports_access_conf = "$conf_dir/open_ports_access.conf";
my $multi_gpg_access_conf  = "$conf_dir/multi_gpg_access.conf";
my $multi_stanzas_access_conf = "$conf_dir/multi_stanzas_access.conf";
my $multi_stanzas_with_broken_keys_conf = "$conf_dir/multi_stanzas_with_broken_keys.conf";
my $mismatch_open_ports_access_conf = "$conf_dir/mismatch_open_ports_access.conf";
my $require_user_access_conf = "$conf_dir/require_user_access.conf";
my $mismatch_user_access_conf = "$conf_dir/mismatch_user_access.conf";
my $require_src_access_conf = "$conf_dir/require_src_access.conf";
my $no_source_match_access_conf = "$conf_dir/no_source_match_access.conf";
my $no_subnet_source_match_access_conf = "$conf_dir/no_subnet_source_match_access.conf";
my $no_multi_source_match_access_conf = "$conf_dir/no_multi_source_match_access.conf";
my $multi_source_match_access_conf = "$conf_dir/multi_source_match_access.conf";
my $ip_source_match_access_conf = "$conf_dir/ip_source_match_access.conf";
my $subnet_source_match_access_conf = "$conf_dir/subnet_source_match_access.conf";

my $fwknopCmd   = '../client/.libs/fwknop';
my $fwknopdCmd  = '../server/.libs/fwknopd';
my $libfko_bin  = "$lib_dir/libfko.so";  ### this is usually a link
my $valgrindCmd = '/usr/bin/valgrind';

my $gpg_server_key = '361BBAD4';
my $gpg_client_key = '6A3FAD56';

my $loopback_ip = '127.0.0.1';
my $fake_ip     = '127.0.0.2';
my $internal_nat_host = '192.168.1.2';
my $force_nat_host = '192.168.1.123';
my $default_spa_port = 62201;
my $non_std_spa_port = 12345;

my $spoof_user = 'testuser';
#================== end config ===================

my $passed = 0;
my $failed = 0;
my $executed = 0;
my $test_include = '';
my @tests_to_include = ();
my $test_exclude = '';
my @tests_to_exclude = ();
my $list_mode = 0;
my $loopback_intf = '';
my $anonymize_results = 0;
my $current_test_file = "$output_dir/init";
my $tarfile = 'test_fwknop.tar.gz';
my $server_test_file  = '';
my $use_valgrind = 0;
my $valgrind_str = '';
my $saved_last_results = 0;
my $diff_mode = 0;
my $enable_recompilation_warnings_check = 0;
my $enable_profile_coverage_check = 0;
my $sudo_path = '';
my $gcov_path = '';
my $platform = '';
my $help = 0;
my $YES = 1;
my $NO  = 0;
my $PRINT_LEN = 68;
my $USE_PREDEF_PKTS = 1;
my $USE_CLIENT = 2;
my $REQUIRED = 1;
my $OPTIONAL = 0;
my $NEW_RULE_REQUIRED = 1;
my $REQUIRE_NO_NEW_RULE = 2;
my $NEW_RULE_REMOVED = 1;
my $REQUIRE_NO_NEW_REMOVED = 2;

my $ip_re = qr|(?:[0-2]?\d{1,2}\.){3}[0-2]?\d{1,2}|;  ### IPv4

my @args_cp = @ARGV;

exit 1 unless GetOptions(
    'Anonymize-results' => \$anonymize_results,
    'fwknop-path=s'     => \$fwknopCmd,
    'fwknopd-path=s'    => \$fwknopdCmd,
    'libfko-path=s'     => \$libfko_bin,
    'loopback-intf=s'   => \$loopback_intf,
    'test-include=s'    => \$test_include,
    'include=s'         => \$test_include,  ### synonym
    'test-exclude=s'    => \$test_exclude,
    'exclude=s'         => \$test_exclude,  ### synonym
    'enable-recompile-check' => \$enable_recompilation_warnings_check,
    'enable-profile-coverage-check' => \$enable_profile_coverage_check,
    'List-mode'         => \$list_mode,
    'enable-valgrind'   => \$use_valgrind,
    'valgrind-path=s'   => \$valgrindCmd,
    'diff'              => \$diff_mode,
    'help'              => \$help
);

&usage() if $help;

### create an anonymized tar file of test suite results that can be
### emailed around to assist in debugging fwknop communications
exit &anonymize_results() if $anonymize_results;

&identify_loopback_intf();

$valgrind_str = "$valgrindCmd --leak-check=full " .
    "--show-reachable=yes --track-origins=yes" if $use_valgrind;

my $intf_str = "-i $loopback_intf --foreground --verbose --verbose";

my $default_client_args = "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
    "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --get-key " .
    "$local_key_file --verbose --verbose";

my $default_client_gpg_args = "$default_client_args " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key " .
    "--gpg-home-dir $gpg_client_home_dir";

my $default_server_conf_args = "-c $default_conf -a $default_access_conf " .
    "-d $default_digest_file -p $default_pid_file";

my $default_server_gpg_args = "LD_LIBRARY_PATH=$lib_dir " .
    "$valgrind_str $fwknopdCmd -c $default_conf " .
    "-a $gpg_access_conf $intf_str " .
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
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str $fwknopCmd -h",
        'fatal'    => $NO
    },
    {
        'category' => 'preliminaries',
        'subcategory' => 'client',
        'detail'   => 'getopt() no such argument',
        'err_msg'  => 'getopt() allowed non-existant argument',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str $fwknopCmd --no-such-arg",
        'exec_err' => $YES,
        'fatal'    => $NO
    },
    {
        'category' => 'preliminaries',
        'subcategory' => 'client',
        'detail'   => '--test mode, packet not sent',
        'err_msg'  => '--test mode, packet sent?',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/test\smode\senabled/],
        'cmdline'  => "$default_client_args --test",
        'fatal'    => $NO
    },

    {
        'category' => 'preliminaries',
        'subcategory' => 'client',
        'detail'   => 'expected code version',
        'err_msg'  => 'code version mis-match',
        'function' => \&expected_code_version,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str $fwknopCmd --version",
        'fatal'    => $NO
    },

    {
        'category' => 'preliminaries',
        'subcategory' => 'server',
        'detail'   => 'usage info',
        'err_msg'  => 'could not get usage info',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str $fwknopdCmd -h",
        'fatal'    => $NO
    },
    {
        'category' => 'preliminaries',
        'subcategory' => 'server',
        'detail'   => 'getopt() no such argument',
        'err_msg'  => 'getopt() allowed non-existant argument',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str $fwknopdCmd --no-such-arg",
        'exec_err' => $YES,
        'fatal'    => $NO
    },

    {
        'category' => 'preliminaries',
        'subcategory' => 'server',
        'detail'   => 'expected code version',
        'err_msg'  => 'code version mis-match',
        'function' => \&expected_code_version,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a " .
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
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/SYSLOG_IDENTITY/],
        'exec_err' => $NO,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf " .
            "-a $default_access_conf --dump-config",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'detail'   => 'override config',
        'err_msg'  => 'could not override configuration',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/ENABLE_PCAP_PROMISC.*\'Y\'/],
        'exec_err' => $NO,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args " .
            "-O $conf_dir/override_fwknopd.conf --dump-config",
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '--get-key path validation',
        'err_msg'  => 'accepted improper --get-key path',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/could\snot\sopen/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -s $fake_ip " .
            "-D $loopback_ip --get-key not/there",
        'fatal'    => $YES
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'require [-s|-R|-a]',
        'err_msg'  => 'allowed null allow IP',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/must\suse\sone\sof/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -D $loopback_ip",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '--allow-ip <IP> valid IP',
        'err_msg'  => 'permitted invalid --allow-ip arg',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Invalid\sallow\sIP\saddress/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -a invalidIP -D $loopback_ip",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '-A <proto>/<port> specification',
        'err_msg'  => 'permitted invalid -A <proto>/<port>',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Invalid\sSPA\saccess\smessage/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A invalid/22 -a $fake_ip -D $loopback_ip",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'generate SPA packet',
        'err_msg'  => 'could not generate SPA packet',
        'function' => \&client_send_spa_packet,
        'cmdline'  => $default_client_args,
        'fatal'    => $YES
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'list current fwknopd fw rules',
        'err_msg'  => 'could not list current fwknopd fw rules',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --fw-list",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'list all current fw rules',
        'err_msg'  => 'could not list all current fw rules',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --fw-list-all",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'flush current firewall rules',
        'err_msg'  => 'could not flush current fw rules',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --fw-flush",
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'start',
        'err_msg'  => 'start error',
        'function' => \&server_start,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'stop',
        'err_msg'  => 'stop error',
        'function' => \&server_stop,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'write PID',
        'err_msg'  => 'did not write PID',
        'function' => \&write_pid,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => '--packet-limit 1 exit',
        'err_msg'  => 'did not exit after one packet',
        'function' => \&server_packet_limit,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --packet-limit 1 $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'ignore packets < min SPA len (140)',
        'err_msg'  => 'did not ignore small packets',
        'function' => \&server_ignore_small_packets,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --packet-limit 1 $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => '-P bpf filter ignore packet',
        'err_msg'  => 'filter did not ignore packet',
        'function' => \&server_bpf_ignore_packet,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --packet-limit 1 $intf_str " .
            qq|-P "udp port $non_std_spa_port"|,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'packet aging (past) (tcp/22 ssh)',
        'err_msg'  => 'old SPA packet accepted',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args --time-offset-minus 300s",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/SPA\sdata\stime\sdifference/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'packet aging (future) (tcp/22 ssh)',
        'err_msg'  => 'future SPA packet accepted',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args --time-offset-plus 300s",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/SPA\sdata\stime\sdifference/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'expired stanza (tcp/22 ssh)',
        'err_msg'  => 'SPA packet accepted',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $expired_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/Access\sstanza\shas\sexpired/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'invalid expire date (tcp/22 ssh)',
        'err_msg'  => 'SPA packet accepted',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $invalid_expire_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/invalid\sdate\svalue/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'expired epoch stanza (tcp/22 ssh)',
        'err_msg'  => 'SPA packet accepted',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $expired_epoch_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/Access\sstanza\shas\sexpired/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'future expired stanza (tcp/22 ssh)',
        'err_msg'  => 'SPA packet not accepted',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $future_expired_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'OPEN_PORTS (tcp/22 ssh)',
        'err_msg'  => "improper OPEN_PORTS result",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $open_ports_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'OPEN_PORTS mismatch',
        'err_msg'  => "SPA packet accepted",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $mismatch_open_ports_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/One\s+or\s+more\s+requested/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'require user (tcp/22 ssh)',
        'err_msg'  => "missed require user criteria",
        'function' => \&spa_cycle,
        'cmdline'  => "SPOOF_USER=$spoof_user $default_client_args",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $require_user_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'user mismatch (tcp/22 ssh)',
        'err_msg'  => "improper user accepted for access",
        'function' => \&user_mismatch,
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $mismatch_user_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/Username\s+in\s+SPA\s+data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'require src (tcp/22 ssh)',
        'err_msg'  => "fw rule not created",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $require_src_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'mismatch require src (tcp/22 ssh)',
        'err_msg'  => "fw rule created",
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -s -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $require_src_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/Got\s0.0.0.0\swhen\svalid\ssource\sIP/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'IP filtering (tcp/22 ssh)',
        'err_msg'  => "did not filter $loopback_ip",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $no_source_match_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/No\saccess\sdata\sfound/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'subnet filtering (tcp/22 ssh)',
        'err_msg'  => "did not filter $loopback_ip",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $no_subnet_source_match_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/No\saccess\sdata\sfound/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'IP+subnet filtering (tcp/22 ssh)',
        'err_msg'  => "did not filter $loopback_ip",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $no_multi_source_match_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/No\saccess\sdata\sfound/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'IP match (tcp/22 ssh)',
        'err_msg'  => "did not filter $loopback_ip",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $ip_source_match_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'subnet match (tcp/22 ssh)',
        'err_msg'  => "did not filter $loopback_ip",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $subnet_source_match_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'multi IP/net match (tcp/22 ssh)',
        'err_msg'  => "did not filter $loopback_ip",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $multi_source_match_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'multi access stanzas (tcp/22 ssh)',
        'err_msg'  => "could not complete SPA cycle",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $multi_stanzas_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'bad/good key stanzas (tcp/22 ssh)',
        'err_msg'  => "could not complete SPA cycle",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $multi_stanzas_with_broken_keys_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "non-enabled NAT (tcp/22 ssh)",
        'err_msg'  => "SPA packet not filtered",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -N $internal_nat_host:22",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/requested\sNAT\saccess.*not\senabled/i],
        'server_conf' => $nat_conf,
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "NAT to $internal_nat_host (tcp/22 ssh)",
        'err_msg'  => "could not complete NAT SPA cycle",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -N $internal_nat_host:22",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $nat_conf -a $open_ports_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $nat_conf,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "force NAT $force_nat_host (tcp/22 ssh)",
        'err_msg'  => "could not complete NAT SPA cycle",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $nat_conf -a $force_nat_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/to\:$force_nat_host\:22/i],
        'server_negative_output_matches' => [qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $nat_conf,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'ECB mode (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -M ecb",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $ecb_mode_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_negative_output_matches' => [qr/Decryption\sfailed/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'CFB mode (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -M cfb",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $cfb_mode_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_negative_output_matches' => [qr/Decryption\sfailed/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'CTR mode (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -M ctr",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $ctr_mode_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_negative_output_matches' => [qr/Decryption\sfailed/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'OFB mode (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -M ofb",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $ofb_mode_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_negative_output_matches' => [qr/Decryption\sfailed/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'mode mismatch (tcp/22 ssh)',
        'err_msg'  => 'server accepted mismatch enc mode',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -M ecb",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $default_conf -a $default_access_conf " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/Decryption\sfailed/i],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/23 telnet)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/23 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/9418 git)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/9418 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (udp/53 dns)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A udp/53 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "-P bpf SPA over port $non_std_spa_port",
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args --server-port $non_std_spa_port",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str " .
            qq|-P "udp port $non_std_spa_port"|,
        'server_positive_output_matches' => [qr/PCAP\sfilter.*\s$non_std_spa_port/],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'random SPA port (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -r",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str " .
            qq|-P "udp"|,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'spoof username (tcp/22)',
        'err_msg'  => 'could not spoof username',
        'function' => \&spoof_username,
        'cmdline'  => "SPOOF_USER=$spoof_user LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'replay attack detection',
        'err_msg'  => 'could not detect replay attack',
        'function' => \&replay_detection,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'server',
        'detail'   => 'digest cache structure',
        'err_msg'  => 'improper digest cache structure',
        'function' => \&digest_cache_structure,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'non-base64 altered SPA data',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&altered_non_base64_spa_data,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'base64 altered SPA data',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&altered_base64_spa_data,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'appended data to SPA pkt',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&appended_spa_data,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'prepended data to SPA pkt',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&prepended_spa_data,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },

    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'multi gpg-IDs (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir " .
            "$valgrind_str $fwknopdCmd -c $default_conf " .
            "-a $multi_gpg_access_conf $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/23 telnet)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/23 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/9418 git)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/9418 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (udp/53 dns)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A udp/53 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'replay attack detection',
        'err_msg'  => 'could not detect replay attack',
        'function' => \&replay_detection,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fatal'    => $NO
    },

    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'non-base64 altered SPA data',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&altered_non_base64_spa_data,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fatal'    => $NO
    },
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'base64 altered SPA data',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&altered_base64_spa_data,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fatal'    => $NO
    },
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'appended data to SPA pkt',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&appended_spa_data,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fatal'    => $NO
    },
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'prepended data to SPA pkt',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&prepended_spa_data,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fatal'    => $NO
    },
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'spoof username (tcp/22 ssh)',
        'err_msg'  => 'could not spoof username',
        'function' => \&spoof_username,
        'cmdline'  => "SPOOF_USER=$spoof_user $default_client_gpg_args",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fatal'    => $NO
    },

    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'server',
        'detail'   => 'digest cache structure',
        'err_msg'  => 'improper digest cache structure',
        'function' => \&digest_cache_structure,
        'fatal'    => $NO
    },

    {
        'category' => 'profile coverage',
        'detail'   => 'gcov profile coverage',
        'err_msg'  => 'profile coverage failed',
        'function' => \&profile_coverage,
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
    'exec_err'        => $OPTIONAL,
    'fw_rule_created' => $OPTIONAL,
    'fw_rule_removed' => $OPTIONAL,
    'server_conf'     => $OPTIONAL,
    'positive_output_matches' => $OPTIONAL,
    'negative_output_matches' => $OPTIONAL,
    'server_positive_output_matches' => $OPTIONAL,
    'server_negative_output_matches' => $OPTIONAL,
);

if ($diff_mode) {
    &diff_test_results();
    exit 0;
}

### make sure everything looks as expected before continuing
&init();

&logr("\n[+] Starting the fwknop test suite...\n\n" .
    "    args: @args_cp\n\n"
);

### save the results from any previous test suite run
### so that we can potentially compare them with --diff
if ($saved_last_results) {
    &logr("    Saved results from previous run " .
        "to: ${output_dir}.last/\n\n");
}

### main loop through all of the tests
for my $test_hr (@tests) {
    &run_test($test_hr);
}

&logr("\n[+] passed/failed/executed: $passed/$failed/$executed tests\n\n");

copy $logfile, "$output_dir/$logfile" or die $!;

exit 0;

#===================== end main =======================

sub run_test() {
    my $test_hr = shift;

    my $msg = "[$test_hr->{'category'}]";
    $msg .= " [$test_hr->{'subcategory'}]" if $test_hr->{'subcategory'};
    $msg .= " $test_hr->{'detail'}";

    return unless &process_include_exclude($msg);

    if ($list_mode) {
        print $msg, "\n";
        return;
    }

    &dots_print($msg);

    $executed++;
    $current_test_file  = "$output_dir/$executed.test";
    $server_test_file   = "$output_dir/${executed}_fwknopd.test";

    &write_test_file("[+] TEST: $msg\n", $current_test_file);
    $test_hr->{'msg'} = $msg;
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
    my $msg = shift;

    ### inclusions/exclusions
    if (@tests_to_include) {
        my $found = 0;
        for my $test (@tests_to_include) {
            if ($msg =~ /$test/) {
                $found = 1;
                last;
            }
        }
        return 0 unless $found;
    }
    if (@tests_to_exclude) {
        my $found = 0;
        for my $test (@tests_to_exclude) {
            if ($msg =~ /$test/) {
                $found = 1;
                last;
            }
        }
        return 0 if $found;
    }
    return 1;
}

sub diff_test_results() {
    die "[*] Need results from a previous run before running --diff"
        unless -d "${output_dir}.last";
    die "[*] Current results set does not exist." unless -d $output_dir;

    my %current_tests  = ();
    my %previous_tests = ();

    ### Only diff results for matching tests (parse the logfile to see which
    ### test numbers match across the two test cycles).
    &build_results_hash(\%current_tests, $output_dir);
    &build_results_hash(\%previous_tests, "${output_dir}.last");

    for my $test_msg (sort {$current_tests{$a}{'num'} <=> $current_tests{$b}{'num'}}
                keys %current_tests) {
        my $current_result = $current_tests{$test_msg}{'pass_fail'};
        my $current_num    = $current_tests{$test_msg}{'num'};
        if (defined $previous_tests{$test_msg}) {
            print "[+] Checking: $test_msg\n";
            my $previous_result = $previous_tests{$test_msg}{'pass_fail'};
            my $previous_num    = $previous_tests{$test_msg}{'num'};
            if ($current_result ne $previous_result) {
                print " DIFF: **$current_result** $test_msg\n";
            }

            &diff_results($previous_num, $current_num);
            print "\n";
        }
    }

    exit 0;
}

sub diff_results() {
    my ($previous_num, $current_num) = @_;

    ### edit out any valgrind "==354==" prefixes
    my $valgrind_search_re = qr/^==\d+==\s/;

    ### remove CMD timestamps
    my $cmd_search_re = qr/^\S+\s.*?\s\d{4}\sCMD\:/;

    for my $file ("${output_dir}.last/${previous_num}.test",
        "${output_dir}.last/${previous_num}_fwknopd.test",
        "${output_dir}/${current_num}.test",
        "${output_dir}/${current_num}_fwknopd.test",
    ) {
        system qq{perl -p -i -e 's|$valgrind_search_re||' $file} if -e $file;
        system qq{perl -p -i -e 's|$cmd_search_re|CMD:|' $file} if -e $file;
    }

    if (-e "${output_dir}.last/${previous_num}.test"
            and -e "${output_dir}/${current_num}.test") {
        system "diff -u ${output_dir}.last/${previous_num}.test " .
            "${output_dir}/${current_num}.test";
    }

    if (-e "${output_dir}.last/${previous_num}_fwknopd.test"
            and -e "${output_dir}/${current_num}_fwknopd.test") {
        system "diff -u ${output_dir}.last/${previous_num}_fwknopd.test " .
            "${output_dir}/${current_num}_fwknopd.test";
    }

    return;
}

sub build_results_hash() {
    my ($hr, $dir) = @_;

    open F, "< $dir/$logfile" or die $!;
    while (<F>) {
        if (/^(.*?)\.\.\..*(pass|fail)\s\((\d+)\)/) {
            $hr->{$1}{'pass_fail'} = $2;
            $hr->{$1}{'num'}       = $3;
        }
    }
    return;
}

sub compile_warnings() {

    ### 'make clean' as root
    return 0 unless &run_cmd('make -C .. clean',
        $cmd_out_tmp, $current_test_file);

    if ($sudo_path) {
        my $username = getpwuid((stat($configure_path))[4]);
        die "[*] Could not determine $configure_path owner"
            unless $username;

        return 0 unless &run_cmd("$sudo_path -u $username make -C ..",
            $cmd_out_tmp, $current_test_file);

    } else {

        return 0 unless &run_cmd('make -C ..',
            $cmd_out_tmp, $current_test_file);

    }

    ### look for compilation warnings - something like:
    ###     warning: ‘test’ is used uninitialized in this function
    return 0 if &file_find_regex([qr/\swarning:\s/, qr/gcc\:.*\sunused/],
        $current_test_file);

    ### the new binaries should exist
    unless (-e $fwknopCmd and -x $fwknopCmd) {
        &write_test_file("[-] $fwknopCmd does not exist or not executable.\n",
            $current_test_file);
    }
    unless (-e $fwknopdCmd and -x $fwknopdCmd) {
        &write_test_file("[-] $fwknopdCmd does not exist or not executable.\n",
            $current_test_file);
    }

    return 1;
}

sub profile_coverage() {

    ### check for any *.gcno files - if they don't exist, then fwknop was
    ### not compiled with profile support
    unless (glob('../client/*.gcno') and glob('../server/*.gcno')) {
        &write_test_file("[-] ../client/*.gcno and " .
            "../server/*.gcno files do not exist.\n", $current_test_file);
        return 0;
    }

    my $curr_dir = getcwd() or die $!;

    ### gcov -b ../client/*.gcno
    for my $dir ('../client', '../server', '../lib/.libs') {
        next unless -d $dir;
        chdir $dir or die $!;
        system "$gcov_path -b -u *.gcno > /dev/null 2>&1";
        chdir $curr_dir or die $!;

        &run_cmd(qq|grep "called 0 returned" $dir/*.gcov|,
                $cmd_out_tmp, $current_test_file);
    }

    return 1;
}

sub binary_exists() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};

    ### account for different libfko.so paths (e.g. libfko.so.0.3 with no
    ### libfko.so link on OpenBSD)

    if ($test_hr->{'binary'} =~ /libfko/) {
        unless (-e $test_hr->{'binary'}) {
            for my $file (glob("$lib_dir/libfko.so*")) {
                if (-e $file and -x $file) {
                    $test_hr->{'binary'} = $file;
                    $libfko_bin = $file;
                    last;
                }
            }
        }
    }

    return 0 unless -e $test_hr->{'binary'} and -x $test_hr->{'binary'};
    return 1;
}

sub expected_code_version() {
    my $test_hr = shift;

    unless (-e '../VERSION') {
        &write_test_file("[-] ../VERSION file does not exist.\n",
            $current_test_file);
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

sub client_send_spa_packet() {
    my $test_hr = shift;

    &write_key('fwknoptest', $local_key_file);

    return 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $current_test_file);
    return 0 unless &file_find_regex([qr/final\spacked/i],
        $current_test_file);

    return 1;
}

sub spa_cycle() {
    my $test_hr = shift;

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
            = &client_server_interaction($test_hr, [], $USE_CLIENT);

    if ($test_hr->{'fw_rule_created'} eq $NEW_RULE_REQUIRED) {
        $rv = 0 unless $fw_rule_created;
    } elsif ($test_hr->{'fw_rule_created'} eq $REQUIRE_NO_NEW_RULE) {
        $rv = 0 if $fw_rule_created;
    }

    if ($test_hr->{'fw_rule_removed'} eq $NEW_RULE_REMOVED) {
        $rv = 0 unless $fw_rule_removed;
    } elsif ($test_hr->{'fw_rule_removed'} eq $REQUIRE_NO_NEW_REMOVED) {
        $rv = 0 if $fw_rule_removed;
    }

    if ($test_hr->{'server_positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'server_positive_output_matches'},
            $server_test_file);
    }

    if ($test_hr->{'server_negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'server_negative_output_matches'},
            $server_test_file);
    }

    return $rv;
}

sub spoof_username() {
    my $test_hr = shift;

    my $rv = &spa_cycle($test_hr);

    unless (&file_find_regex([qr/Username:\s*$spoof_user/],
            $current_test_file)) {
        $rv = 0;
    }

    unless (&file_find_regex([qr/Username:\s*$spoof_user/],
            $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub replay_detection() {
    my $test_hr = shift;

    ### do a complete SPA cycle and then parse the SPA packet out of the
    ### current test file and re-send

    return 0 unless &spa_cycle($test_hr);

    my $spa_pkt = &get_spa_packet_from_file($current_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $current_test_file\n",
            $current_test_file);
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

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    $rv = 0 unless $server_was_stopped;

    unless (&file_find_regex([qr/Replay\sdetected\sfrom\ssource\sIP/i],
            $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub digest_cache_structure() {
    my $test_hr = shift;
    my $rv = 1;

    &run_cmd("file $default_digest_file", $cmd_out_tmp, $current_test_file);

    if (&file_find_regex([qr/ASCII/i], $cmd_out_tmp)) {

        ### the format should be:
        ### <digest> <proto> <src_ip> <src_port> <dst_ip> <dst_port> <time>
        open F, "< $default_digest_file" or
            die "[*] could not open $default_digest_file: $!";
        while (<F>) {
            next if /^#/;
            next unless /\S/;
            unless (m|^\S+\s+\d+\s+$ip_re\s+\d+\s+$ip_re\s+\d+\s+\d+|) {
                &write_test_file("[-] invalid digest.cache line: $_",
                    $current_test_file);
                $rv = 0;
                last;
            }
        }
        close F;
    } elsif (&file_find_regex([qr/dbm/i], $cmd_out_tmp)) {
        &write_test_file("[+] DBM digest file format, " .
            "assuming this is valid.\n", $current_test_file);
    } else {
        ### don't know what kind of file the digest.cache is
        &write_test_file("[-] unrecognized file type for " .
            "$default_digest_file.\n", $current_test_file);
        $rv = 0;
    }

    if ($rv) {
        &write_test_file("[+] valid digest.cache structure.\n",
            $current_test_file);
    }

    return $rv;
}

sub server_bpf_ignore_packet() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    unless (&client_send_spa_packet($test_hr)) {
        &write_test_file("[-] fwknop client execution error.\n",
            $current_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($current_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $current_test_file\n", $current_test_file);
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

    ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    unless (&file_find_regex([qr/PCAP\sfilter.*\s$non_std_spa_port/],
            $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub altered_non_base64_spa_data() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    unless (&client_send_spa_packet($test_hr)) {
        &write_test_file("[-] fwknop client execution error.\n",
            $current_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($current_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $current_test_file\n", $current_test_file);
        return 0;
    }

    ### alter one byte (change to a ":")
    $spa_pkt =~ s|^(.{3}).|$1:|;

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => $spa_pkt,
        },
    );

    ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    $rv = 0 unless $server_was_stopped;

    return $rv;
}

sub altered_base64_spa_data() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    unless (&client_send_spa_packet($test_hr)) {
        &write_test_file("[-] fwknop client execution error.\n",
            $current_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($current_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $current_test_file\n", $current_test_file);
        return 0;
    }

    $spa_pkt =~ s|^(.{3}).|AAAA|;

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => $spa_pkt,
        },
    );

    ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    $rv = 0 unless $server_was_stopped;

    if ($fw_rule_created) {
        &write_test_file("[-] new fw rule created.\n", $current_test_file);
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule not created.\n", $current_test_file);
    }

    unless (&file_find_regex([qr/Error\screating\sfko\scontext/],
            $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub appended_spa_data() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    unless (&client_send_spa_packet($test_hr)) {
        &write_test_file("[-] fwknop client execution error.\n",
            $current_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($current_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $current_test_file\n", $current_test_file);
        return 0;
    }

    $spa_pkt .= 'AAAA';

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => $spa_pkt,
        },
    );

    ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    $rv = 0 unless $server_was_stopped;

    if ($fw_rule_created) {
        &write_test_file("[-] new fw rule created.\n", $current_test_file);
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule not created.\n", $current_test_file);
    }

    unless (&file_find_regex([qr/Error\screating\sfko\scontext/],
            $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub prepended_spa_data() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    unless (&client_send_spa_packet($test_hr)) {
        &write_test_file("[-] fwknop client execution error.\n",
            $current_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($current_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $current_test_file\n", $current_test_file);
        return 0;
    }

    $spa_pkt = 'AAAA' . $spa_pkt;

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => $spa_pkt,
        },
    );

    ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    $rv = 0 unless $server_was_stopped;

    if ($fw_rule_created) {
        &write_test_file("[-] new fw rule created.\n", $current_test_file);
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule not created.\n", $current_test_file);
    }

    unless (&file_find_regex([qr/Error\screating\sfko\scontext/],
            $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub server_start() {
    my $test_hr = shift;

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, [], $USE_PREDEF_PKTS);

    unless (&file_find_regex([qr/Starting\sfwknopd\smain\sevent\sloop/],
            $server_test_file)) {
        $rv = 0;
    }

    $rv = 0 unless $server_was_stopped;

    return $rv;
}

sub server_stop() {
    my $test_hr = shift;

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, [], $USE_PREDEF_PKTS);

    $rv = 0 unless $server_was_stopped;

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

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    if (&is_fwknopd_running()) {
        &stop_fwknopd();
        $rv = 0;
    }

    unless (&file_find_regex([qr/count\slimit\sof\s1\sreached/],
            $server_test_file)) {
        $rv = 0;
    }

    unless (&file_find_regex([qr/Shutting\sDown\sfwknopd/i],
            $server_test_file)) {
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
            'data'   => 'A'x120,  ### < MIN_SPA_DATA_SIZE
        },
    );

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    sleep 2;

    if (&is_fwknopd_running()) {
        &stop_fwknopd();
        $rv = 0;
    }

    return $rv;
}

sub client_server_interaction() {
    my ($test_hr, $pkts_hr, $spa_client_flag, $fw_rules_flag) = @_;

    my $rv = 1;
    my $server_was_stopped = 1;
    my $fw_rule_created = 1;
    my $fw_rule_removed = 0;

    ### start fwknopd to monitor for the SPA packet over the loopback interface
    my $fwknopd_parent_pid = &start_fwknopd($test_hr);

    ### give fwknopd a chance to parse its config and start sniffing
    ### on the loopback interface
    if ($use_valgrind) {
        sleep 3;
    } else {
        sleep 2;
    }

    ### send the SPA packet(s) to the server either manually using IO::Socket or
    ### with the fwknopd client
    if ($spa_client_flag == $USE_CLIENT) {
        unless (&client_send_spa_packet($test_hr)) {
            &write_test_file("[-] fwknop client execution error.\n",
                $current_test_file);
            $rv = 0;
        }
    } else {
        &send_packets($pkts_hr);
    }

    ### check to see if the SPA packet resulted in a new fw access rule
    my $ctr = 0;
    while (not &is_fw_rule_active($test_hr)) {
        &write_test_file("[-] new fw rule does not exist.\n",
            $current_test_file);
        $ctr++;
        last if $ctr == 3;
        sleep 1;
    }
    if ($ctr == 3) {
        $fw_rule_created = 0;
        $fw_rule_removed = 0;
    }

    &time_for_valgrind() if $use_valgrind;

    if ($fw_rule_created) {
        sleep 3;  ### allow time for rule time out.
        if (&is_fw_rule_active($test_hr)) {
            &write_test_file("[-] new fw rule not timed out.\n",
                $current_test_file);
            $rv = 0;
        } else {
            &write_test_file("[+] new fw rule timed out.\n",
                $current_test_file);
            $fw_rule_removed = 1;
        }
    }

    if (&is_fwknopd_running()) {
        &stop_fwknopd();
        unless (&file_find_regex([qr/Got\sSIGTERM/, qr/^Terminated/],
                $server_test_file)) {
            $server_was_stopped = 0;
        }
    } else {
        &write_test_file("[-] server is not running.\n",
            $current_test_file);
        $server_was_stopped = 0;
    }

    return ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed);
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

sub generic_exec() {
    my $test_hr = shift;

    my $rv = 1;

    my $exec_rv = &run_cmd($test_hr->{'cmdline'},
                $cmd_out_tmp, $current_test_file);

    if ($test_hr->{'exec_err'} eq $YES) {
        $rv = 0 if $exec_rv;
    } else {
        $rv = 0 unless $exec_rv;
    }

    if ($test_hr->{'positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'positive_output_matches'},
            $current_test_file);
    }

    if ($test_hr->{'negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'negative_output_matches'},
            $current_test_file);
    }

    return $rv;
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

     &run_cmd("LD_LIBRARY_PATH=$lib_dir $valgrind_str $fwknopdCmd " .
            "$default_server_conf_args --fw-list-all",
            $cmd_out_tmp, $current_test_file);

    my $have_gpgme = 0;

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

        if ($cmd =~ /^ldd/) {
            $have_gpgme++ if &file_find_regex([qr/gpgme/], $cmd_out_tmp);
        }
    }

    ### all three of fwknop/fwknopd/libfko must link against gpgme in order
    ### to enable gpg tests
    unless ($have_gpgme == 3) {
        push @tests_to_exclude, "GPG";
    }

    return 1;
}

sub time_for_valgrind() {
    my $ctr = 0;
    while (&run_cmd("ps axuww | grep LD_LIBRARY_PATH | " .
            "grep valgrind |grep -v perl | grep -v grep",
            $cmd_out_tmp, $current_test_file)) {
        $ctr++;
        last if $ctr == 5;
        sleep 1;
    }
    return;
}

sub anonymize_results() {
    my $rv = 0;
    die "[*] $output_dir does not exist" unless -d $output_dir;
    die "[*] $logfile does not exist, has $0 been executed?"
        unless -e $logfile;
    if (-e $tarfile) {
        unlink $tarfile or die "[*] Could not unlink $tarfile: $!";
    }

    ### remove non-loopback IP addresses
    my $search_re = qr/\b127\.0\.0\.1\b/;
    system "perl -p -i -e 's|$search_re|00MY1271STR00|g' $output_dir/*.test";
    $search_re = qr/\b127\.0\.0\.2\b/;
    system "perl -p -i -e 's|$search_re|00MY1272STR00|g' $output_dir/*.test";
    $search_re = qr/\b0\.0\.0\.0\b/;
    system "perl -p -i -e 's|$search_re|00MY0000STR00|g' $output_dir/*.test";
    $search_re = qr/\b(?:[0-2]?\d{1,2}\.){3}[0-2]?\d{1,2}\b/;
    system "perl -p -i -e 's|$search_re|N.N.N.N|g' $output_dir/*.test";
    system "perl -p -i -e 's|00MY1271STR00|127.0.0.1|g' $output_dir/*.test";
    system "perl -p -i -e 's|00MY1272STR00|127.0.0.2|g' $output_dir/*.test";
    system "perl -p -i -e 's|00MY0000STR00|0.0.0.0|g' $output_dir/*.test";

    ### remove hostname from any uname output
    $search_re = qr/\suname\s+\-a\s*\n\s*(\S+)\s+\S+/;
    system "perl -p -i -e 'undef \$/; s|$search_re" .
        "| uname -a\n\$1 (removed)|s' $output_dir/*.test";

    $search_re = qr/uname=\x27(\S+)\s+\S+/;
    system "perl -p -i -e 's|$search_re|uname= \$1 (removed)|' $output_dir/*.test";

    ### create tarball
    system "tar cvfz $tarfile $logfile $output_dir";
    print "[+] Anonymized test results file: $tarfile\n";
    if (-e $tarfile) {
        $rv = 1;
    }
    return $rv;
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

    &write_test_file("[+] TEST: $test_hr->{'msg'}\n", $server_test_file);

    my $pid = fork();
    die "[*] Could not fork: $!" unless defined $pid;

    if ($pid == 0) {

        ### we are the child, so start fwknopd
        exit &run_cmd($test_hr->{'fwknopd_cmdline'},
            $server_cmd_tmp, $server_test_file);
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

    $|++; ### turn off buffering

    $< == 0 && $> == 0 or
        die "[*] $0: You must be root (or equivalent ",
            "UID 0 account) to effectively test fwknop";

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

    if ($use_valgrind) {
        die "[*] $valgrindCmd exec problem, use --valgrind-path"
            unless -e $valgrindCmd and -x $valgrindCmd;
    }

    die "[*] $conf_dir directory does not exist." unless -d $conf_dir;
    die "[*] $lib_dir directory does not exist." unless -d $lib_dir;

    for my $file ($configure_path,
            $default_conf,
            $nat_conf,
            $default_access_conf,
            $no_source_match_access_conf,
            $ip_source_match_access_conf,
            $subnet_source_match_access_conf,
            $no_subnet_source_match_access_conf,
            $no_multi_source_match_access_conf,
            $multi_source_match_access_conf,
            $open_ports_access_conf,
            $mismatch_open_ports_access_conf,
            $require_user_access_conf,
            $mismatch_user_access_conf,
            $require_src_access_conf,
            $multi_gpg_access_conf,
            $multi_stanzas_access_conf,
            $expired_access_conf,
            $expired_epoch_access_conf,
            $future_expired_access_conf,
            $invalid_expire_access_conf,
            $force_nat_access_conf,
    ) {
        die "[*] $file does not exist" unless -e $file;
    }

    if (-d $output_dir) {
        if (-d "${output_dir}.last") {
            rmtree "${output_dir}.last"
                or die "[*] rmtree ${output_dir}.last $!";
        }
        mkdir "${output_dir}.last"
            or die "[*] ${output_dir}.last: $!";
        for my $file (glob("$output_dir/*.test")) {
            if ($file =~ m|.*/(.*)|) {
                copy $file, "${output_dir}.last/$1" or die $!;
            }
        }
        if (-e "$output_dir/init") {
            copy "$output_dir/init", "${output_dir}.last/init";
        }
        if (-e $logfile) {
            copy $logfile, "${output_dir}.last/$logfile" or die $!;
        }
        $saved_last_results = 1;
    } else {
        mkdir $output_dir or die "[*] Could not mkdir $output_dir: $!";
    }
    unless (-d $run_dir) {
        mkdir $run_dir or die "[*] Could not mkdir $run_dir: $!";
    }

    for my $file (glob("$output_dir/*.test")) {
        unlink $file or die "[*] Could not unlink($file)";
    }
    if (-e "$output_dir/init") {
        unlink "$output_dir/init" or die $!;
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

    unless ($enable_profile_coverage_check) {
        push @tests_to_exclude, 'profile coverage';
    }

    $sudo_path = &find_command('sudo');

    unless ((&find_command('cc') or &find_command('gcc')) and &find_command('make')) {
        ### disable compilation checks
        push @tests_to_exclude, 'recompilation';
    }

    $gcov_path = &find_command('gcov');

    if ($gcov_path) {
        if ($enable_profile_coverage_check) {
            for my $extension ('*.gcov', '*.gcda') {
                ### remove profile output from any previous run
                system qq{find .. -name $extension | xargs rm 2> /dev/null};
            }
        }
    } else {
        push @tests_to_exclude, 'profile coverage';
    }

    open UNAME, "uname |" or die "[*] Could not execute uname: $!";
    while (<UNAME>) {
        if (/linux/i) {
            $platform = 'linux';
            last;
        }
    }
    close UNAME;

    unless ($platform eq 'linux') {
        push @tests_to_exclude, 'NAT';
    }

    return;
}

sub identify_loopback_intf() {
    return if $loopback_intf;

    ### Linux:

    ### lo    Link encap:Local Loopback
    ###       inet addr:127.0.0.1  Mask:255.0.0.0
    ###       inet6 addr: ::1/128 Scope:Host
    ###       UP LOOPBACK RUNNING  MTU:16436  Metric:1
    ###       RX packets:534709 errors:0 dropped:0 overruns:0 frame:0
    ###       TX packets:534709 errors:0 dropped:0 overruns:0 carrier:0
    ###       collisions:0 txqueuelen:0
    ###       RX bytes:101110617 (101.1 MB)  TX bytes:101110617 (101.1 MB)

    ### Freebsd:

    ### lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
    ###         options=3<RXCSUM,TXCSUM>
    ###         inet6 fe80::1%lo0 prefixlen 64 scopeid 0x2
    ###         inet6 ::1 prefixlen 128
    ###         inet 127.0.0.1 netmask 0xff000000
    ###         nd6 options=3<PERFORMNUD,ACCEPT_RTADV>

    my $intf = '';
    my $found_loopback_intf = 0;

    my $cmd = 'ifconfig -a';
    open C, "$cmd |" or die "[*] (use --loopback <name>) $cmd: $!";
    while (<C>) {
        if (/^(\S+?):?\s+.*loopback/i) {
            $intf = $1;
            next;
        }
        if (/^\S/ and $intf and not $found_loopback_intf) {
            ### should not happen
            last;
        }
        if ($intf and /\b127\.0\.0\.1\b/) {
            $found_loopback_intf = 1;
            last;
        }
    }
    close C;

    die "[*] could not determine loopback interface, use --loopback <name>"
        unless $found_loopback_intf;

    $loopback_intf = $intf;

    return;
}

sub is_fw_rule_active() {
    my $test_hr = shift;

    my $conf_args = $default_server_conf_args;

    if ($test_hr->{'server_conf'}) {
        $conf_args = "-c $test_hr->{'server_conf'} -a $default_access_conf " .
            "-d $default_digest_file -p $default_pid_file";
    }

    return 1 if &run_cmd("LD_LIBRARY_PATH=$lib_dir $fwknopdCmd " .
            qq{$conf_args --fw-list | grep -v "# DISABLED" |grep $fake_ip |grep _exp_},
            $cmd_out_tmp, $current_test_file);
    return 0;
}

sub is_fwknopd_running() {

    sleep 2 if $use_valgrind;

    &run_cmd("LD_LIBRARY_PATH=$lib_dir $fwknopdCmd $default_server_conf_args " .
        "--status", $cmd_out_tmp, $current_test_file);

    return 0 if &file_find_regex([qr/no\s+running/i], $cmd_out_tmp);

    return 1;
}

sub stop_fwknopd() {

    &run_cmd("LD_LIBRARY_PATH=$lib_dir $fwknopdCmd " .
        "$default_server_conf_args -K", $cmd_out_tmp, $current_test_file);

    if ($use_valgrind) {
        &time_for_valgrind();
    } else {
        sleep 1;
    }

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
            &write_test_file($line, $file);
        }
    } else {
        &write_test_file("[.] find_find_regex() Did not " .
            "match any regex in: '@$re_ar'\n", $file);
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
    my ($msg, $file) = @_;

    if (-e $file) {
        open F, ">> $file"
            or die "[*] Could not open $file: $!";
        print F $msg;
        close F;
    } else {
        open F, "> $file"
            or die "[*] Could not open $file: $!";
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

sub usage() {
    return;
}
