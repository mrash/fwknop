#!/usr/bin/perl -w

use Cwd;
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
my $cmd_out_tmp    = 'cmd.out';
my $server_cmd_tmp = 'server_cmd.out';
my $data_tmp       = 'data.tmp';
my $key_tmp        = 'key.tmp';
my $enc_save_tmp   = 'openssl_save.enc';
my $test_suite_path = 'test-fwknop.pl';
my $gpg_client_home_dir = "$conf_dir/client-gpg";
my $gpg_client_home_dir_no_pw = "$conf_dir/client-gpg-no-pw";
my $replay_pcap_file = "$conf_dir/spa_replay.pcap";

my %cf = (
    'nat'                     => "$conf_dir/nat_fwknopd.conf",
    'def'                     => "$conf_dir/default_fwknopd.conf",
    'def_access'              => "$conf_dir/default_access.conf",
    'hmac_access'             => "$conf_dir/hmac_access.conf",
    'exp_access'              => "$conf_dir/expired_stanza_access.conf",
    'future_exp_access'       => "$conf_dir/future_expired_stanza_access.conf",
    'exp_epoch_access'        => "$conf_dir/expired_epoch_stanza_access.conf",
    'invalid_exp_access'      => "$conf_dir/invalid_expire_access.conf",
    'force_nat_access'        => "$conf_dir/force_nat_access.conf",
    'cmd_access'              => "$conf_dir/cmd_access.conf",
    'local_nat'               => "$conf_dir/local_nat_fwknopd.conf",
    'ipfw_active_expire'      => "$conf_dir/ipfw_active_expire_equal_fwknopd.conf",
    'android_access'          => "$conf_dir/android_access.conf",
    'android_legacy_iv_access' => "$conf_dir/android_legacy_iv_access.conf",
    'dual_key_access'         => "$conf_dir/dual_key_usage_access.conf",
    'gpg_access'              => "$conf_dir/gpg_access.conf",
    'legacy_iv_access'        => "$conf_dir/legacy_iv_access.conf",
    'gpg_no_pw_access'        => "$conf_dir/gpg_no_pw_access.conf",
    'tcp_server'              => "$conf_dir/tcp_server_fwknopd.conf",
    'tcp_pcap_filter'         => "$conf_dir/tcp_pcap_filter_fwknopd.conf",
    'icmp_pcap_filter'        => "$conf_dir/icmp_pcap_filter_fwknopd.conf",
    'open_ports_access'       => "$conf_dir/open_ports_access.conf",
    'multi_gpg_access'        => "$conf_dir/multi_gpg_access.conf",
    'multi_gpg_no_pw_access'  => "$conf_dir/multi_gpg_no_pw_access.conf",
    'multi_stanza_access'     => "$conf_dir/multi_stanzas_access.conf",
    'broken_keys_access'      => "$conf_dir/multi_stanzas_with_broken_keys.conf",
    'ecb_mode_access'         => "$conf_dir/ecb_mode_access.conf",
    'ctr_mode_access'         => "$conf_dir/ctr_mode_access.conf",
    'cfb_mode_access'         => "$conf_dir/cfb_mode_access.conf",
    'ofb_mode_access'         => "$conf_dir/ofb_mode_access.conf",
    'open_ports_mismatch'     => "$conf_dir/mismatch_open_ports_access.conf",
    'require_user_access'     => "$conf_dir/require_user_access.conf",
    'user_mismatch_access'    => "$conf_dir/mismatch_user_access.conf",
    'require_src_access'      => "$conf_dir/require_src_access.conf",
    'invalid_src_access'      => "$conf_dir/invalid_source_access.conf",
    'no_src_match'            => "$conf_dir/no_source_match_access.conf",
    'no_subnet_match'         => "$conf_dir/no_subnet_source_match_access.conf",
    'no_multi_src'            => "$conf_dir/no_multi_source_match_access.conf",
    'multi_src_access'        => "$conf_dir/multi_source_match_access.conf",
    'ip_src_match'            => "$conf_dir/ip_source_match_access.conf",
    'subnet_src_match'        => "$conf_dir/ip_source_match_access.conf",
    'rc_file_def_key'         => "$conf_dir/fwknoprc_with_default_key",
    'rc_file_def_b64_key'     => "$conf_dir/fwknoprc_with_default_base64_key",
    'rc_file_named_key'       => "$conf_dir/fwknoprc_named_key",
    'rc_file_invalid_b64_key' => "$conf_dir/fwknoprc_invalid_base64_key",
    'rc_file_hmac_b64_key'    => "$conf_dir/fwknoprc_default_hmac_base64_key",
    'base64_key_access'       => "$conf_dir/base64_key_access.conf",
    'disable_aging'           => "$conf_dir/disable_aging_fwknopd.conf",
    'disable_aging_nat'       => "$conf_dir/disable_aging_nat_fwknopd.conf",
    'fuzz_source'             => "$conf_dir/fuzzing_source_access.conf",
    'fuzz_open_ports'         => "$conf_dir/fuzzing_open_ports_access.conf",
    'fuzz_restrict_ports'     => "$conf_dir/fuzzing_restrict_ports_access.conf",
);

my $default_digest_file = "$run_dir/digest.cache";
my $default_pid_file    = "$run_dir/fwknopd.pid";
my $tmp_rc_file         = "$run_dir/fwknoprc";
my $tmp_pkt_file        = "$run_dir/tmp_spa.pkt";
my $tmp_args_file       = "$run_dir/args.save";

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

my $valgrind_cov_dir = 'valgrind-coverage';

my $spoof_ip   = '1.2.3.4';
my $perl_mod_fko_dir = 'FKO';
my $cmd_exec_test_file = '/tmp/fwknoptest';
my $default_key = 'fwknoptest';
#================== end config ===================

my $passed = 0;
my $failed = 0;
my $executed = 0;
my $test_include = '';
my @tests_to_include = ();
my $test_exclude = '';
my @tests_to_exclude = ();
my %valgrind_flagged_fcns = ();
my %valgrind_flagged_fcns_unique = ();
my $previous_valgrind_coverage_dir = '';
my $uniq_keys = 100;
my $test_limit = 0;
my $list_mode = 0;
my $diff_dir1 = '';
my $diff_dir2 = '';
my $loopback_intf = '';
my $anonymize_results = 0;
my $curr_test_file = "$output_dir/init";
my $tarfile = 'test_fwknop.tar.gz';
my $key_gen_file = "$output_dir/key_gen";
my $fuzzing_pkts_file = 'fuzzing/fuzzing_spa_packets';
my $fuzzing_pkts_append = 0;
my $fuzzing_key = 'testtest';
my $fuzzing_num_pkts = 0;
my $fuzzing_test_tag = '';
my $fuzzing_class = 'bogus data';
my %fuzzing_spa_packets = ();
my $total_fuzzing_pkts = 0;
my $server_test_file  = '';
my $enable_valgrind = 0;
my $valgrind_str = '';
my %prev_valgrind_cov = ();
my $fko_wrapper_dir = 'fko-wrapper';
my $enable_client_ip_resolve_test = 0;
my $enable_all = 0;
my $saved_last_results = 0;
my $diff_mode = 0;
my $fko_obj = ();
my $enable_recompilation_warnings_check = 0;
my $enable_profile_coverage_check = 0;
my $enable_make_distcheck = 0;
my $enable_perl_module_checks = 0;
my $enable_perl_module_fuzzing_spa_pkt_generation = 0;
my $enable_openssl_compatibility_tests = 0;
my $openssl_success_ctr = 0;
my $openssl_failure_ctr = 0;
my $openssl_ctr = 0;
my $fuzzing_success_ctr = 0;
my $fuzzing_failure_ctr = 0;
my $fuzzing_ctr = 0;
my $sudo_path = '';
my $gcov_path = '';
my $killall_path = '';
my $pgrep_path   = '';
my $openssl_path = '';
my $pinentry_fail = 0;
my $platform = '';
my $help = 0;
my $YES = 1;
my $NO  = 0;
my $IGNORE = 2;
my $PRINT_LEN = 68;
my $USE_PREDEF_PKTS = 1;
my $USE_CLIENT = 2;
my $USE_PCAP_FILE = 3;
my $REQUIRED = 1;
my $OPTIONAL = 0;
my $NEW_RULE_REQUIRED = 1;
my $REQUIRE_NO_NEW_RULE = 2;
my $NEW_RULE_REMOVED = 1;
my $REQUIRE_NO_NEW_REMOVED = 2;
my $MATCH_ANY = 1;
my $MATCH_ALL = 2;
my $REQUIRE_SUCCESS = 0;
my $REQUIRE_FAILURE = 1;
my $LINUX   = 1;
my $FREEBSD = 2;
my $MACOSX  = 3;
my $OPENBSD = 4;

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
    'enable-perl-module-checks' => \$enable_perl_module_checks,
    'enable-perl-module-pkt-generation' => \$enable_perl_module_fuzzing_spa_pkt_generation,
    'fuzzing-pkts-file=s' => \$fuzzing_pkts_file,
    'fuzzing-pkts-append' => \$fuzzing_pkts_append,
    'fuzzing-test-tag=s'  => \$fuzzing_test_tag,
    'fuzzing-class=s'     => \$fuzzing_class,
    'enable-recompile-check' => \$enable_recompilation_warnings_check,
    'enable-profile-coverage-check' => \$enable_profile_coverage_check,
    'enable-ip-resolve' => \$enable_client_ip_resolve_test,
    'enable-distcheck'  => \$enable_make_distcheck,
    'enable-dist-check' => \$enable_make_distcheck,  ### synonym
    'enable-openssl-checks' => \$enable_openssl_compatibility_tests,
    'List-mode'         => \$list_mode,
    'test-limit=i'      => \$test_limit,
    'enable-valgrind'   => \$enable_valgrind,
    'enable-all'        => \$enable_all,
    'valgrind-path=s'   => \$valgrindCmd,
    ### can set the following to "output.last/valgrind-coverage" if
    ### a full test suite run has already been executed with --enable-valgrind
    'valgrind-prev-cov-dir=s' => \$previous_valgrind_coverage_dir,
    'output-dir=s'      => \$output_dir,
    'diff'              => \$diff_mode,
    'diff-dir1=s'       => \$diff_dir1,
    'diff-dir2=s'       => \$diff_dir2,
    'help'              => \$help
);

&usage() if $help;

if ($enable_all) {
    $enable_valgrind = 1;
    $enable_recompilation_warnings_check = 1;
    $enable_make_distcheck = 1;
    $enable_client_ip_resolve_test = 1;
    $enable_perl_module_checks = 1;
    $enable_openssl_compatibility_tests = 1;
}

### create an anonymized tar file of test suite results that can be
### emailed around to assist in debugging fwknop communications
exit &anonymize_results() if $anonymize_results;

&identify_loopback_intf();

$valgrind_str = "$valgrindCmd --leak-check=full " .
    "--show-reachable=yes --track-origins=yes" if $enable_valgrind;

my $intf_str = "-i $loopback_intf --foreground --verbose --verbose";

my $default_client_args = "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
    "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --get-key " .
    "$local_key_file --no-save-args --verbose --verbose";

my $default_client_args_no_get_key = "LD_LIBRARY_PATH=$lib_dir " .
    "$valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip " .
    "--no-save-args --verbose --verbose";

my $client_ip_resolve_args = "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
    "$fwknopCmd -A tcp/22 -R -D $loopback_ip --get-key " .
    "$local_key_file --verbose --verbose";

my $default_client_gpg_args = "$default_client_args " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key " .
    "--gpg-home-dir $gpg_client_home_dir";

my $default_client_gpg_args_no_homedir = "$default_client_args " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key ";

my $default_client_gpg_args_no_get_key = "$default_client_args_no_get_key " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key " .
    "--gpg-home-dir $gpg_client_home_dir";

my $default_server_conf_args = "-c $cf{'def'} -a $cf{'def_access'} " .
    "-d $default_digest_file -p $default_pid_file";

my $default_server_gpg_args = "LD_LIBRARY_PATH=$lib_dir " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_access'} $intf_str " .
    "-d $default_digest_file -p $default_pid_file";

my $default_server_gpg_args_no_pw = "LD_LIBRARY_PATH=$lib_dir " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_no_pw_access'} $intf_str " .
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
        'category' => 'make distcheck',
        'detail'   => 'ensure proper distribution creation',
        'err_msg'  => 'could not create proper tarball',
        'function' => \&make_distcheck,
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
            "$fwknopdCmd -c $cf{'def'} -a " .
            "$cf{'def_access'} --version",
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
            "$fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'def_access'} --dump-config",
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
        'detail'   => 'show last args',
        'err_msg'  => 'could not show last args',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Could\snot|Last\sfwknop/i],
        'exec_err' => $IGNORE,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd --show-last",
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
            "$fwknopCmd -A tcp/22 -a $fake_ip " .
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
        'detail'   => '-A <proto>/<port> specification (proto)',
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
        'detail'   => '-A <proto>/<port> specification (port)',
        'err_msg'  => 'permitted invalid -A <proto>/<port>',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Invalid\sSPA\saccess\smessage/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/600001 -a $fake_ip -D $loopback_ip",
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
        'detail'   => 'rotate digest file',
        'err_msg'  => 'could not rotate digest file',
        'function' => \&rotate_digest_file,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str --rotate-digest-cache",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client',
        'detail'   => "--save-packet $tmp_pkt_file",
        'err_msg'  => 'could not run SPA client',
        'function' => \&client_save_spa_pkt,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --save-args-file $tmp_args_file --verbose " .
            "--verbose --save-packet $tmp_pkt_file",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client',
        'detail'   => "--last-cmd",
        'err_msg'  => 'could not run last args',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd --last-cmd --save-args-file $tmp_args_file " .
            "--verbose --verbose",
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'permissions check cycle (tcp/22)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&permissions_check,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/permissions\sshould\sonly\sbe\suser/],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'client IP resolve (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => $client_ip_resolve_args,
        'no_ip_check' => 1,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle MD5 (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -m md5",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA1 (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -m sha1",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA256 (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -m sha256",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA384 (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -m sha384",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA512 (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -m sha512",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client',
        'detail'   => 'validate digest type arg',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&generic_exec,
        'cmdline'  => "$default_client_args -m invaliddigest",
        'positive_output_matches' => [qr/Invalid\sdigest\stype/i],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'dual usage access key (tcp/80 http)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/80 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'dual_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        ### check for the first stanza that does not allow tcp/80 - the
        ### second stanza allows this
        'server_positive_output_matches' => [qr/stanza #1\)\sOne\sor\smore\srequested\sprotocol\/ports\swas\sdenied/],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'create rc file (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args --rc-file $tmp_rc_file",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $tmp_rc_file,
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => "rc file created",
        'err_msg'  => "rc file $tmp_rc_file does not exist",
        'function' => \&rc_file_exists,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'rc file default key (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_file_def_key'}",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_file_def_key'},
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'rc file base64 key (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_file_def_b64_key'}",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'base64_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_file_def_b64_key'},
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'rc file named key (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_file_named_key'} -n testssh",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_file_named_key'},
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client',
        'detail'   => 'rc file HMAC base64 key (tcp/22 ssh)',
        'err_msg'  => 'SPA packet not generated',
        'function' => \&generic_exec,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_file_hmac_b64_key'}",
        'key_file' => $cf{'rc_file_hmac_b64_key'},
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle + HMAC (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_file_hmac_b64_key'}",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'altered HMAC (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&altered_hmac_spa_data,  ### alter HMAC itself
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_file_hmac_b64_key'}",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'key_file' => $cf{'rc_file_hmac_b64_key'},
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'altered pkt HMAC (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&altered_pkt_hmac_spa_data,  ### alter SPA payload
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_file_hmac_b64_key'}",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'key_file' => $cf{'rc_file_hmac_b64_key'},
        'fatal'    => $NO
    },

    ### --key-gen tests
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client',
        'detail'   => '--key-gen',
        'err_msg'  => 'keys not generated',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir " .
            "$valgrind_str $fwknopCmd --key-gen",
        'positive_output_matches' => [qr/BASE64/, qw/HMAC/, qw/KEY/],
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client',
        'detail'   => "--key-gen $uniq_keys key uniqueness",
        'err_msg'  => 'keys not generated',
        'function' => \&key_gen_uniqueness,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd --key-gen",   ### no valgrind string (too slow for 100 client exec's)
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client',
        'detail'   => '--key-gen to file',
        'err_msg'  => 'keys not generated',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir " .
            "$valgrind_str $fwknopCmd --key-gen --key-gen-file $key_gen_file",
        'positive_output_matches' => [qr/Wrote.*\skeys/],
        'fatal'    => $NO
    },

    ### rc file tests
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client',
        'detail'   => 'rc file invalid stanza (tcp/22 ssh)',
        'err_msg'  => 'SPA packet generated/accepted',
        'function' => \&generic_exec,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_file_named_key'} -n invalidstanza",
        'positive_output_matches' => [qr/Named\sconfiguration.*not\sfound/],
        'key_file' => $cf{'rc_file_named_key'},
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client',
        'detail'   => 'rc file invalid base64 key (tcp/22 ssh)',
        'err_msg'  => 'SPA packet generated/accepted',
        'function' => \&generic_exec,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_file_invalid_b64_key'} -n testssh",
        'positive_output_matches' => [qr/look\slike\sbase64\-encoded/],
        'key_file' => $cf{'rc_file_invalide_b64_key'},
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
        'detail'   => 'invalid SOURCE (tcp/22 ssh)',
        'err_msg'  => 'SPA packet accepted',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'invalid_src_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/Fatal\serror\sparsing\sIP\sto\sint/],
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'exp_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'invalid_exp_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'exp_epoch_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'future_exp_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'open_ports_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'open_ports_mismatch'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/One\s+or\s+more\s+requested/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },

    ### spoof the source IP on the SPA packet
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "udpraw spoof src IP (tcp/22 ssh)",
        'err_msg'  => "could not spoof source IP",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -P udpraw -Q $spoof_ip",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_positive_output_matches' => [qr/SPA\sPacket\sfrom\sIP\:\s$spoof_ip\s/],
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "tcpraw spoof src IP (tcp/22 ssh)",
        'err_msg'  => "could not spoof source IP",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -P tcpraw -Q $spoof_ip",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'tcp_pcap_filter'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_positive_output_matches' => [qr/SPA\sPacket\sfrom\sIP\:\s$spoof_ip\s/],
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "icmp spoof src IP (tcp/22 ssh)",
        'err_msg'  => "could not spoof source IP",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -P icmp -Q $spoof_ip",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'icmp_pcap_filter'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_positive_output_matches' => [qr/SPA\sPacket\sfrom\sIP\:\s$spoof_ip\s/],
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "icmp type/code 8/0 spoof src IP ",
        'err_msg'  => "could not spoof source IP",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -P icmp --icmp-type 8 --icmp-code 0 -Q $spoof_ip",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'icmp_pcap_filter'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_positive_output_matches' => [qr/SPA\sPacket\sfrom\sIP\:\s$spoof_ip\s/],
        'fatal'    => $NO
    },

    ### SPA over TCP (not really "single" packet auth since a TCP connection
    ### is established)
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "SPA over TCP connection",
        'err_msg'  => "could not send/process SPA packet over TCP connection",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args -P tcp",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'tcp_server'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'require_user_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'user_mismatch_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'require_src_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'require_src_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/Got\s0.0.0.0\swhen\svalid\ssource\sIP/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'allow -s (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'no_ip_check' => 1,
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -s -D $loopback_ip --get-key " .
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
        'detail'   => 'IP filtering (tcp/22 ssh)',
        'err_msg'  => "did not filter $loopback_ip",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'no_src_match'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'no_subnet_match'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'no_multi_src'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'ip_src_match'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'subnet_src_match'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'multi_src_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'multi_stanza_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'broken_keys_access'} " .
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
        'server_conf' => $cf{'nat'},
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
            "$fwknopdCmd -c $cf{'nat'} -a $cf{'open_ports_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'nat'},
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client',
        'detail'   => "NAT bogus IP validation",
        'err_msg'  => "could not complete NAT SPA cycle",
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args -N 999.1.1.1:22",
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
            "$fwknopdCmd -c $cf{'nat'} -a $cf{'force_nat_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/\sto\:$force_nat_host\:22/i],
        'server_negative_output_matches' => [qr/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'nat'},
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "local NAT $force_nat_host (tcp/22 ssh)",
        'err_msg'  => "could not complete NAT SPA cycle",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args --nat-local",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'local_nat'} -a $cf{'force_nat_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/to\:$force_nat_host\:22/i,
            qr/FWKNOP_INPUT.*dport\s22.*\sACCEPT/],
        'server_negative_output_matches' => [qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'nat'},
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => "local NAT non-FORCE_NAT (tcp/22 ssh)",
        'err_msg'  => "could not complete NAT SPA cycle",
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/80 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose --nat-local --nat-port 22",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'local_nat'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/to\:$loopback_ip\:22/i,
            qr/FWKNOP_INPUT.*dport\s22.*\sACCEPT/],
        'server_negative_output_matches' => [qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'nat'},
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'ecb_mode_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'cfb_mode_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'ctr_mode_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'ofb_mode_access'} " .
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
            "$fwknopdCmd -c $cf{'def'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/Decryption\sfailed/i],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },

    ### --pcap-file
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => '--pcap-file processing',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&process_pcap_file_directly,
        'cmdline'  => '',
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "--pcap-file $replay_pcap_file --foreground --verbose --verbose " .
            "--verbose",
        'server_positive_output_matches' => [qr/Replay\sdetected/i,
            qr/candidate\sSPA/, qr/0x0000\:\s+2b/],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
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
        'detail'   => 'complete cycle (tcp/60001)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/60001 -a $fake_ip -D $loopback_ip --get-key " .
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
        'detail'   => 'multi port (tcp/60001,udp/60001)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/60001,udp/60001 -a $fake_ip -D $loopback_ip --get-key " .
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
        'detail'   => 'multi port (tcp/22,udp/53,tcp/1234)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22,udp/53,tcp/1234 -a $fake_ip -D $loopback_ip --get-key " .
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
        'replay_positive_output_matches' => [qr/Replay\sdetected\sfrom\ssource\sIP/],
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay #1 (Rijndael prefix)',
        'err_msg'  => 'could not detect replay attack',
        'function' => \&replay_detection,
        'pkt_prefix' => 'U2FsdGVkX1',
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'replay_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
        'fatal'    => $NO
    },

    ### ensure iptables rules are not duplicated for identical access requests
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'iptables rules not duplicated',
        'err_msg'  => 'iptables rules duplicated',
        'function' => \&iptables_rules_not_duplicated,
        'cmdline'  => "$default_client_args --test",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_negative_output_matches' => [qr/^2\s+ACCEPT\s.*$fake_ip/],
        'fatal'    => $NO
    },

    ### backwards compatibility tests
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client->server backwards compatibility',
        'detail'   => 'v2.0',
        'err_msg'  => 'backwards compatibility failed',
        'function' => \&backwards_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '9ptGrLs8kVGVludcXFy17opvThEYzTeaT7RVlCN66W/G9QZs9BBevEQ0xxI8eCn' .
            'KPDM+Bu9g0XwmCEVxxg+4jwBwtbCxVt9t5aSR29EVWZ6UAOwLkunK3t4FYBy1tL' .
            '55krFt+1B2TtNSAH005kyDEZEOIGoY9Q/iU',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client->server backwards compatibility',
        'detail'   => 'v2.0.1',
        'err_msg'  => 'backwards compatibility failed',
        'function' => \&backwards_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '+uAD6hlS2BHuaCtVKIGyIsB/4U8USqcP9o4aT6FvBuPKORwTV8byyzv6bzZYINs4' .
            'Voq3QvBbIwkXJ63/oU+XxvP5R+DBLEnh3e/NHPFK6NB0WT2dujVyVxwBfvvWjIqW' .
            'Hhro2tH34nqfTRIpevfLTMx7r+N8ZQ4V8',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client->server backwards compatibility',
        'detail'   => 'v2.0.2',
        'err_msg'  => 'backwards compatibility failed',
        'function' => \&backwards_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '+mS70t2A2YmV50KgwDyy6nYLwzQ7AUO8pA/eatm7g9xc83xy1z7VOXeAYrgAOWy' .
            'Ksk30QvkwHtPhl7I0oDz1bO+2K2JbDbyc0KBBzVNMLgJcuYgEpOXPkX2XhcTsgQ' .
            'Vw2/Va/aUjvEvNPtwuipQS6DLTzOw/qy+/g',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client->server backwards compatibility',
        'detail'   => 'v2.0.3',
        'err_msg'  => 'backwards compatibility failed',
        'function' => \&backwards_compatibility,
        'pkt' =>
            '+8OtxmTJPgQmrXZ7hAqTopLBC/thqHNuPHTfR234pFuQOCZUikPe0inHmjfnQFnP' .
            'Sop/Iy6v+BCn9D+QD7eT7JI6BIoKp14K+8iNgKaNw1BdfgF1XDulpkNEdyG0fXz5' .
            'M+GledHfz2d49aYThoQ2Cr8Iw1ycViawY',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client->server backwards compatibility',
        'detail'   => 'v2.0.4',
        'err_msg'  => 'backwards compatibility failed',
        'function' => \&backwards_compatibility,
        'pkt' =>
            '8Xm8U5vQ03T88UTCWbwO3t/aL6euZ8IgVbNdDVz3Bn6HkTcBqxcME95U/G3bCH' .
            'vQznpnGb05Md4ZgexHZGzZdSwsP8iVtcZdsgCBfeO4Eqs8OaSMjJVF8SQ+Jmhu' .
            'XZMcWgMsIzhpprJ7JX41DrWd0OtBnE3rVwsN0',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'Android compatibility',
        'detail'   => 'v4.1.2',
        'err_msg'  => 'Android compatibility failed',
        'function' => \&backwards_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '+59hIQhS1RlmqYLXNM/hPxtBAQTB5y3UKZq13O+r6qmg+APdQ+HQ' .
            'OI7d4QCsp14s8KJpW8qBzZ/n0aZCFCFdZnvdZeJJVboQu4jo' .
            'QFKZ8mmKwR/5DIO7k3qrXYGxYP0bnHYsih0HIE6CzSHlBGSf' .
            'DJR92YhjYtL4Q',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'android_legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },

    ### fuzzing tests
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'FUZZING',
        'detail'   => 'overly long port value',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A \
        # "tcp/`perl -e '{print "1"x"40"}'`" -a 127.0.0.2 -D 127.0.0.1 \
        # --get-key local_spa.key --verbose --verbose
        #
        # This problem was found by Fernando Arnaboldi of IOActive and exploits
        # a buffer overflow in the fwknopd servers prior to 2.0.3 from
        # authenticated clients.
        #
        'fuzzing_pkt' =>
            '+JzxeTGlc6lwwzbJSrYChKx8bonWBIPajwGfEtGOaoglcMLbTY/GGXo/nxqiN1LykFS' .
            'lDFXgrkyx2emJ7NGzYqQPUYZxLdZRocR9aRIptvXLLIPBcIpJASi/TUiJlw7CDFMcj0' .
            'ptSBJJUZi0tozpKHETp3AgqfzyOy5FNs38aZsV5/sDl3Pt+kF7fTZJ+YLbmYY4yCUz2' .
            'ZUYoCaJ7X78ULyJTi5eT7nug',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'FUZZING',
        'detail'   => 'overly long proto value',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A \
        # "tcp`perl -e '{print "A"x"28"}'`/1" -a 127.0.0.2 -D 127.0.0.1 \
        # --get-key local_spa.key --verbose --verbose
        #
        # This problem was found by Fernando Arnaboldi of IOActive and exploits
        # a buffer overflow in the fwknopd servers prior to 2.0.3 from
        # authenticated clients.
        #
        'fuzzing_pkt' =>
            '/im5MiJQmOdzqrdWXv+AjEtAm/HsLrdaTFcSw3ZskqpGOdDIrSCz3VXbFfv7qDkc5Y4' .
            'q/k1mRXl9SGzpug87U5dZSyCdAr30z7/2kUFEPTGOQBi/x+L1t1pvdkm4xg13t09ldm' .
            '5OD8KiV6qzqLOvN4ULJjvvJJWBZ9qvo/f2Q9Wf67g2KHiwS6EeCINAuMoUw/mNRQMa4' .
            'oGnOXu3/DeWHJAwtSeh7EAr4',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'FUZZING',
        'detail'   => 'overly long IP value',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A tcp/22 \
        # -a `perl -e '{print "1"x"136"}'`.0.0.1 -D 127.0.0.1 \
        # --get-key local_spa.key --verbose --verbose
        #
        # This problem was found by Fernando Arnaboldi of IOActive and exploits
        # a condition in which pre-2.0.3 fwknopd servers fail to properly validate
        # allow IP addresses from malicious authenticated clients.
        #
        'fuzzing_pkt' =>
            '93f2rhsXLmBoPicWvYTqrbp+6lNqvWDc8dzmX2s3settwjBGRAXm33TB9agibEphrBu' .
            '3d+7DEsivZLDS6Kz0JwdjX7t0J9c8es+DVNjlLnPtVNcxhs+2kUzimNrgysIXQRJ+GF' .
            'GbhdxiXCqdy1vWxWpdoaZmY/CeGIkpoFJFPbJhCRLLX25UMvMF2wXj02MpI4d3t1/6W' .
            'DM3taM3kZsiFv6HxFjAhIEuQ1oAg2OgRGXkDmT3jDNZMHUm0d4Ahm9LonG7RbOxq/B0' .
            'qUvY8lkymbwvjelVok7Lvlc06cRhN4zm32D4V05g0vQS3PlX9C+mgph9DeAPVX+D8iZ' .
            '8lGrxcPSfbCOW61k0MP+q1EhLZkc1qAm5g2+2cLNZcoBNEdh3yj8OTPZJyBVw',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'FUZZING',
        'detail'   => 'negative port value',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A \
        # tcp/-33 -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key \
        # --verbose --verbose
        #
        'fuzzing_pkt' =>
            '/weoc+pEuQknZo8ImWTQBB+/PwSJ2/TcrmFoSkxpRXX4+jlUxoJakHrioxh8rhLmAD9' .
            '8E4lMnq+EbM2XYdhs2alpZ5bovAFojMsYRWwr/BvRO4Um4Fmo9z9sY3DR477TXNYXBR' .
            'iGXWxSL4u+AWSSePK3qiiYoRQVw',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'FUZZING',
        'detail'   => 'null port value',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A tcp/ \
        # -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key \
        # --verbose --verbose
        #
        'fuzzing_pkt' =>
            '94nu7hvq6V/3A27GzjHwfPnPCQfs44ySlraIFYHOAqy5YqjkrBS67nH35tX55N1BrYZ' .
            '07zvcT03keUhLE1Uo7Wme1nE7BfTOG5stmIK1UQI85sL52//lDHu+xCqNcL7GUKbVRz' .
            'ekw+EUscVvUkrsRcVtSvOm+fCNo',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'FUZZING',
        'detail'   => 'long FKO protocol value (enc mode trigger)',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A tcp/22 \
        # -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key --verbose --verbose
        #
        # This problem was found by Fernando Arnaboldi of IOActive and is designed
        # to have fwknopd look for a mode decryption mode for a long Rijndael-
        # encrypted SPA packet
        #
        'fuzzing_pkt' =>
            '/ewH/k1XsDX+VQ8NlNvCZ4P2QOl/4IpJYXkq4TtAe3899OtApXJiTtPCuYW70XPuxge' .
            'MtFjc4UfslK/r9v+FYfyd3fIIHCz0Q0M4+nM3agTLmJj8nOxk6ZeBj82SDQWhHAxGdJ' .
            'IQALPve0ug4cuGxS3b4M+2Q/Av9i2tU3Lzlogw3sY0tk6wGf4zZk4UsviVXYpINniGT' .
            'RhYSIQ1dfdkng7hKiHMDaObYY1GFp4nxEt/QjasAwvE+7/iFyoKN+IRpGG4v4hGEPh2' .
            'vTDqmvfRuIHtgFD7NxZjt+m/jjcu0gkdWEoD4fenwGU35FlvchyM2AiAEw7yRzSABfn' .
            'R9d3sYZGMtyASw2O1vSluwIxUUnDop3gxEIhJEj8h+01pA3K+klSpALeY9EZgHqYC7E' .
            'ETuPS6dZ3764nWohtCY67JvNUX7TtNDNc2qrhrapdRP17+PT2Vh4s9m38V3WwVWC3uH' .
            'X/klLZcHIt+aRDV+uekw9GOKSgwFL2ekPpr3gXxigc3zrxel5hcsqLOpVUa4CP/0HkG' .
            'F0NPQvOT3ZvpeIJnirKP1ZX9gDFinqhuzL7oqktW61e1iwe7KZEdrZV0k2KZwyb8qU5' .
            'rPAEnw',
        'server_positive_output_matches' => [qr/No\sstanza\sencryption\smode\smatch/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'FUZZING',
        'detail'   => 'long FKO protocol value (Rijndael trigger)',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A tcp/22 \
        # -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key --verbose --verbose
        #
        # This problem was found by Fernando Arnaboldi of IOActive and is designed
        # to have fwknopd look for a mode decryption mode for a long Rijndael-
        # encrypted SPA packet
        #
        'fuzzing_pkt' =>
            '+YQNu4BFgiNeu8HeiBiNKriqCFSseALt9vJaKzkzK/OF4pjkJcvhGEOi7fEVXqn3VIdlGR' .
            'DmBul2I7H3z18U9E97bWGgT9NexKgEPCuekL18ZEPf5xR3JleNsNWatqYgAOkgN8ZWE69Q' .
            'qQUYYhxTvJHS6R+5JqFKB3A44hMXoICdYNkn9MAktHxk3PbbpQ+nA+jESwVCra2doAiLiM' .
            'ucvGIZZiTv0Mc1blFYIE2zqZ/C7ct1V+ukwSkUv0r87eA7uJhmlpThRsL0dN6iekJ6i87B' .
            'tE8QyuOXzOMftI11SUn/LwqD4RMdR21rvLrzR6ZB5eUX2UBpODyzX6n+PJJkTWCuFVT4z1' .
            'MKY',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'FUZZING',
        'detail'   => 'null proto value',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A /22 \
        # -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key \
        # --verbose --verbose
        #
        'fuzzing_pkt' =>
            '/JT14qxh9P4iy+CuUZahThaQjoEuL2zd46a+jL6sTrBZJSa6faUX4dH5fte/4ZJv+9f' .
            'd/diWYKAUvdQ4DydPGlR7mwQa2W+obKpqrsTBz7D4054z6ATAOGpCtifakEVl1XRc2+' .
            'hW04WpY8mdUNu9i+PrfPr7/KxqU',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'FUZZING',
        'detail'   => 'invalid NAT IP',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A tcp/22 \
        # -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key --verbose \
        # --verbose -N 999.1.1.1:22
        'fuzzing_pkt' =>
            '/v/kYVOqw+NCkg8CNEphPPvH3dOAECWjqiF+NNYnK7yKHer/Gy8wCVNa/Rr/Wnm' .
            'siApB3jrXEfyEY3yebJV+PHoYIYC3+4Trt2jxw0m+6iR231Ywhw1JetIPwsv7iQ' .
            'ATvSTpZ+qiaoN0PPfy0+7yM6KlaQIu7bfG5E2a6VJTqTZ1qYz3H7QaJfbAtOD8j' .
            'yEkDgP5+f49xrRA',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging_nat'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fatal'    => $NO
    },

    {
        'category' => 'FUZZING',
        'subcategory' => 'server',
        'detail'   => 'invalid SOURCE access.conf',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'fuzz_source'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'positive_output_matches' => [qr/Fatal\sinvalid/],
        'exec_err' => $YES,
        'fatal'    => $NO
    },
    {
        'category' => 'FUZZING',
        'subcategory' => 'server',
        'detail'   => 'invalid OPEN_PORTS access.conf',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'fuzz_open_ports'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'positive_output_matches' => [qr/Fatal\sinvalid/],
        'exec_err' => $YES,
        'fatal'    => $NO
    },
    {
        'category' => 'FUZZING',
        'subcategory' => 'server',
        'detail'   => 'invalid RESTRICT_PORTS access.conf',
        'err_msg'  => 'server crashed or did not detect error condition',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'fuzz_restrict_ports'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'positive_output_matches' => [qr/Fatal\sinvalid/],
        'exec_err' => $YES,
        'fatal'    => $NO
    },

    ### command execution tests
    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'command execution',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            qq|$fwknopCmd --server-cmd "echo fwknoptest > $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --get-key $local_key_file " .
            "--verbose --verbose",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'cmd_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },

    {
        'category' => 'Rijndael SPA',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay #2 (Rijndael prefix)',
        'err_msg'  => 'could not detect replay attack',
        'function' => \&replay_detection,
        'pkt_prefix' => 'U2FsdGVkX1',
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
        'subcategory' => 'server',
        'detail'   => 'ipfw active/expire sets not equal',
        'err_msg'  => 'allowed active/expire sets to be the same',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'ipfw_active_expire'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/Cannot\sset\sidentical\sipfw\sactive\sand\sexpire\ssets/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
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

    ### perl module checks
    {
        'category' => 'perl FKO module',
        'subcategory' => 'compile/install',
        'detail'   => 'to: ./FKO',
        'err_msg'  => 'could not install FKO module',
        'function' => \&perl_fko_module_compile_install,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'FUZZING',
        'detail'   => 'generate invalid SPA pkts',
        'err_msg'  => 'could not generate invalid SPA pkts',
        'function' => \&perl_fko_module_assume_patches_generate_fuzzing_spa_packets,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'FUZZING',
        'detail'   => 'generate invalid encoded pkts',
        'err_msg'  => 'could not generate invalid SPA pkts',
        'function' => \&perl_fko_module_assume_patches_generate_fuzzing_encoding_spa_packets,
        'fatal'    => $NO
    },

    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'create/destroy FKO object',
        'err_msg'  => 'could not create/destroy FKO object',
        'function' => \&perl_fko_module_new_object,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'create/destroy 1000 FKO objects',
        'err_msg'  => 'could not create/destroy FKO object',
        'function' => \&perl_fko_module_new_objects_1000,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko version',
        'err_msg'  => 'could not get libfko version',
        'function' => \&perl_fko_module_version,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get random data',
        'err_msg'  => 'could not get libfko random data',
        'function' => \&perl_fko_module_rand,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set username',
        'err_msg'  => 'could not get libfko username',
        'function' => \&perl_fko_module_user,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko timestamp',
        'err_msg'  => 'could not get libfko timestamp',
        'function' => \&perl_fko_module_timestamp,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set msg types',
        'err_msg'  => 'could not get/set libfko msg types',
        'function' => \&perl_fko_module_msg_types,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set access msgs',
        'err_msg'  => 'could not get/set libfko access msgs',
        'function' => \&perl_fko_module_access_msgs,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set NAT access msgs',
        'err_msg'  => 'could not get/set libfko NAT access msgs',
        'function' => \&perl_fko_module_nat_access_msgs,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set cmd msgs',
        'err_msg'  => 'could not get/set libfko cmd msgs',
        'function' => \&perl_fko_module_cmd_msgs,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set client timeout',
        'err_msg'  => 'could not get/set libfko client timeout',
        'function' => \&perl_fko_module_client_timeout,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'encrypt/decrypt',
        'detail'   => 'libfko complete cycle',
        'err_msg'  => 'could not finish complete cycle',
        'function' => \&perl_fko_module_complete_cycle,
        'set_legacy_iv' => $NO,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'encrypt/decrypt',
        'detail'   => 'libfko complete cycle (lIV)',
        'err_msg'  => 'could not finish complete cycle',
        'function' => \&perl_fko_module_complete_cycle,
        'set_legacy_iv' => $YES,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'encrypt/decrypt',
        'detail'   => 'truncated keys',
        'err_msg'  => 'allowed truncated keys to decrypt SPA data',
        'function' => \&perl_fko_module_rijndael_truncated_keys,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'encrypt/decrypt',
        'detail'   => 'complete cycle (mod reuse)',
        'err_msg'  => 'could not finish complete cycle',
        'function' => \&perl_fko_module_complete_cycle_module_reuse,
        'set_legacy_iv' => $NO,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'encrypt/decrypt',
        'detail'   => 'complete cycle (mod reuse, lIV)',
        'err_msg'  => 'could not finish complete cycle',
        'function' => \&perl_fko_module_complete_cycle_module_reuse,
        'set_legacy_iv' => $YES,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'fuzzing data',
        'detail'   => 'legacy IV REPLPKTS',
        'err_msg'  => 'server accepted fuzzing pkts',
        'function' => \&perl_fko_module_full_fuzzing_packets,
        'set_legacy_iv' => $YES,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'fuzzing data',
        'detail'   => 'non-legacy IV REPLPKTS',
        'err_msg'  => 'server accepted fuzzing pkts',
        'function' => \&perl_fko_module_full_fuzzing_packets,
        'set_legacy_iv' => $NO,
        'fatal'    => $NO
    },

    {
        'category' => 'perl FKO module',
        'subcategory' => 'compatibility',
        'detail'   => 'client FKO -> C server',
        'err_msg'  => 'invalid SPA packet data',
        'function' => \&perl_fko_module_client_compatibility,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'compatibility',
        'detail'   => 'FKO -> C invalid legacy IV',
        'err_msg'  => 'invalid SPA packet data',
        'function' => \&perl_fko_module_client_compatibility,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "$intf_str",
        'server_positive_output_matches' => [qr/Decryption failed/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'compatibility',
        'detail'   => 'FKO -> C valid legacy IV',
        'err_msg'  => 'invalid SPA packet data',
        'function' => \&perl_fko_module_client_compatibility,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "$intf_str",
        'set_legacy_iv' => $YES,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    ### no password GPG testing
    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'multi gpg-IDs (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir " .
            "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'multi_gpg_no_pw_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/23 telnet)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/23 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/9418 git)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/9418 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/60001)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/60001 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (udp/53 dns)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A udp/53 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'replay attack detection',
        'err_msg'  => 'could not detect replay attack',
        'function' => \&replay_detection,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'replay_positive_output_matches' => [qr/Replay\sdetected\sfrom\ssource\sIP/],
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay #1 (GnuPG prefix)',
        'err_msg'  => 'could not detect replay attack',
        'function' => \&replay_detection,
        'pkt_prefix' => 'hQ',
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'replay_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
        'fatal'    => $NO
    },

    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'non-base64 altered SPA data',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&altered_non_base64_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'base64 altered SPA data',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&altered_base64_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'appended data to SPA pkt',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&appended_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'prepended data to SPA pkt',
        'err_msg'  => 'allowed improper SPA data',
        'function' => \&prepended_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'spoof username (tcp/22 ssh)',
        'err_msg'  => 'could not spoof username',
        'function' => \&spoof_username,
        'cmdline'  => "SPOOF_USER=$spoof_user $default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fatal'    => $NO
    },

    ### GPG testing (with passwords associated with keys) - first check to
    ### see if pinentry is required and disable remaining GPG tests if so
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'pinentry not required',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&gpg_pinentry_check,
        'cmdline'  => $default_client_gpg_args,
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
        'detail'   => 'rc file default key (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_gpg_args_no_get_key " .
            "--rc-file $cf{'rc_file_def_key'}",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_file_def_key'},
        'fatal'    => $NO
    },
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'rc file named key (tcp/22 ssh)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_gpg_args_no_get_key " .
            "--rc-file $cf{'rc_file_named_key'} -n testssh",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_file_named_key'},
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
            "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'multi_gpg_access'} $intf_str " .
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
        'detail'   => 'complete cycle (tcp/60001)',
        'err_msg'  => 'could not complete SPA cycle',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/60001 -a $fake_ip -D $loopback_ip --get-key " .
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
        'replay_positive_output_matches' => [qr/Replay\sdetected\sfrom\ssource\sIP/],
        'fatal'    => $NO
    },
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay #2 (GnuPG prefix)',
        'err_msg'  => 'could not detect replay attack',
        'function' => \&replay_detection,
        'pkt_prefix' => 'hQ',
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'replay_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
        'fatal'    => $NO
    },
    {
        'category' => 'GnuPG (GPG) SPA',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay #3 (GnuPG prefix)',
        'err_msg'  => 'could not detect replay attack',
        'function' => \&replay_detection,
        'pkt_prefix' => 'hQ',
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
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
    'key_file'        => $OPTIONAL,
    'exec_err'        => $OPTIONAL,
    'fw_rule_created' => $OPTIONAL,
    'fw_rule_removed' => $OPTIONAL,
    'server_conf'     => $OPTIONAL,
    'pkt_prefix'      => $OPTIONAL,
    'no_ip_check'     => $OPTIONAL,
    'set_legacy_iv'   => $OPTIONAL,
    'positive_output_matches' => $OPTIONAL,
    'negative_output_matches' => $OPTIONAL,
    'server_positive_output_matches' => $OPTIONAL,
    'server_negative_output_matches' => $OPTIONAL,
    'replay_positive_output_matches' => $OPTIONAL,
    'replay_negative_output_matches' => $OPTIONAL,
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
    if ($test_limit > 0) {
        last if $executed >= $test_limit;
    }
}

if ($enable_profile_coverage_check) {
    &run_test(
        {
            'category' => 'profile coverage',
            'detail'   => 'gcov profile coverage',
            'err_msg'  => 'profile coverage failed',
            'function' => \&profile_coverage,
            'fatal'    => $NO
        },
    );
}

if ($enable_valgrind) {
    &run_test(
        {
            'category' => 'valgrind',
            'subcategory' => 'fko-wrapper',
            'detail'   => 'multiple libfko calls',
            'err_msg'  => 'could not compile/execute fko-wrapper',
            'function' => \&compile_execute_fko_wrapper,
            'fatal'    => $NO
        }
    );
    &run_test(
        {
            'category' => 'valgrind output',
            'subcategory' => 'flagged functions',
            'detail'   => '',
            'err_msg'  => 'could not parse flagged functions',
            'function' => \&parse_valgrind_flagged_functions,
            'fatal'    => $NO
        }
    );
}

&logr("\n");
if ($enable_openssl_compatibility_tests) {
    &logr("[+] $openssl_success_ctr/$openssl_failure_ctr/$openssl_ctr " .
        "OpenSSL tests passed/failed/executed\n");
}
if ($fuzzing_ctr > 0) {
    &logr("[+] $fuzzing_success_ctr/$fuzzing_failure_ctr/$fuzzing_ctr " .
        "Fuzzing tests passed/failed/executed\n");
}
&logr("[+] $passed/$failed/$executed tests passed/failed/executed\n\n");

copy $logfile, "$output_dir/$logfile" or die $!;

if ($pinentry_fail) {
    if ($killall_path) {
        ### kill all gpg processes in the fwknop client
        ### process group (this will kill the test suite
        ### too, but we're already done)
        system "$killall_path -g fwknop";
    }
}

exit 0;

#===================== end main =======================

sub run_test() {
    my $test_hr = shift;

    my $msg = "[$test_hr->{'category'}]";
    $msg .= " [$test_hr->{'subcategory'}]" if $test_hr->{'subcategory'};
    $msg .= " $test_hr->{'detail'}";

    $msg =~ s/REPLPKTS/-->$total_fuzzing_pkts<-- pkts/;

    return unless &process_include_exclude($msg);

    if ($list_mode) {
        print $msg, "\n";
        return;
    }

    &dots_print($msg);

    $executed++;
    $curr_test_file   = "$output_dir/$executed.test";
    $server_test_file = "$output_dir/${executed}_fwknopd.test";

    &write_test_file("[+] TEST: $msg\n", $curr_test_file);
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

    if ($enable_valgrind) {
        if ($killall_path and $pgrep_path) {
            for my $cmd ('memcheck', 'valgrind') {
                system "$pgrep_path > /dev/null $cmd " .
                    "&& $killall_path -g -r $cmd > /dev/null 2>&1";
            }
        }
    }

    if ($enable_perl_module_fuzzing_spa_pkt_generation) {
       if ($msg =~ /perl FKO module.*FUZZING/) {
            print "\n[+] Wrote $fuzzing_num_pkts fuzzing SPA ",
                "packets to $fuzzing_pkts_file.tmp...\n\n";
            exit 0;
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
            if ($msg =~ $test
                    or ($enable_valgrind and $msg =~ /valgrind\soutput/)
                    or ($enable_profile_coverage_check and $msg =~ /profile\scoverage/)
            ) {
                $found = 1;
                last;
            }
        }
        return 0 unless $found;
    }
    if (@tests_to_exclude) {
        my $found = 0;
        for my $test (@tests_to_exclude) {
            if ($msg =~ $test) {
                $found = 1;
                last;
            }
        }
        return 0 if $found;
    }
    return 1;
}

sub diff_test_results() {

    $diff_dir1 = "${output_dir}.last" unless $diff_dir1;
    $diff_dir2 = $output_dir unless $diff_dir2;

    die "[*] Need results from a previous run before running --diff"
        unless -d $diff_dir2;
    die "[*] Current results set does not exist." unless -d $diff_dir1;

    my %curr_tests  = ();
    my %prev_tests = ();

    ### Only diff results for matching tests (parse the logfile to see which
    ### test numbers match across the two test cycles).
    &build_results_hash(\%curr_tests, $diff_dir1);
    &build_results_hash(\%prev_tests, $diff_dir2);

    for my $test_msg (sort {$curr_tests{$a}{'num'} <=> $curr_tests{$b}{'num'}}
                keys %curr_tests) {
        my $curr_result = $curr_tests{$test_msg}{'pass_fail'};
        my $curr_num    = $curr_tests{$test_msg}{'num'};
        if (defined $prev_tests{$test_msg}) {
            print "[+] Diff check: $test_msg\n";
            my $prev_result = $prev_tests{$test_msg}{'pass_fail'};
            my $prev_num    = $prev_tests{$test_msg}{'num'};
            if ($curr_result ne $prev_result) {
                print " ** Verdict diff: current: $curr_result, ",
                    "previous: $prev_result $test_msg\n";
            }

            &diff_results($prev_num, $curr_num, $diff_dir1, $diff_dir2);

            print "\n";
        }
    }

    if (-d "$diff_dir1/$valgrind_cov_dir"
            and -d "$diff_dir2/$valgrind_cov_dir") {
        &diff_valgrind_results(\%curr_tests, \%prev_tests)
    }

    exit 0;
}

sub diff_valgrind_results() {
    my ($curr_tests_hr, $prev_tests_hr) = @_;

    print "\n\n\n[+] Valgrind differences:\n\n";
    for my $test_msg (sort {$curr_tests_hr->{$a}->{'num'} <=> $curr_tests_hr->{$b}->{'num'}}
                keys %$curr_tests_hr) {
        my $curr_num = $curr_tests_hr->{$test_msg}->{'num'};
        if (defined $prev_tests_hr->{$test_msg}) {
            print "[+] Valgrind diff check: $test_msg\n";
            my $prev_result = $prev_tests_hr->{$test_msg}->{'pass_fail'};
            my $prev_num    = $prev_tests_hr->{$test_msg}->{'num'};
            &diff_results($prev_num, $curr_num,
                "$diff_dir1/$valgrind_cov_dir", "$diff_dir2/$valgrind_cov_dir");

            print "\n";
        }
    }

    return;
}

sub diff_results() {
    my ($prev_num, $curr_num, $dir1, $dir2) = @_;

    ### edit out any valgrind "==354==" prefixes
    my $valgrind_search_re = qr/^==\d+==\s/;

    ### remove CMD timestamps
    my $cmd_search_re = qr/^\S+\s.*?\s\d{4}\sCMD\:/;

    for my $file ("$dir1/${prev_num}.test",
        "$dir1/${prev_num}_fwknopd.test",
        "$dir2/${curr_num}.test",
        "$dir2/${curr_num}_fwknopd.test",
    ) {
        system qq{perl -p -i -e 's|$valgrind_search_re||' $file} if -e $file;
        system qq{perl -p -i -e 's|$cmd_search_re|CMD:|' $file} if -e $file;
    }

    if (-e "$dir1/${prev_num}.test"
            and -e "$dir2/${curr_num}.test") {
        system "diff -u $dir1/${prev_num}.test " .
            "$dir2/${curr_num}.test";
    }

    if (-e "$dir1/${prev_num}_fwknopd.test"
            and -e "$dir2/${curr_num}_fwknopd.test") {
        system "diff -u $dir1/${prev_num}_fwknopd.test " .
            "$dir2/${curr_num}_fwknopd.test";
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

    my $curr_pwd = cwd() or die $!;

    chdir '..' or die $!;

    ### 'make clean' as root
    unless (&run_cmd('make clean', $cmd_out_tmp,
            "test/$curr_test_file")) {
        chdir $curr_pwd or die $!;
        return 0;
    }

    if ($sudo_path) {
        my $username = getpwuid((stat("test/$test_suite_path"))[4]);
        die "[*] Could not determine test/$test_suite_path owner"
            unless $username;

        unless (&run_cmd("$sudo_path -u $username make",
                $cmd_out_tmp, "test/$curr_test_file")) {
            unless (&run_cmd('make', $cmd_out_tmp,
                    "test/$curr_test_file")) {
                chdir $curr_pwd or die $!;
                return 0;
            }
        }

    } else {

        unless (&run_cmd('make', $cmd_out_tmp,
                "test/$curr_test_file")) {
            chdir $curr_pwd or die $!;
            return 0;
        }
    }

    ### look for compilation warnings - something like:
    ###     warning: ‘test’ is used uninitialized in this function
    if (&file_find_regex([qr/\swarning:\s/i, qr/gcc\:.*\sunused/],
            $MATCH_ANY, "test/$curr_test_file")) {
        chdir $curr_pwd or die $!;
        return 0;
    }

    chdir $curr_pwd or die $!;

    ### the new binaries should exist
    unless (-e $fwknopCmd and -x $fwknopCmd) {
        &write_test_file("[-] $fwknopCmd does not exist or not executable.\n",
            $curr_test_file);
    }
    unless (-e $fwknopdCmd and -x $fwknopdCmd) {
        &write_test_file("[-] $fwknopdCmd does not exist or not executable.\n",
            $curr_test_file);
    }

    return 1;
}

sub profile_coverage() {

    ### check for any *.gcno files - if they don't exist, then fwknop was
    ### not compiled with profile support
    unless (glob('../client/*.gcno') and glob('../server/*.gcno')) {
        &write_test_file("[-] ../client/*.gcno and " .
            "../server/*.gcno files do not exist.\n", $curr_test_file);
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
                $cmd_out_tmp, $curr_test_file);
    }

    return 1;
}

sub make_distcheck() {

    ### 'make clean' as root
    return 0 unless &run_cmd('make -C .. distcheck',
        $cmd_out_tmp, $curr_test_file);

    return 1 if &file_find_regex([qr/archives\sready\sfor\sdistribution/],
        $MATCH_ALL, $curr_test_file);

    return 0;
}


sub binary_exists() {
    my $test_hr = shift;
    return 0 unless $test_hr->{'binary'};

    ### account for different libfko.so paths (e.g. libfko.so.0.3 with no
    ### libfko.so link on OpenBSD, and libfko.dylib path on Mac OS X)

    if ($test_hr->{'binary'} =~ /libfko/) {
        unless (-e $test_hr->{'binary'}) {
            my $file = "$lib_dir/libfko.dylib";
            if (-e $file) {
                $test_hr->{'binary'} = $file;
                $libfko_bin = $file;
            } else {
                for my $f (glob("$lib_dir/libfko.so*")) {
                    if (-e $f and -x $f) {
                        $test_hr->{'binary'} = $f;
                        $libfko_bin = $f;
                        last;
                    }
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
            $curr_test_file);
        return 0;
    }

    open F, '< ../VERSION' or die $!;
    my $line = <F>;
    close F;
    if ($line =~ /(\d.*\d)/) {
        my $version = $1;
        return 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $curr_test_file);
        return 1 if &file_find_regex([qr/$version/],
            $MATCH_ALL, $curr_test_file);
    }
    return 0;
}

sub client_send_spa_packet() {
    my $test_hr = shift;

    my $rv = 1;

    &write_key($default_key, $local_key_file);

    $rv = 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $curr_test_file);
    $rv = 0 unless &file_find_regex([qr/final\spacked/i],
        $MATCH_ALL, $curr_test_file);

    if ($enable_openssl_compatibility_tests
            and $test_hr->{'detail'} !~ /iptables.*not\sduplicated/) {

        ### extract the SPA packet from the cmd tmp file before
        ### openssl command execution overwrites it
        my $encoded_msg = '';
        my $digest = '';
        my $enc_mode = 0;
        my $is_hmac_mode = 1;
        open F, "< $cmd_out_tmp" or die $!;
        while (<F>) {
            if (/^\s+Encoded\sData\:\s+(\S+)/) {
                $encoded_msg = $1;
            } elsif (/Data\sDigest\:\s(\S+)/) {
                $digest = $1;
            } elsif (/Encryption\sMode\:\s+(\d+)/) {
                $enc_mode = $1;
            } elsif (/^\s+HMAC.*\:\s\<NULL\>/) {
                $is_hmac_mode = 0;
            }
        }
        close F;

        $encoded_msg .= ":$digest";

        my $ssl_test_flag = $REQUIRE_SUCCESS;
        $ssl_test_flag = $REQUIRE_FAILURE if $enc_mode != 2;  ### CBC mode
        $ssl_test_flag = $REQUIRE_FAILURE if $is_hmac_mode;

        my $encrypted_msg = &get_spa_packet_from_file($cmd_out_tmp);

        my $key = '';
        if ($test_hr->{'key_file'}) {
            open F, "< $test_hr->{'key_file'}" or die $!;
            while (<F>) {
                if (/^KEY_BASE64\s+(\S+)/) {
                    $key = decode_base64($1);
                }
            }
            close F;
        }
        $key = $default_key unless $key;

        unless (&openssl_verification($encrypted_msg,
                $encoded_msg, '', $key, $ssl_test_flag)) {
            $rv = 0;
        }
    }

    return $rv;
}

sub permissions_check() {
    my $test_hr = shift;

    my $rv = 0;
    chmod 0777, $cf{'def'} or die $!;
    chmod 0777, $cf{'def_access'} or die $!;

    $rv = &spa_cycle($test_hr);

    chmod 0600, $cf{'def'} or die $!;
    chmod 0600, $cf{'def_access'} or die $!;

    if ($test_hr->{'server_positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'server_positive_output_matches'},
            $MATCH_ALL, $server_test_file);
    }
    return $rv;
}

sub rotate_digest_file() {
    my $test_hr = shift;
    my $rv = 1;

    $rv = &spa_cycle($test_hr);

    if (-e "${default_digest_file}-old") {
        ### put the file back in place
        move "${default_digest_file}-old", $default_digest_file;
        &write_test_file("[+] digest cache file was rotated.\n",
            $curr_test_file);
    } else {
        &write_test_file("[-] rotated digest cache file does not exist.\n",
            $curr_test_file);
        $rv = 0;
    }

    return $rv;
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

    if ($test_hr->{'client_positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'client_positive_output_matches'},
            $MATCH_ALL, $curr_test_file);
    }

    if ($test_hr->{'client_negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'client_negative_output_matches'},
            $MATCH_ANY, $curr_test_file);
    }

    if ($test_hr->{'server_positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'server_positive_output_matches'},
            $MATCH_ALL, $server_test_file);
    }

    if ($test_hr->{'server_negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'server_negative_output_matches'},
            $MATCH_ANY, $server_test_file);
    }

    return $rv;
}

sub spoof_username() {
    my $test_hr = shift;

    my $rv = &spa_cycle($test_hr);

    unless (&file_find_regex([qr/Username:\s*$spoof_user/],
            $MATCH_ALL, $curr_test_file)) {
        $rv = 0;
    }

    unless (&file_find_regex([qr/Username:\s*$spoof_user/],
            $MATCH_ALL, $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub gpg_pinentry_check() {
    my $test_hr = shift;

    my $rv = 1;

    my $pid;
    if ($pid = fork()) {
        local $SIG{'ALRM'} = sub {die "[*] External script timeout.\n"};
        alarm 5;  ### running the client should be fast
        eval {
            waitpid($pid, 0);
        };
        alarm 0;
        if ($@) {
            $rv = 0;
            push @tests_to_exclude, qr/GPG/;
            $pinentry_fail = 1;
        }
    } else {
        die "[*] Could not run the fwknop client: $!" unless defined $pid;
        exec qq{$test_hr->{'cmdline'} > /dev/null 2>&1 };
    }

    return $rv;
}

sub perl_fko_module_compile_install() {
    my $test_hr = shift;

    my $rv = 1;

    if (-d $perl_mod_fko_dir) {
        rmtree $perl_mod_fko_dir or die $!;
    }
    mkdir $perl_mod_fko_dir or die "[*] Could not mkdir $perl_mod_fko_dir: $!";

    my $curr_pwd = cwd() or die $!;

    chdir '../perl/FKO' or die $!;

    &run_cmd("make clean", $cmd_out_tmp, "../../test/$curr_test_file")
        if -e 'Makefile' or -e 'Makefile.old';

    &run_cmd("perl Makefile.PL PREFIX=../../test/$perl_mod_fko_dir " .
        "LIB=../../test/$perl_mod_fko_dir", $cmd_out_tmp,
        "../../test/$curr_test_file");

    &run_cmd('make', $cmd_out_tmp, "../../test/$curr_test_file");

    if (&file_find_regex([qr/rerun\sthe\smake\scommand/],
            $MATCH_ALL, "../../test/$curr_test_file")) {
        &run_cmd('touch Makefile.PL', $cmd_out_tmp, "../../test/$curr_test_file");
        &run_cmd('touch Makefile', $cmd_out_tmp, "../../test/$curr_test_file");
        &run_cmd('make', $cmd_out_tmp, "../../test/$curr_test_file");
    }

    &run_cmd('make install', $cmd_out_tmp, "../../test/$curr_test_file");

    chdir $curr_pwd or die $!;

    my $mod_paths_ar = &get_mod_paths();

    if ($#$mod_paths_ar > -1) {  ### FKO/ exists
        push @$mod_paths_ar, @INC;
        splice @INC, 0, $#$mod_paths_ar+1, @$mod_paths_ar;
    }

    eval { require FKO };
    if ($@) {
        &write_test_file("[-] could not 'require FKO' module: $@\n",
            $curr_test_file);
        $rv = 0;

        ### disable remaining perl module checks
        push @tests_to_exclude, qr/perl FKO module/;
    }

    return $rv;
}

sub perl_fko_module_new_object() {
    my $test_hr = shift;

    my $rv = 1;

    $fko_obj = FKO->new();

    if ($fko_obj) {
        $fko_obj->destroy();
    } else {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);

        ### disable remaining perl module checks
        push @tests_to_exclude, qr/perl FKO module/;

        $rv = 0;
    }

    return $rv;
}

sub perl_fko_module_new_objects_1000() {
    my $test_hr = shift;

    my $rv = 1;

    for (my $i=0; $i < 1000; $i++) {
        $fko_obj = FKO->new();

        if ($fko_obj) {
            $fko_obj->destroy();
        } else {
            &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                $curr_test_file);

            ### disable remaining perl module checks
            push @tests_to_exclude, qr/perl FKO module/;

            $rv = 0;
            last;
        }
    }

    return $rv;
}

sub perl_fko_module_version() {
    my $test_hr = shift;

    my $rv = 1;

    $fko_obj = FKO->new();

    unless ($fko_obj) {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);
        return 0;
    }

    my $version = $fko_obj->version();

    if ($version) {
        &write_test_file("[+] got version(): $version\n",
            $curr_test_file);
    } else {
        &write_test_file("[-] could not get version()\n",
            $curr_test_file);
        $rv = 0;
    }

    $fko_obj->destroy();

    return $rv;
}

sub perl_fko_module_rand() {
    my $test_hr = shift;

    my $rv = 1;

    $fko_obj = FKO->new();

    unless ($fko_obj) {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);
        return 0;
    }

    my $rand_value = $fko_obj->rand_value();

    if ($rand_value) {
        &write_test_file("[+] got rand_value(): $rand_value\n",
            $curr_test_file);
    } else {
        &write_test_file("[-] could not get rand_value()\n",
            $curr_test_file);
        $rv = 0;
    }

    $fko_obj->destroy();

    return $rv;
}

sub perl_fko_module_user() {
    my $test_hr = shift;

    my $rv = 1;

    $fko_obj = FKO->new();

    unless ($fko_obj) {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);
        return 0;
    }

    my $username = $fko_obj->username();

    if ($username) {
        &write_test_file("[+] got username(): $username\n",
            $curr_test_file);
    } else {
        &write_test_file("[-] could not get username()\n",
            $curr_test_file);
        $rv = 0;
    }

    my $status = 0;

    for my $user (@{&valid_usernames()}) {

        ### set the username and check it
        $status = $fko_obj->username($user);

        if ($status == FKO->FKO_SUCCESS and $fko_obj->username() eq $user) {
            &write_test_file("[+] get/set username(): $user\n",
                $curr_test_file);
        } else {
            &write_test_file("[-] could not get/set username(): $user " .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    for my $fuzzing_user (@{&fuzzing_usernames()}) {

        ### set the username to something fuzzing and make sure libfko rejects it
        $status = $fko_obj->username($fuzzing_user);

        if ($status == FKO->FKO_SUCCESS and $fko_obj->username() eq $fuzzing_user) {
            &write_test_file("[-] libfko allowed fuzzing username(): $fuzzing_user " .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
        } else {
            &write_test_file("[+] libfko threw out fuzzing username(): $fuzzing_user\n",
                $curr_test_file);
        }
    }

    $fko_obj->destroy();

    return $rv;
}

sub perl_fko_module_timestamp() {
    my $test_hr = shift;

    my $rv = 1;

    $fko_obj = FKO->new();

    unless ($fko_obj) {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);
        return 0;
    }

    my $curr_time = $fko_obj->timestamp();

    if ($curr_time) {
        &write_test_file("[+] got current timestamp(): $curr_time\n",
            $curr_test_file);
    } else {
        &write_test_file("[-] could not get timestamp()\n",
            $curr_test_file);
        $rv = 0;
    }

    for my $offset (@{&valid_time_offsets()}) {

        $fko_obj->timestamp($offset);

        my $spa_timestamp = $fko_obj->timestamp();

        if (abs($spa_timestamp - $curr_time) < (abs($offset) + 10)) {
            &write_test_file("[+] set valid timestamp() offset: $offset\n",
                $curr_test_file);
        } else {
            &write_test_file("[-] timestamp() offset: $offset not accepted.\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    $fko_obj->destroy();

    return $rv;
}

sub perl_fko_module_client_timeout() {
    my $test_hr = shift;

    my $rv = 1;

    $fko_obj = FKO->new();

    unless ($fko_obj) {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);
        return 0;
    }

   my $valid_timeout = 30;
    my $status = $fko_obj->spa_client_timeout($valid_timeout);

    if ($status == FKO->FKO_SUCCESS and $fko_obj->spa_client_timeout() == $valid_timeout) {
        &write_test_file("[+] got spa_client_timeout(): $valid_timeout\n",
            $curr_test_file);
    } else {
        &write_test_file("[-] could not get spa_client_timeout()\n",
            $curr_test_file);
        $rv = 0;
    }

    for my $fuzzing_client_timeout (@{&fuzzing_client_timeouts()}) {

        ### set message timeout and then see if it matches
        my $status = $fko_obj->spa_client_timeout($fuzzing_client_timeout);

        if ($status == FKO->FKO_SUCCESS) {
            &write_test_file("[-] libfko allowed fuzzing spa_client_timeout(): $fuzzing_client_timeout " .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
        } else {
            &write_test_file("[+] libfko rejected fuzzing spa_client_timeout(): $fuzzing_client_timeout\n",
                $curr_test_file);
        }
    }

    $fko_obj->destroy();

    return $rv;
}

sub perl_fko_module_msg_types() {
    my $test_hr = shift;

    my $rv = 1;

    $fko_obj = FKO->new();

    unless ($fko_obj) {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);
        return 0;
    }

    my $msg_type = -1;

    ### default
    $msg_type = $fko_obj->spa_message_type();

    if ($msg_type > -1) {
        &write_test_file("[+] got default spa_message_type(): $msg_type\n",
            $curr_test_file);
    } else {
        &write_test_file("[-] could not get default spa_message_type()\n",
            $curr_test_file);
        $rv = 0;
    }

    for my $type (@{&valid_spa_message_types()}) {

        ### set message type and then see if it matches
        my $status = $fko_obj->spa_message_type($type);

        if ($status == FKO->FKO_SUCCESS and $fko_obj->spa_message_type() == $type) {
            &write_test_file("[+] get/set spa_message_type(): $type\n",
                $curr_test_file);
        } else {
            &write_test_file("[-] could not get/set spa_message_type(): $type " .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
            last;
        }
    }

    for my $fuzzing_type (@{&fuzzing_spa_message_types()}) {

        ### set message type and then see if it matches
        my $status = $fko_obj->spa_message_type($fuzzing_type);

        if ($status == FKO->FKO_SUCCESS) {
            &write_test_file("[-] libfko allowed fuzzing spa_message_type(): $fuzzing_type " .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
        } else {
            &write_test_file("[+] libfko rejected fuzzing spa_message_type(): $fuzzing_type\n",
                $curr_test_file);
        }
    }

    $fko_obj->destroy();

    return $rv;
}

sub perl_fko_module_access_msgs() {
    my $test_hr = shift;

    my $rv = 1;

    $fko_obj = FKO->new();

    unless ($fko_obj) {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);
        return 0;
    }

    for my $msg (@{valid_access_messages()}) {

        ### set message and then see if it matches
        my $status = $fko_obj->spa_message($msg);

        if ($status == FKO->FKO_SUCCESS and $fko_obj->spa_message() eq $msg) {
            &write_test_file("[+] get/set spa_message(): $msg\n",
                $curr_test_file);
        } else {
            &write_test_file("[-] could not get/set spa_message(): $msg " .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
            last;
        }
    }

    for my $fuzzing_msg (@{&fuzzing_access_messages()}) {

        ### set message type and then see if it matches
        my $status = $fko_obj->spa_message($fuzzing_msg);

        if ($status == FKO->FKO_SUCCESS) {
            &write_test_file("[-] libfko allowed fuzzing " .
                "spa_message(): $fuzzing_msg, got: " . $fko_obj->spa_message() . ' ' .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
        } else {
            &write_test_file("[+] libfko rejected fuzzing spa_message(): $fuzzing_msg\n",
                $curr_test_file);
        }
    }

    $fko_obj->destroy();

    return $rv;
}

sub perl_fko_module_nat_access_msgs() {
    my $test_hr = shift;

    my $rv = 1;

    $fko_obj = FKO->new();

    unless ($fko_obj) {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);
        return 0;
    }

    $fko_obj->spa_message_type(FKO->FKO_NAT_ACCESS_MSG);

    for my $msg (@{valid_nat_access_messages()}) {

        ### set message and then see if it matches
        my $status = $fko_obj->spa_nat_access($msg);

        if ($status == FKO->FKO_SUCCESS and $fko_obj->spa_nat_access() eq $msg) {
            &write_test_file("[+] get/set spa_nat_access(): $msg\n",
                $curr_test_file);
        } else {
            &write_test_file("[-] could not get/set spa_nat_access(): $msg " .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
            last;
        }
    }

    for my $fuzzing_msg (@{&fuzzing_nat_access_messages()}, @{&valid_access_messages()}) {

        ### set message type and then see if it matches
        my $status = $fko_obj->spa_nat_access($fuzzing_msg);

        if ($status == FKO->FKO_SUCCESS) {
            &write_test_file("[-] libfko allowed fuzzing " .
                "spa_nat_access(): $fuzzing_msg, got: " . $fko_obj->spa_nat_access() . ' ' .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
        } else {
            &write_test_file("[+] libfko rejected fuzzing spa_nat_access(): $fuzzing_msg\n",
                $curr_test_file);
        }
    }

    $fko_obj->destroy();

    return $rv;
}

sub perl_fko_module_cmd_msgs() {
    my $test_hr = shift;

    my $rv = 1;

    $fko_obj = FKO->new();

    unless ($fko_obj) {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);
        return 0;
    }

    $fko_obj->spa_message_type(FKO->FKO_COMMAND_MSG);

    for my $msg (@{valid_cmd_messages()}) {

        ### set message and then see if it matches
        my $status = $fko_obj->spa_message($msg);

        if ($status == FKO->FKO_SUCCESS and $fko_obj->spa_message() eq $msg) {
            &write_test_file("[+] get/set spa_message(): $msg\n",
                $curr_test_file);
        } else {
            &write_test_file("[-] could not get/set spa_message(): $msg " .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
            last;
        }
    }

    for my $fuzzing_msg (@{&fuzzing_cmd_messages()}) {

        ### set message type and then see if it matches
        my $status = $fko_obj->spa_message($fuzzing_msg);

        if ($status == FKO->FKO_SUCCESS) {
            &write_test_file("[-] libfko allowed fuzzing " .
                "spa_message(): $fuzzing_msg, got: " . $fko_obj->spa_message() . ' ' .
                FKO::error_str() . "\n",
                $curr_test_file);
            $rv = 0;
        } else {
            &write_test_file("[+] libfko rejected fuzzing spa_message(): $fuzzing_msg\n",
                $curr_test_file);
        }
    }

    $fko_obj->destroy();

    return $rv;
}

sub valid_time_offsets() {
    my @offsets = (
        9999999,
        10,
        -10,
        -999999,
    );
    return \@offsets;
}

sub fuzzing_client_timeouts() {
    my @timeouts = (
        -1,
        -10,
        -10000,
    );
    return \@timeouts;
}

sub valid_usernames() {
    my @users = (
        'test',
        'root',
        'mbr',
        'test-test',
        'test_test',
        'someuser',
        'someUser',
        'USER',
        'USER001',
        '00001'
    );
    return \@users;
}

sub fuzzing_usernames() {
    my @users = (
        'A'x1000,
        "-1",
        -1,
#        pack('a', ""),
        '123%123',
        '123$123',
        '-user',
        '_user',
        '-User',
        ',User',
        'part1 part2',
        'a:b'
    );
    return \@users;
}

sub valid_encryption_keys() {
    my @keys = (
        'testtest',
        '12341234',
        '1',
        '1234',
        'a',
        '$',
        '!@#$%',
        'asdfasdfsafsdaf',
    );
    return \@keys;
}

sub valid_spa_digest_types() {
    my @types = (
        FKO->FKO_DIGEST_MD5,
        FKO->FKO_DIGEST_SHA1,
        FKO->FKO_DIGEST_SHA256,
        FKO->FKO_DIGEST_SHA384,
        FKO->FKO_DIGEST_SHA512
    );
    return \@types;
}

sub fuzzing_spa_digest_types() {
    my @types = (
        -1,
        -2,
        255,
    );
    return \@types;
}

sub valid_spa_message_types() {
    my @types = (
        FKO->FKO_ACCESS_MSG,
        FKO->FKO_COMMAND_MSG,
        FKO->FKO_LOCAL_NAT_ACCESS_MSG,
        FKO->FKO_NAT_ACCESS_MSG,
        FKO->FKO_CLIENT_TIMEOUT_ACCESS_MSG,
        FKO->FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG,
        FKO->FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG,
    );
    return \@types;
}

sub fuzzing_spa_message_types() {
    my @types = (
        -1,
        -2,
        255,
    );
    return \@types;
}

sub valid_access_messages() {
    my @msgs = (
        '1.2.3.4,tcp/22',
        '123.123.123.123,tcp/12345',
        '1.2.3.4,udp/53',
        '123.123.123.123,udp/12345',
        '123.123.123.123,udp/12345,tcp/12345',
        '1.1.1.1,udp/1,tcp/1,tcp/2,udp/3,tcp/4,tcp/12345',
#        '123.123.123.123,icmp/1'
    );
    return \@msgs;
}

sub valid_nat_access_messages() {
    my @msgs = (
        '1.2.3.4,22',
        '123.123.123.123,12345',
    );
    return \@msgs;
}

sub valid_cmd_messages() {
    my @msgs = (
        '1.2.3.4,cat /etc/hosts',
        '123.123.123.123,cat /etc/hosts',
        '123.123.123.123,echo blah > /some/file',
        '1.1.1.1,echo blah > /some/file',
        '1.1.1.1,' . 'A'x10,
        '1.1.1.1,' . 'A'x10 . ':',
    );
    return \@msgs;
}

sub fuzzing_access_messages() {
    my @msgs = ();

    push @msgs, @{&fuzzing_nat_access_messages()};
    push @msgs, '1.1.1.2,12345',
    push @msgs, @{&valid_nat_access_messages()};
    return \@msgs;
}

sub fuzzing_nat_access_messages() {
    my @msgs = (
        '1.2.3.4',
        '1.2.3.4.',
        '123.123.123.123',
        '923.123.123.123',
        '123.123.123.123.',
        '999.999.999.999',
        '1.2.3.4,tcp/2a2',
        '1.2.3.4,tcp/22,',
        '1.2.3.4,tcp/123456',
        '1.2.3.4,tcp/123456' . '9'x100,
        '1.2.3.4,tcp//22',
        '1.2.3.4,tcp/22/',
        'a23.123.123.123,tcp/12345',
        '999.999.999.999,tcp/22',
        '999.1.1.1,tcp/22',
        -1,
        1,
        'A',
        0x0,
        'A'x1000,
        '/'x1000,
        '%'x1000,
        ':'x1000,
        pack('a', ""),
        '1.1.1.p/12345',
        '1.1.1.2,,,,12345',
        '1.1.1.2,icmp/123',
        ',,,',
        '----',
        '1.3.4.5.5',
        '1.3.4.5,' . '/'x100,
        '1.3.4.5,' . '/'x100 . '22',
        '1.2.3.4,rcp/22',
        '1.2.3.4,udp/-1',
        '1.2.3.4,tcp/-1',
        '1.2.3.4,icmp/-1',
        '1.2.3' . pack('a', "") . '.4,tcp/22',
        '1.2.3.' . pack('a', "") . '4,tcp/22',
        '1.2.3.4' . pack('a', "") . ',tcp/22',
        '1.2.3.4,' . pack('a', "") . 'tcp/22',
        '1.2.3.4,t' . pack('a', "") . 'cp/22',
        '1.2.3.4,tc' . pack('a', "") . 'p/22',
        '1.2.3.4,tcp' . pack('a', "") . '/22',
        '1.2.3.4,tcp/' . pack('a', "") . '22',
        '123.123.123' . pack('a', "") . '.123,tcp/22',
        '123.123.123.' . pack('a', "") . '123,tcp/22',
        '123.123.123.1' . pack('a', "") . '23,tcp/22',
        '123.123.123.12' . pack('a', "") . '3,tcp/22',
        '123.123.123.123' . pack('a', "") . ',tcp/22',
        '123.123.123.123,' . pack('a', "") . 'tcp/22',
        '123.123.123.123,t' . pack('a', "") . 'cp/22',
        '123.123.123.123,tc' . pack('a', "") . 'p/22',
        '123.123.123.123,tcp' . pack('a', "") . '/22',
        '123.123.123.123,tcp/' . pack('a', "") . '22',
        '1.2.3.4,t' . pack('a', "") . 'cp/22',
        '1.1.1.1,udp/1,tap/1,tcp/2,udp/3,tcp/4,tcp/12345',
        '1.1.1.1,udp/1,tcp/-11,tcp/2,udp/3,tcp/4,tcp/12345',
        '1.1.1.1,udp/1,tcp/1,tcp/2udp/3,tcp/4,tcp/12345',
        '1.1.1.1,udp/1,tcp/1,tcp/2,udp/3,tcp/4,tcp////12345',
        '1.1.1.1,udp/1,tcp/1,tcp/2udp/3,tcp/4,tcp////12345',
        '1.1.1.1,udp/1,tcp/1,tcp/2udp/3,tcp/4,tcp////12345',
        '1.1.1.1,udp/1,tcp/1,tcp/2udp/3*tcp/4,tcp////12345',
        '1.1.1.1,udp/1,tcp/1,tcp/2udp/3,tcb/4,tcp////12345',
        '1.1.1.1,udp/1,tcp/1tcp/2udp/3,tcp/4,tcp////12345',
        '123.123.123.123udp/1,tcp/1,tcp/2udp/3,tcp/4,tcp////12345////////////',
    );
    return \@msgs;
}

sub fuzzing_cmd_messages() {
    my @msgs = (
        ### must start with a valid IP, so test this
        -1,
        1,
        'A',
        0x0,
        'A'x1000,
        '/'x1000,
        '%'x1000,
        ':'x1000,
        pack('a', ""),
        ',,,',
        '----',
        '1.3.4.5.5',
        '999.3.4.5',
        '1.,',
        '1.2.,',
        '1.2.3.,',
        '1.2.3.4',
        '123.123.123.123',
        '1.2.3.4,',
        '1.2.3.4.',
        '123.123.123.123,' . 'A'x1000,
    );
    return \@msgs;
}

sub perl_fko_module_rijndael_truncated_keys() {
    my $test_hr = shift;

    my $rv = 1;

    for my $msg (@{valid_access_messages()}[0]) {
        for my $user (@{valid_usernames()}[0]) {
            for my $digest_type (@{valid_spa_digest_types()}[0]) {

                my $key = '1';
                for (my $i=20; $i <= 32; $i++) {

                    $key .= $i % 10;

                    &write_test_file("\n\n[+] ------ KEY: $key (" . length($key) . " bytes)\n",
                        $curr_test_file);
                    for (my $j=1; $j < length($key); $j++) {

                        &write_test_file("\n    MSG: $msg, user: $user, " .
                            "digest type: $digest_type (orig key: $key)\n",
                            $curr_test_file);

                        $fko_obj = FKO->new();
                        unless ($fko_obj) {
                            &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                                $curr_test_file);
                            return 0;
                        }

                        $fko_obj->spa_message($msg);
                        $fko_obj->username($user);
                        $fko_obj->spa_message_type(FKO->FKO_ACCESS_MSG);
                        $fko_obj->digest_type($digest_type);
                        $fko_obj->spa_data_final($key, length($key), '', 0);

                        my $encrypted_msg = $fko_obj->spa_data();

                        $fko_obj->destroy();

                        if ($enable_openssl_compatibility_tests) {
                            unless (&openssl_verification($encrypted_msg,
                                    '', $msg, $key, $REQUIRE_SUCCESS)) {
                                $rv = 0;
                            }
                        }

                        ### now get new object for decryption
                        $fko_obj = FKO->new();
                        unless ($fko_obj) {
                            &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                                $curr_test_file);
                            return 0;
                        }
                        $fko_obj->spa_data($encrypted_msg);
                        my $truncated_key = $key;
                        $truncated_key =~ s/^(.{$j}).*/$1/;
                        &write_test_file("    Trying truncated key: $truncated_key\n",
                            $curr_test_file);
                        if ($fko_obj->decrypt_spa_data($truncated_key,
                                length($truncated_key)) == FKO->FKO_SUCCESS) {
                            &write_test_file("[-] $msg decrypt success with truncated key " .
                                "($key -> $truncated_key)\n",
                                $curr_test_file);
                            $rv = 0;
                        } else {
                            &write_test_file("[+] $msg decrypt rejected truncated " .
                                "key ($key -> $truncated_key)\n",
                                $curr_test_file);
                        }

                        $fko_obj->destroy();

                        if ($enable_openssl_compatibility_tests) {
                            unless (&openssl_verification($encrypted_msg,
                                    '', $msg, $truncated_key, $REQUIRE_FAILURE)) {
                                $rv = 0;
                            }
                        }
                    }
                    &write_test_file("\n", $curr_test_file);
                }
            }
        }
    }

    return $rv;
}

sub perl_fko_module_complete_cycle() {
    my $test_hr = shift;

    my $rv = 1;

    for my $msg (@{valid_access_messages()}) {
        for my $user (@{valid_usernames()}) {
            for my $digest_type (@{valid_spa_digest_types()}) {
                for my $key (@{valid_encryption_keys()}) {

                    &write_test_file("[+] msg: $msg, user: $user, " .
                        "digest type: $digest_type, key: $key\n",
                        $curr_test_file);

                    $fko_obj = FKO->new();
                    unless ($fko_obj) {
                        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                            $curr_test_file);
                        return 0;
                    }

                    $fko_obj->spa_message($msg);
                    $fko_obj->username($user);
                    $fko_obj->spa_message_type(FKO->FKO_ACCESS_MSG);
                    $fko_obj->digest_type($digest_type);
                    $fko_obj->encryption_mode(FKO->FKO_ENC_MODE_CBC_LEGACY_IV)
                        if $test_hr->{'set_legacy_iv'} eq $YES;
                    $fko_obj->spa_data_final($key, length($key), '', 0);

                    my $encrypted_msg = $fko_obj->spa_data();

                    $fko_obj->destroy();

                    ### now get new object for decryption
                    $fko_obj = FKO->new();
                    unless ($fko_obj) {
                        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                            $curr_test_file);
                        return 0;
                    }
                    $fko_obj->spa_data($encrypted_msg);
                    $fko_obj->encryption_mode(FKO->FKO_ENC_MODE_CBC_LEGACY_IV)
                        if $test_hr->{'set_legacy_iv'} eq $YES;
                    $fko_obj->decrypt_spa_data($key, length($key));

                    if ($msg ne $fko_obj->spa_message()) {
                        &write_test_file("[-] $msg encrypt/decrypt mismatch\n",
                            $curr_test_file);
                        $rv = 0;
                    }

                    $fko_obj->destroy();

                    if ($enable_openssl_compatibility_tests) {
                        my $flag = $REQUIRE_SUCCESS;
                        $flag = $REQUIRE_FAILURE if $test_hr->{'set_legacy_iv'} eq $YES;
                        unless (&openssl_verification($encrypted_msg,
                                '', $msg, $key, $flag)) {
                            $rv = 0;
                        }
                    }
                }
            }
        }
    }

    return $rv;
}

sub perl_fko_module_complete_cycle_module_reuse() {
    my $test_hr = shift;

    my $rv = 1;

    for my $msg (@{valid_access_messages()}) {
        for my $user (@{valid_usernames()}) {
            for my $digest_type (@{valid_spa_digest_types()}) {
                for my $key (@{valid_encryption_keys()}) {

                    &write_test_file("[+] msg: $msg, user: $user, " .
                        "digest type: $digest_type, key: $key\n",
                        $curr_test_file);

                    $fko_obj = FKO->new();
                    unless ($fko_obj) {
                        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                            $curr_test_file);
                        return 0;
                    }

                    $fko_obj->spa_message($msg);
                    $fko_obj->username($user);
                    $fko_obj->spa_message_type(FKO->FKO_ACCESS_MSG);
                    $fko_obj->digest_type($digest_type);
                    $fko_obj->encryption_mode(FKO->FKO_ENC_MODE_CBC_LEGACY_IV)
                        if $test_hr->{'set_legacy_iv'} eq $YES;
                    $fko_obj->spa_data_final($key, length($key), '', 0);

                    my $encrypted_msg = $fko_obj->spa_data();

                    $fko_obj->spa_data($encrypted_msg);
                    $fko_obj->decrypt_spa_data($key, length($key));

                    if ($msg ne $fko_obj->spa_message()) {
                        &write_test_file("[-] $msg encrypt/decrypt mismatch\n",
                            $curr_test_file);
                        $rv = 0;
                    }

                    $fko_obj->destroy();

                    if ($enable_openssl_compatibility_tests) {
                        my $flag = $REQUIRE_SUCCESS;
                        $flag = $REQUIRE_FAILURE if $test_hr->{'set_legacy_iv'} eq $YES;
                        unless (&openssl_verification($encrypted_msg,
                                '', $msg, $key, $flag)) {
                            $rv = 0;
                        }
                    }
                }
            }
        }
    }

    return $rv;
}

sub perl_fko_module_assume_patches_generate_fuzzing_spa_packets() {
    my $test_hr = shift;

    my $rv = 1;

    my @fuzzing_pkts = ();

    USER: for my $user (@{&fuzzing_usernames()}) {

        $fko_obj = FKO->new();
        unless ($fko_obj) {
            die "[*] error FKO->new(): " . FKO::error_str();
        }
        $fko_obj->spa_message('1.2.3.4,tcp/22');
        my $status = $fko_obj->username($user);
        if ($status != FKO->FKO_SUCCESS) {
            ### we expect that a patch has been applied to libfko to allow
            ### fuzzing data
            &write_test_file("[-] Bogus user: $user triggered a libfko error\n",
                $curr_test_file);
            $fko_obj->destroy();
            $rv = 0;
            next USER;
        }
        $fko_obj->spa_message_type(FKO->FKO_ACCESS_MSG);
        $fko_obj->digest_type(FKO->FKO_DIGEST_SHA256);
        $fko_obj->spa_data_final($fuzzing_key, length($fuzzing_key), '', 0);

        my $fuzzing_str = '[+] Bogus user: '
            . $fuzzing_test_tag
            . "$user, SPA packet: "
            . ($fko_obj->spa_data() || '(NULL)');
        $fuzzing_str =~ s/[^\x20-\x7e]{1,}/(NA)/g;

        push @fuzzing_pkts, $fuzzing_str;
        &write_test_file("$fuzzing_str\n", $curr_test_file);

        $fko_obj->destroy();
    }

    MSG: for my $msg (@{&fuzzing_access_messages()}) {

        $fko_obj = FKO->new();
        unless ($fko_obj) {
            die "[*] error FKO->new(): " . FKO::error_str();
        }
        my $status = $fko_obj->spa_message($msg);
        if ($status != FKO->FKO_SUCCESS) {
            ### we expect that a patch has been applied to libfko to allow
            ### fuzzing data
            &write_test_file("[-] Bogus access_msg: $msg triggered a libfko error\n",
                $curr_test_file);
            $fko_obj->destroy();
            $rv = 0;
            next MSG;
        }
        $fko_obj->spa_message_type(FKO->FKO_ACCESS_MSG);
        $fko_obj->digest_type(FKO->FKO_DIGEST_SHA256);
        $fko_obj->spa_data_final($fuzzing_key, length($fuzzing_key), '', 0);

        my $fuzzing_str = '[+] Bogus access_msg: '
            . $fuzzing_test_tag
            . "$msg, SPA packet: "
            . ($fko_obj->spa_data() || '(NULL)');
        $fuzzing_str =~ s/[^\x20-\x7e]{1,}/(NA)/g;

        push @fuzzing_pkts, $fuzzing_str;
        &write_test_file("$fuzzing_str\n", $curr_test_file);

        $fko_obj->destroy();
    }

    NAT_MSG: for my $nat_msg (@{&fuzzing_nat_access_messages()}) {

        $fko_obj = FKO->new();
        unless ($fko_obj) {
            die "[*] error FKO->new(): " . FKO::error_str();
        }
        $fko_obj->spa_message('1.2.3.4,tcp/22');
        my $status = $fko_obj->spa_nat_access($nat_msg);
        if ($status != FKO->FKO_SUCCESS) {
            ### we expect that a patch has been applied to libfko to allow
            ### fuzzing data
            &write_test_file("[-] Bogus NAT_access_msg: $nat_msg triggered a libfko error\n",
                $curr_test_file);
            $fko_obj->destroy();
            $rv = 0;
            next NAT_MSG;
        }
        $fko_obj->spa_message_type(FKO->FKO_NAT_ACCESS_MSG);
        $fko_obj->digest_type(FKO->FKO_DIGEST_SHA256);
        $fko_obj->spa_data_final($fuzzing_key, length($fuzzing_key), '', 0);

        my $fuzzing_str = '[+] Bogus NAT_access_msg: '
            . $fuzzing_test_tag
            . "$nat_msg, SPA packet: "
            . ($fko_obj->spa_data() || '(NULL)');
        $fuzzing_str =~ s/[^\x20-\x7e]{1,}/(NA)/g;

        push @fuzzing_pkts, $fuzzing_str;
        &write_test_file("$fuzzing_str\n", $curr_test_file);

        $fko_obj->destroy();
    }

    CMD: for my $msg (@{&fuzzing_cmd_messages()}) {

        $fko_obj = FKO->new();
        unless ($fko_obj) {
            die "[*] error FKO->new(): " . FKO::error_str();
        }
        my $status = $fko_obj->spa_message($msg);
        if ($status != FKO->FKO_SUCCESS) {
            ### we expect that a patch has been applied to libfko to allow
            ### fuzzing data
            &write_test_file("[-] Bogus cmd_msg: $msg triggered a libfko error\n",
                $curr_test_file);
            $fko_obj->destroy();
            $rv = 0;
            next CMD;
        }
        $fko_obj->spa_message_type(FKO->FKO_COMMAND_MSG);
        $fko_obj->digest_type(FKO->FKO_DIGEST_SHA256);
        $fko_obj->spa_data_final($fuzzing_key, length($fuzzing_key), '', 0);

        my $fuzzing_str = '[+] Bogus cmd_msg: '
            . $fuzzing_test_tag
            . "$msg, SPA packet: "
            . ($fko_obj->spa_data() || '(NULL)');
        $fuzzing_str =~ s/[^\x20-\x7e]{1,}/(NA)/g;

        push @fuzzing_pkts, $fuzzing_str;
        &write_test_file("$fuzzing_str\n", $curr_test_file);

        $fko_obj->destroy();
    }

    TYPE: for my $type (@{&fuzzing_spa_message_types()}) {

        $fko_obj = FKO->new();
        unless ($fko_obj) {
            die "[*] error FKO->new(): " . FKO::error_str();
        }
        $fko_obj->spa_message('1.2.3.4,tcp/22');
        my $status = $fko_obj->spa_message_type($type);
        if ($status != FKO->FKO_SUCCESS) {
            ### we expect that a patch has been applied to libfko to allow
            ### fuzzing data
            &write_test_file("[-] Bogus msg_type: $type triggered a libfko error\n",
                $curr_test_file);
            $fko_obj->destroy();
            $rv = 0;
            next TYPE;
        }
        $fko_obj->digest_type(FKO->FKO_DIGEST_SHA256);
        $fko_obj->spa_data_final($fuzzing_key, length($fuzzing_key), '', 0);

        my $fuzzing_str = '[+] Bogus msg_type: '
            . $fuzzing_test_tag
            . "$type, SPA packet: "
            . ($fko_obj->spa_data() || '(NULL)');
        $fuzzing_str =~ s/[^\x20-\x7e]{1,}/(NA)/g;

        push @fuzzing_pkts, $fuzzing_str;
        &write_test_file("$fuzzing_str\n", $curr_test_file);

        $fko_obj->destroy();
    }

    if ($fuzzing_pkts_append) {
        open F, ">> $fuzzing_pkts_file.tmp" or die $!;
    } else {
        open F, "> $fuzzing_pkts_file.tmp" or die $!;
    }
    for my $pkt (@fuzzing_pkts) {
        print F $pkt, "\n";
    }
    close F;

    $fuzzing_num_pkts = $#fuzzing_pkts+1;

    return $rv;
}

sub perl_fko_module_assume_patches_generate_fuzzing_encoding_spa_packets() {
    my $test_hr = shift;

    ### this function assumes the lib/fko_encode.c has been patched to mess
    ### with final encoded SPA packet data just before encryption

    my $rv = 1;

    my @fuzzing_pkts = ();

    USER: for my $user (@{&valid_usernames()}) {

        $fko_obj = FKO->new();
        unless ($fko_obj) {
            die "[*] error FKO->new(): " . FKO::error_str();
        }
        $fko_obj->spa_message('1.2.3.4,tcp/22');
        my $status = $fko_obj->username($user);
        if ($status != FKO->FKO_SUCCESS) {
            &write_test_file("[-] Invalid_encoding user: $user triggered a libfko error\n",
                $curr_test_file);
            $fko_obj->destroy();
            $rv = 0;
            next USER;
        }
        $fko_obj->spa_message_type(FKO->FKO_ACCESS_MSG);
        $fko_obj->digest_type(FKO->FKO_DIGEST_SHA256);
        $fko_obj->spa_data_final($fuzzing_key, length($fuzzing_key), '', 0);

        my $fuzzing_str = '[+] Invalid_encoding user: '
            . $fuzzing_test_tag
            . "$user, SPA packet: "
            . ($fko_obj->spa_data() || '(NULL)');
        $fuzzing_str =~ s/[^\x20-\x7e]{1,}/(NA)/g;

        push @fuzzing_pkts, $fuzzing_str;
        &write_test_file("$fuzzing_str\n", $curr_test_file);

        $fko_obj->destroy();
    }

    MSG: for my $msg (@{&valid_access_messages()}) {

        $fko_obj = FKO->new();
        unless ($fko_obj) {
            die "[*] error FKO->new(): " . FKO::error_str();
        }
        my $status = $fko_obj->spa_message($msg);
        if ($status != FKO->FKO_SUCCESS) {
            ### we expect that a patch has been applied to libfko to allow
            ### fuzzing data
            &write_test_file("[-] Invalid_encoding access_msg: $msg triggered a libfko error\n",
                $curr_test_file);
            $fko_obj->destroy();
            $rv = 0;
            next MSG;
        }
        $fko_obj->spa_message_type(FKO->FKO_ACCESS_MSG);
        $fko_obj->digest_type(FKO->FKO_DIGEST_SHA256);
        $fko_obj->spa_data_final($fuzzing_key, length($fuzzing_key), '', 0);

        my $fuzzing_str = '[+] Invalid_encoding access_msg: '
            . $fuzzing_test_tag
            . "$msg, SPA packet: "
            . ($fko_obj->spa_data() || '(NULL)');
        $fuzzing_str =~ s/[^\x20-\x7e]{1,}/(NA)/g;

        push @fuzzing_pkts, $fuzzing_str;
        &write_test_file("$fuzzing_str\n", $curr_test_file);

        $fko_obj->destroy();
    }

    NAT_MSG: for my $nat_msg (@{&valid_nat_access_messages()}) {

        $fko_obj = FKO->new();
        unless ($fko_obj) {
            die "[*] error FKO->new(): " . FKO::error_str();
        }
        $fko_obj->spa_message('1.2.3.4,tcp/22');
        my $status = $fko_obj->spa_nat_access($nat_msg);
        if ($status != FKO->FKO_SUCCESS) {
            ### we expect that a patch has been applied to libfko to allow
            ### fuzzing data
            &write_test_file("[-] Invalid_encoding NAT_access_msg: $nat_msg triggered a libfko error\n",
                $curr_test_file);
            $fko_obj->destroy();
            $rv = 0;
            next NAT_MSG;
        }
        $fko_obj->spa_message_type(FKO->FKO_NAT_ACCESS_MSG);
        $fko_obj->digest_type(FKO->FKO_DIGEST_SHA256);
        $fko_obj->spa_data_final($fuzzing_key, length($fuzzing_key), '', 0);

        my $fuzzing_str = '[+] Invalid_encoding NAT_access_msg: '
            . $fuzzing_test_tag
            . "$nat_msg, SPA packet: "
            . ($fko_obj->spa_data() || '(NULL)');
        $fuzzing_str =~ s/[^\x20-\x7e]{1,}/(NA)/g;

        push @fuzzing_pkts, $fuzzing_str;
        &write_test_file("$fuzzing_str\n", $curr_test_file);

        $fko_obj->destroy();
    }

    CMD: for my $msg (@{&valid_cmd_messages()}) {

        $fko_obj = FKO->new();
        unless ($fko_obj) {
            die "[*] error FKO->new(): " . FKO::error_str();
        }
        $fko_obj->spa_message_type(FKO->FKO_COMMAND_MSG);
        my $status = $fko_obj->spa_message($msg);
        if ($status != FKO->FKO_SUCCESS) {
            ### we expect that a patch has been applied to libfko to allow
            ### fuzzing data
            &write_test_file("[-] Invalid_encoding cmd_msg: $msg triggered a libfko error\n",
                $curr_test_file);
            $fko_obj->destroy();
            $rv = 0;
            next CMD;
        }
        $fko_obj->digest_type(FKO->FKO_DIGEST_SHA256);
        $fko_obj->spa_data_final($fuzzing_key, length($fuzzing_key), '', 0);

        my $fuzzing_str = '[+] Invalid_encoding cmd_msg: '
            . $fuzzing_test_tag
            . "$msg, SPA packet: "
            . ($fko_obj->spa_data() || '(NULL)');
        $fuzzing_str =~ s/[^\x20-\x7e]{1,}/(NA)/g;

        push @fuzzing_pkts, $fuzzing_str;
        &write_test_file("$fuzzing_str\n", $curr_test_file);

        $fko_obj->destroy();
    }

    TYPE: for my $type (@{&valid_spa_message_types()}) {

        $fko_obj = FKO->new();
        unless ($fko_obj) {
            die "[*] error FKO->new(): " . FKO::error_str();
        }
        $fko_obj->spa_message('1.2.3.4,tcp/22');
        my $status = $fko_obj->spa_message_type($type);
        if ($status != FKO->FKO_SUCCESS) {
            ### we expect that a patch has been applied to libfko to allow
            ### fuzzing data
            &write_test_file("[-] Invalid_encoding msg_type: $type triggered a libfko error\n",
                $curr_test_file);
            $fko_obj->destroy();
            $rv = 0;
            next TYPE;
        }
        $fko_obj->digest_type(FKO->FKO_DIGEST_SHA256);
        $fko_obj->spa_data_final($fuzzing_key, length($fuzzing_key), '', 0);

        my $fuzzing_str = '[+] Invalid_encoding msg_type: '
            . $fuzzing_test_tag
            . "$type, SPA packet: "
            . ($fko_obj->spa_data() || '(NULL)');
        $fuzzing_str =~ s/[^\x20-\x7e]{1,}/(NA)/g;

        push @fuzzing_pkts, $fuzzing_str;
        &write_test_file("$fuzzing_str\n", $curr_test_file);

        $fko_obj->destroy();
    }

    if ($fuzzing_pkts_append) {
        open F, ">> $fuzzing_pkts_file.tmp" or die $!;
    } else {
        open F, "> $fuzzing_pkts_file.tmp" or die $!;
    }
    for my $pkt (@fuzzing_pkts) {
        print F $pkt, "\n";
    }
    close F;

    $fuzzing_num_pkts = $#fuzzing_pkts+1;

    return $rv;
}

sub perl_fko_module_full_fuzzing_packets() {
    my $test_hr = shift;

    my $rv = 1;

    for my $field (keys %fuzzing_spa_packets) {
        for my $field_val (keys %{$fuzzing_spa_packets{$field}}) {
            for my $encrypted_spa_pkt (@{$fuzzing_spa_packets{$field}{$field_val}}) {

                ### now get new object for decryption
                $fko_obj = FKO->new();
                unless ($fko_obj) {
                    &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                        $curr_test_file);
                    return 0;
                }
                $fko_obj->encryption_mode(FKO->FKO_ENC_MODE_CBC_LEGACY_IV)
                    if $test_hr->{'set_legacy_iv'} eq $YES;
                $fko_obj->spa_data($encrypted_spa_pkt);

                my $status = $fko_obj->decrypt_spa_data($fuzzing_key, length($fuzzing_key));

                if ($status == FKO->FKO_SUCCESS) {
                    &write_test_file("[-] Accepted fuzzing $field $field_val SPA packet.\n",
                        $curr_test_file);
                    $rv = 0;
                    $fuzzing_failure_ctr++;
                } else {
                    &write_test_file("[+] Rejected fuzzing $field $field_val SPA packet.\n",
                        $curr_test_file);
                    $fuzzing_success_ctr++;
                }
                $fuzzing_ctr++;

                $fko_obj->destroy();
            }
        }
    }

    return $rv;
}

sub perl_fko_module_client_compatibility() {
    my $test_hr = shift;

    $fko_obj = FKO->new();

    unless ($fko_obj) {
        &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
            $curr_test_file);
        return 0;
    }

    $fko_obj->spa_message("$fake_ip,tcp/22");
    $fko_obj->spa_message_type(FKO->FKO_ACCESS_MSG);
    $fko_obj->encryption_mode(FKO->FKO_ENC_MODE_CBC_LEGACY_IV)
        if $test_hr->{'set_legacy_iv'} eq $YES;
    $fko_obj->spa_data_final($default_key, length($default_key), '', 0);
    my $spa_pkt = $fko_obj->spa_data();
    $fko_obj->destroy();

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
            $MATCH_ALL, $server_test_file);
    }

    return $rv;
}

sub get_mod_paths() {

    my @paths = ();

    opendir D, $perl_mod_fko_dir
        or die "[*] Could not open $perl_mod_fko_dir: $!";
    my @dirs = readdir D;
    closedir D;

    push @paths, $perl_mod_fko_dir;

    for my $dir (@dirs) {
        ### get directories like "FKO/x86_64-linux"
        next unless -d "$perl_mod_fko_dir/$dir";
        push @paths, "$perl_mod_fko_dir/$dir"
            if $dir =~ m|linux| or $dir =~ m|thread|
                or (-d "$perl_mod_fko_dir/$dir/auto");
    }
    return \@paths;
}

sub spa_cmd_exec_cycle() {
    my $test_hr = shift;

    my $rv = &spa_cycle($test_hr);

    if (-e $cmd_exec_test_file) {
        unlink $cmd_exec_test_file;
    } else {
        $rv = 0;
    }

    return $rv;
}

sub replay_detection() {
    my $test_hr = shift;

    ### do a complete SPA cycle and then parse the SPA packet out of the
    ### current test file and re-send

    return 0 unless &spa_cycle($test_hr);

    my $spa_pkt = &get_spa_packet_from_file($curr_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $curr_test_file\n",
            $curr_test_file);
        return 0;
    }

    if ($test_hr->{'pkt_prefix'}) {
        $spa_pkt = $test_hr->{'pkt_prefix'} . $spa_pkt;
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

    if ($test_hr->{'replay_positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'replay_positive_output_matches'},
            $MATCH_ALL, $server_test_file);
    }

    if ($test_hr->{'replay_negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'replay_negative_output_matches'},
            $MATCH_ANY, $server_test_file);
    }

    return $rv;
}

sub digest_cache_structure() {
    my $test_hr = shift;
    my $rv = 1;

    &run_cmd("file $default_digest_file", $cmd_out_tmp, $curr_test_file);

    if (&file_find_regex([qr/ASCII/i], $MATCH_ALL, $cmd_out_tmp)) {

        ### the format should be:
        ### <digest> <proto> <src_ip> <src_port> <dst_ip> <dst_port> <time>
        open F, "< $default_digest_file" or
            die "[*] could not open $default_digest_file: $!";
        while (<F>) {
            next if /^#/;
            next unless /\S/;
            unless (m|^\S+\s+\d+\s+$ip_re\s+\d+\s+$ip_re\s+\d+\s+\d+|) {
                &write_test_file("[-] invalid digest.cache line: $_",
                    $curr_test_file);
                $rv = 0;
                last;
            }
        }
        close F;
    } elsif (&file_find_regex([qr/dbm/i], $MATCH_ALL, $cmd_out_tmp)) {
        &write_test_file("[+] DBM digest file format, " .
            "assuming this is valid.\n", $curr_test_file);
    } else {
        ### don't know what kind of file the digest.cache is
        &write_test_file("[-] unrecognized file type for " .
            "$default_digest_file.\n", $curr_test_file);
        $rv = 0;
    }

    if ($rv) {
        &write_test_file("[+] valid digest.cache structure.\n",
            $curr_test_file);
    }

    return $rv;
}

sub iptables_rules_not_duplicated() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    my @packets = ();

    for (my $i=0; $i < 3; $i++) {
        unless (&client_send_spa_packet($test_hr)) {
            &write_test_file("[-] fwknop client execution error.\n",
                $curr_test_file);
            $rv = 0;
        }
        my $spa_pkt = &get_spa_packet_from_file($cmd_out_tmp);

        unless ($spa_pkt) {
            &write_test_file("[-] could not get SPA packet " .
                "from file: $curr_test_file\n", $curr_test_file);
            return 0;
        }

        push @packets,
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => $spa_pkt,
        };
        $i++;
    }

    ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    ### make sure there aren't two iptables rule with the same creation time
    my $time_stamp = 0;
    open F, "< $server_test_file" or die $!;
    while (<F>) {
        ### 1    ACCEPT    tcp  --  127.0.0.2    0.0.0.0/0   tcp dpt:22 /* _exp_1359688354 */
        if (m|^\d+\s+.*$fake_ip\s+.*_exp_(\d+)|) {
            $time_stamp = $1;
            next;
        }
        if ($time_stamp) {
            if (/^2\s+.*$fake_ip\s+.*_exp_$time_stamp/) {
                $rv = 0;
                last;
            }
        }
    }
    close F;

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
            $curr_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($curr_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $curr_test_file\n", $curr_test_file);
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
            $MATCH_ALL, $server_test_file)) {
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
            $curr_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($curr_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $curr_test_file\n", $curr_test_file);
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

sub backwards_compatibility() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => $test_hr->{'pkt'},
        },
    );

    ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    $rv = 0 unless $server_was_stopped;

    if ($fw_rule_created) {
        &write_test_file("[+] new fw rule created.\n", $curr_test_file);
    } else {
        &write_test_file("[-] new fw rule not created.\n", $curr_test_file);
        $rv = 0;
    }

    if ($test_hr->{'server_positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'server_positive_output_matches'},
            $MATCH_ALL, $server_test_file);
    }

    return $rv;
}

sub process_pcap_file_directly() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, [], $USE_PCAP_FILE);

    $rv = 0 unless $server_was_stopped;

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
            $MATCH_ALL, $server_test_file);
    }

    if ($test_hr->{'server_negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'server_negative_output_matches'},
            $MATCH_ANY, $server_test_file);
    }

    return $rv;
}

sub fuzzer() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => $test_hr->{'fuzzing_pkt'},
        },
    );

    ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    $rv = 0 unless $server_was_stopped;

    if ($fw_rule_created) {
        &write_test_file("[-] new fw rule created.\n", $curr_test_file);
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule not created.\n", $curr_test_file);
    }

    if ($test_hr->{'server_positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'server_positive_output_matches'},
            $MATCH_ALL, $server_test_file);
    }

    if ($rv) {
        $fuzzing_success_ctr++;
    } else {
        $fuzzing_failure_ctr++;
    }
    $fuzzing_ctr++;

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
            $curr_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($curr_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $curr_test_file\n", $curr_test_file);
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
        &write_test_file("[-] new fw rule created.\n", $curr_test_file);
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule not created.\n", $curr_test_file);
    }

    unless (&file_find_regex([qr/Error\screating\sfko\scontext/],
            $MATCH_ALL, $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub altered_hmac_spa_data() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    unless (&client_send_spa_packet($test_hr)) {
        &write_test_file("[-] fwknop client execution error.\n",
            $curr_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($curr_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $curr_test_file\n", $curr_test_file);
        return 0;
    }

    ### alter the HMAC region of the SPA packet
    $spa_pkt =~ s|(.{5})$|AAAAA|;

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
        &write_test_file("[-] new fw rule created.\n", $curr_test_file);
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule not created.\n", $curr_test_file);
    }

    unless (&file_find_regex([qr/Error\screating\sfko\scontext/],
            $MATCH_ALL, $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub altered_pkt_hmac_spa_data() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    unless (&client_send_spa_packet($test_hr)) {
        &write_test_file("[-] fwknop client execution error.\n",
            $curr_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($curr_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $curr_test_file\n", $curr_test_file);
        return 0;
    }

    ### alter the SPA packet region before the HMAC
    $spa_pkt =~ s|^(.{5})|AAAAA|;

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
        &write_test_file("[-] new fw rule created.\n", $curr_test_file);
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule not created.\n", $curr_test_file);
    }

    unless (&file_find_regex([qr/Error\screating\sfko\scontext/],
            $MATCH_ALL, $server_test_file)) {
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
            $curr_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($curr_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $curr_test_file\n", $curr_test_file);
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
        &write_test_file("[-] new fw rule created.\n", $curr_test_file);
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule not created.\n", $curr_test_file);
    }

    unless (&file_find_regex([qr/Error\screating\sfko\scontext/],
            $MATCH_ALL, $server_test_file)) {
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
            $curr_test_file);
        $rv = 0;
    }

    my $spa_pkt = &get_spa_packet_from_file($curr_test_file);

    unless ($spa_pkt) {
        &write_test_file("[-] could not get SPA packet " .
            "from file: $curr_test_file\n", $curr_test_file);
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
        &write_test_file("[-] new fw rule created.\n", $curr_test_file);
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule not created.\n", $curr_test_file);
    }

    unless (&file_find_regex([qr/Error\screating\sfko\scontext/],
            $MATCH_ALL, $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub server_start() {
    my $test_hr = shift;

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, [], $USE_PREDEF_PKTS);

    unless (&file_find_regex([qr/Starting\sfwknopd\smain\sevent\sloop/],
            $MATCH_ALL, $server_test_file)) {
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
            $MATCH_ALL, $server_test_file)) {
        $rv = 0;
    }

    unless (&file_find_regex([qr/Shutting\sDown\sfwknopd/i],
            $MATCH_ALL, $server_test_file)) {
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
    my ($test_hr, $pkts_hr, $spa_client_flag) = @_;

    my $rv = 1;
    my $server_was_stopped = 1;
    my $fw_rule_created = 1;
    my $fw_rule_removed = 0;

    ### start fwknopd to monitor for the SPA packet over the loopback interface
    my $fwknopd_parent_pid = &start_fwknopd($test_hr);

    ### give fwknopd a chance to parse its config and start sniffing
    ### on the loopback interface
    if ($enable_valgrind) {
        sleep 3;
    } else {
        sleep 2;
    }

    ### send the SPA packet(s) to the server either manually using IO::Socket or
    ### with the fwknopd client
    if ($spa_client_flag == $USE_CLIENT) {
        unless (&client_send_spa_packet($test_hr)) {
            &write_test_file("[-] fwknop client execution error.\n",
                $curr_test_file);
            $rv = 0;
        }
    } elsif ($spa_client_flag == $USE_PREDEF_PKTS) {
        &send_packets($pkts_hr);
    } else {
        ### pcap file mode, nothing to do
    }

    ### check to see if the SPA packet resulted in a new fw access rule
    my $ctr = 0;
    while (not &is_fw_rule_active($test_hr)) {
        &write_test_file("[-] new fw rule does not exist.\n",
            $curr_test_file);
        $ctr++;
        last if $ctr == 3;
        sleep 1;
    }
    if ($ctr == 3) {
        $fw_rule_created = 0;
        $fw_rule_removed = 0;
    }

    &time_for_valgrind() if $enable_valgrind;

    if ($fw_rule_created) {
        sleep 3;  ### allow time for rule time out.
        if (&is_fw_rule_active($test_hr)) {
            &write_test_file("[-] new fw rule not timed out.\n",
                $curr_test_file);
            $rv = 0;
        } else {
            &write_test_file("[+] new fw rule timed out.\n",
                $curr_test_file);
            $fw_rule_removed = 1;
        }
    }

    if (&is_fwknopd_running()) {
        &stop_fwknopd();
        unless (&file_find_regex([qr/Got\sSIGTERM/],
                $MATCH_ALL, $server_test_file)) {
            $server_was_stopped = 0;
        }
    } else {
        &write_test_file("[-] server is not running.\n",
            $curr_test_file);
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

    open F, ">> $curr_test_file" or die $!;
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

sub rc_file_exists() {
    my $test_hr = shift;

    my $rv = 1;

    if (-e $tmp_rc_file) {
        $rv = 0 unless &file_find_regex([qr/This\sfile\scontains/],
            $MATCH_ALL, $tmp_rc_file);
    } else {
        &write_test_file("[-] $tmp_rc_file does not exist.\n",
            $curr_test_file);
        $rv = 0;
    }

    return $rv;
}

sub client_save_spa_pkt() {
    my $test_hr = shift;

    my $rv = &generic_exec($test_hr);

    unless (-e $tmp_pkt_file) {
        $rv = 0;
    }
    return $rv;
}

sub generic_exec() {
    my $test_hr = shift;

    my $rv = 1;

    my $exec_rv = &run_cmd($test_hr->{'cmdline'},
                $cmd_out_tmp, $curr_test_file);

    if ($test_hr->{'exec_err'} eq $YES) {
        $rv = 0 if $exec_rv;
    } elsif ($test_hr->{'exec_err'} eq $NO) {
        $rv = 0 unless $exec_rv;
    } ### else it must be $IGNORE so ignore the $exec_rv value

    if ($test_hr->{'positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'positive_output_matches'},
            $MATCH_ALL, $curr_test_file);
    }

    if ($test_hr->{'negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'negative_output_matches'},
            $MATCH_ANY, $curr_test_file);
    }

    return $rv;
}

sub key_gen_uniqueness() {
    my $test_hr = shift;

    my %rijndael_keys = ();
    my %hmac_keys     = ();

    ### collect key information
    my $found_dup = 0;
    for (my $i=0; $i < $uniq_keys; $i++) {
        open CMD, "$test_hr->{'cmdline'} | " or die $!;
        while (<CMD>) {
            if (/^KEY_BASE64\:\s+(\S+)/) {
                $found_dup = 1 if defined $rijndael_keys{$1};
                $rijndael_keys{$1} = '';
            } elsif (/^HMAC_KEY_BASE64\:\s+(\S+)/) {
                $found_dup = 1 if defined $hmac_keys{$1};
                $hmac_keys{$1} = '';
            }
        }
        close CMD;
        last if $found_dup;
    }

    return ! $found_dup;
}

### check for PIE
sub pie_binary() {
    my $test_hr = shift;
    return 0 unless -e $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $curr_test_file);
    return 1 if &file_find_regex([qr/Position\sIndependent.*:\syes/i],
        $MATCH_ALL, $curr_test_file);
    return 0;
}

### check for stack protection
sub stack_protected_binary() {
    my $test_hr = shift;
    return 0 unless -e $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $curr_test_file);
    return 1 if &file_find_regex([qr/Stack\sprotected.*:\syes/i],
        $MATCH_ALL, $curr_test_file);
    return 0;
}

### check for fortified source functions
sub fortify_source_functions() {
    my $test_hr = shift;
    return 0 unless -e $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $curr_test_file);
    return 1 if &file_find_regex([qr/Fortify\sSource\sfunctions:\syes/i],
        $MATCH_ALL, $curr_test_file);
    return 0;
}

### check for read-only relocations
sub read_only_relocations() {
    my $test_hr = shift;
    return 0 unless -e $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $curr_test_file);
    return 1 if &file_find_regex([qr/Read.only\srelocations:\syes/i],
        $MATCH_ALL, $curr_test_file);
    return 0;
}

### check for immediate binding
sub immediate_binding() {
    my $test_hr = shift;
    return 0 unless -e $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $curr_test_file);
    return 1 if &file_find_regex([qr/Immediate\sbinding:\syes/i],
        $MATCH_ALL, $curr_test_file);
    return 0;
}

sub openssl_verification() {
    my ($encrypted_msg, $encoded_msg, $access_msg, $key, $rv_flag) = @_;

    my $rv = 1;

    my $rv_str = 'REQUIRE_SUCCESS';
    $rv_str = 'REQUIRE_FAILURE' if $rv_flag == $REQUIRE_FAILURE;

    &write_test_file("[+] OpenSSL verification, (encoded msg: " .
        "$encoded_msg) (access: $access_msg), key: $key, " .
        "encrypted+encoded msg: $encrypted_msg, $rv_str\n",
        $curr_test_file);

    ### transform encrypted message into the format that openssl expects
    $encrypted_msg = 'U2FsdGVkX1' . $encrypted_msg
        unless $encrypted_msg =~ /^U2FsdGVkX1/;

    my $len_remainder = length($encrypted_msg) % 4;
    if ($len_remainder > 0) {
        for (my $i=0; $i < 4-$len_remainder; $i++) {
            $encrypted_msg .= '=';
        }
    }

    $encrypted_msg =~ s|(.{76})|$1\n|g;

    open F, "> $data_tmp" or die $!;
    print F $encrypted_msg, "\n";
    close F;

    open F, "> $key_tmp" or die $!;
    print F $key;
    close F;

    $rv = &run_cmd("$openssl_path enc -d -a -aes-256-cbc " .
        "-pass file:$key_tmp -in $data_tmp",
        $cmd_out_tmp, $curr_test_file);

    if ($rv) {
        if ($rv_flag == $REQUIRE_FAILURE) {
            &write_test_file("[.] OpenSSL decryption did not generate " .
                "error code exit status\n",
                $curr_test_file);
            $rv = 0;

            ### make absolutely certain that the decrypted data does not contain
            ### a valid access message
            my $decrypted_msg = '';
            my $decrypted_access_msg = '';
            open F, "< $cmd_out_tmp" or die $!;
            while (<F>) {
                if (/^(?:\S+?\:){5}(\S+?)\:/) {
                    $decrypted_access_msg = $1;
                    $decrypted_msg = $_;
                }
            }
            close F;

            if ($decrypted_msg) {
                if ($encoded_msg and $encoded_msg eq $decrypted_msg) {
                    &write_test_file("[-] OpenSSL DECRYPTED msg with truncated key!\n",
                        $curr_test_file);
                    $rv = 1;
                }
            }

            if ($decrypted_access_msg) {
                my $decoded_msg = decode_base64($decrypted_access_msg);
                if ($decoded_msg) {
                    if ($access_msg and $access_msg eq $decoded_msg) {
                        &write_test_file("[-] OpenSSL DECRYPTED msg with truncated key!\n",
                            $curr_test_file);
                        $rv = 1;
                    }
                }
            }

        } else {

            ### 2868244741993914:dGVzdA:2358972093:2.0.4:1:MS4yLjMANCx0YAAvMjI:vPFqXEA6SnzP2ScsIWAxhg

            ### make sure the access message checks out, or the entire
            ### decrypted (but not decoded) packet if we were passed the
            ### encoded version
            my $decrypted_msg = '';
            my $decrypted_access_msg = '';
            my $decoded_msg = '';
            open F, "< $cmd_out_tmp" or die $!;
            while (<F>) {
                if (/^(?:\S+?\:){5}(\S+?)\:/) {
                    $decrypted_access_msg = $1;
                    $decrypted_msg = $_;
                }
            }
            close F;

            $decrypted_msg =~ s/\n//;

            my $decryption_success = 0;

            unless ($encoded_msg) {
                my $len_remainder = length($decrypted_access_msg) % 4;
                if ($len_remainder > 0) {
                    for (my $i=0; $i < 4-$len_remainder; $i++) {
                        $decrypted_access_msg .= '=';
                    }
                }
                $decoded_msg = decode_base64($decrypted_access_msg);
            }

            if ($encoded_msg) {
                $decryption_success = 1 if $encoded_msg eq $decrypted_msg;
            } else {
                $decryption_success = 1 if $access_msg eq $decoded_msg;
            }

            if ($decryption_success) {
                &write_test_file("[+] OpenSSL access message " .
                    "match in decrypted data\n",
                    $curr_test_file);
                ### now check the exit status of re-encrypting the data
                unless (&run_cmd("$openssl_path enc " .
                        "-e -a -aes-256-cbc -pass file:$key_tmp -in " .
                        "$data_tmp -out $enc_save_tmp",
                        $cmd_out_tmp, $curr_test_file)) {

                    &write_test_file("[-] OpenSSL could not re-encrypt\n",
                        $curr_test_file);

                    $rv = 0;
                }

            } else {
                &write_test_file("[-] OpenSSL access message " .
                    "mis-match in decrypted data\n",
                    $curr_test_file);
                $rv = 0;
            }
        }
    } else {
        if ($rv_flag == $REQUIRE_SUCCESS) {
            &write_test_file("[-] OpenSSL bad decryption exit status\n",
                $curr_test_file);
        } else {
            &write_test_file("[+] OpenSSL did not decrypt bogus " .
                "key/data combination\n",
                $curr_test_file);
        }
    }

    if ($rv) {
        if ($rv_flag == $REQUIRE_SUCCESS) {
            &write_test_file("[+] OpenSSL test success (expected " .
                "encryption/decryption success)\n",
                $curr_test_file);
            $openssl_success_ctr++;
        } else {
            &write_test_file("[-] OpenSSL test failure (expected " .
                "encryption/decryption failure)\n",
                $curr_test_file);
            $openssl_failure_ctr++;
            $rv = 0;
        }
    } else {
        if ($rv_flag == $REQUIRE_SUCCESS) {
            &write_test_file("[-] OpenSSL test failure (expected " .
                "encryption/decryption success)\n",
                $curr_test_file);
            $openssl_failure_ctr++;
        } else {
            &write_test_file("[+] OpenSSL test success (expected " .
                "encryption/decryption failure)\n",
                $curr_test_file);
            $openssl_success_ctr++;
            $rv = 1;
        }
    }
    $openssl_ctr++;
    return $rv;
}

sub specs() {

     &run_cmd("LD_LIBRARY_PATH=$lib_dir $valgrind_str $fwknopdCmd " .
            "$default_server_conf_args --fw-list-all",
            $cmd_out_tmp, $curr_test_file);

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
        &run_cmd($cmd, $cmd_out_tmp, $curr_test_file);

        if ($cmd =~ /^ldd/) {
            $have_gpgme++ if &file_find_regex([qr/gpgme/],
                $MATCH_ALL, $cmd_out_tmp);
        }
    }

    ### all three of fwknop/fwknopd/libfko must link against gpgme in order
    ### to enable gpg tests
    unless ($have_gpgme == 3) {
        push @tests_to_exclude, qr/GPG/;
    }

    return 1;
}

sub time_for_valgrind() {
    my $ctr = 0;
    while (&run_cmd("ps axuww | grep LD_LIBRARY_PATH | " .
            "grep valgrind |grep -v perl | grep -v grep",
            $cmd_out_tmp, $curr_test_file)) {
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

    print "[+] Anonymizing all IP addresses and hostnames ",
        "from $output_dir files...\n";

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
    print "    Creating tar file: $tarfile\n";
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
    open C, ">> $curr_test_file"
        or die "[*] Could not open $curr_test_file: $!";
    print C "\n" . localtime() . " [+] PID dump:\n";
    close C;
    &run_cmd("ps auxww | grep knop |grep -v grep",
        $cmd_out_tmp, $curr_test_file);
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

    ### copy original file descriptors (credit: Perl Cookbook)
    open OLDOUT, ">&STDOUT";
    open OLDERR, ">&STDERR";

    ### redirect command output
    open STDOUT, "> $cmd_out" or die "[*] Could not redirect stdout: $!";
    open STDERR, ">&STDOUT"   or die "[*] Could not dup stdout: $!";

    my $rv = ((system $cmd) >> 8);

    close STDOUT or die "[*] Could not close STDOUT: $!";
    close STDERR or die "[*] Could not close STDERR: $!";

    ### restore original filehandles
    open STDERR, ">&OLDERR" or die "[*] Could not restore stderr: $!";
    open STDOUT, ">&OLDOUT" or die "[*] Could not restore stdout: $!";

    ### close the old copies
    close OLDOUT or die "[*] Could not close OLDOUT: $!";
    close OLDERR or die "[*] Could not close OLDERR: $!";

    open C, "< $cmd_out" or die "[*] Could not open $cmd_out: $!";
    my @cmd_lines = <C>;
    close C;

    open F, ">> $file" or die "[*] Could not open $file: $!";
    for (@cmd_lines) {
        if (/\n/) {
            print F $_;
        } else {
            print F $_, "\n";
        }
    }
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

    if ($enable_valgrind) {
        die "[*] $valgrindCmd exec problem, use --valgrind-path"
            unless -e $valgrindCmd and -x $valgrindCmd;
    }

    die "[*] $conf_dir directory does not exist." unless -d $conf_dir;

    unless ($enable_recompilation_warnings_check) {
        die "[*] $lib_dir directory does not exist." unless -d $lib_dir;
    }

    unlink $cmd_exec_test_file if -e $cmd_exec_test_file;
    for my $name (keys %cf) {
        die "[*] $cf{$name} does not exist" unless -e $cf{$name};
        chmod 0600, $cf{$name} or die "[*] Could not chmod 0600 $cf{$name}";
    }

    if (-d $output_dir) {
        if (-d "${output_dir}.last") {
            rmtree "${output_dir}.last"
                or die "[*] rmtree ${output_dir}.last $!";
        }
        move $output_dir, "${output_dir}.last" or die $!;
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

    if (-d $run_dir) {
        rmtree $run_dir or die $!;
    }
    mkdir $run_dir or die "[*] Could not mkdir $run_dir: $!";

    for my $dir ($output_dir, $run_dir) {
        next if -d $dir;
        mkdir $dir or die "[*] Could not mkdir $dir: $!";
    }

    for my $file (glob("$output_dir/*.test"), "$output_dir/init",
            $tmp_rc_file, $tmp_pkt_file, $tmp_args_file,
            $logfile, $key_gen_file) {
        next unless -e $file;
        unlink $file or die "[*] Could not unlink($file)";
    }

    if ($test_include) {
        for my $re (split /\s*,\s*/, $test_include) {
            push @tests_to_include, qr/$re/;
        }
    }
    if ($test_exclude) {
        for my $re (split /\s*,\s*/, $test_exclude) {
            push @tests_to_exclude, qr/$re/;
        }
    }

    ### make sure test message strings are unique across all tests
    my %uniq_test_msgs = ();
    for my $test_hr (@tests) {
        my $msg = "[$test_hr->{'category'}]";
        $msg .= " [$test_hr->{'subcategory'}]" if $test_hr->{'subcategory'};
        $msg .= " $test_hr->{'detail'}";
        if (defined $uniq_test_msgs{$msg}) {
            die "[*] Duplicate test message: $msg\n";
        } else {
            $uniq_test_msgs{$msg} = '';
        }
    }

    ### make sure no fwknopd instance is currently running
    die "[*] Please stop the running fwknopd instance."
        if &is_fwknopd_running();

    if ($enable_openssl_compatibility_tests) {
        $openssl_path = &find_command('openssl');
        die "[*] openssl command not found." unless $openssl_path;
        require MIME::Base64;
        MIME::Base64->import(qw(decode_base64));
    }

    $enable_perl_module_checks = 1
        if $enable_perl_module_fuzzing_spa_pkt_generation;

    if ($fuzzing_test_tag) {
        $fuzzing_test_tag .= '_' unless $fuzzing_test_tag =~ /_$/;
    }

    unless ($enable_recompilation_warnings_check) {
        push @tests_to_exclude, qr/recompilation/;
    }

    unless ($enable_make_distcheck) {
        push @tests_to_exclude, qr/distcheck/;
    }

    unless ($enable_client_ip_resolve_test) {
        push @tests_to_exclude, qr/IP resolve/;
    }

    if ($enable_perl_module_checks) {
        open F, "< $fuzzing_pkts_file" or die $!;
        while (<F>) {
            if (/(?:Bogus|Invalid_encoding)\s(\S+)\:\s+(.*)\,\sSPA\spacket\:\s(\S+)/) {
                push @{$fuzzing_spa_packets{$1}{$2}}, $3;
                $total_fuzzing_pkts++;
            }
        }
        close F;
    } else {
        push @tests_to_exclude, qr/perl FKO module/;
    }

    if ($enable_perl_module_fuzzing_spa_pkt_generation) {
        push @tests_to_include, qr/perl FKO module/;
        if ($fuzzing_class eq 'bogus data') {
            push @tests_to_exclude, qr/perl FKO module.*FUZZING.*invalid encoded/;
        } else {
            push @tests_to_exclude, qr/perl FKO module.*FUZZING.*invalid SPA/;
        }
    } else {
        push @tests_to_exclude, qr/perl FKO module.*FUZZING/;
    }

    $sudo_path    = &find_command('sudo');
    $killall_path = &find_command('killall');
    $pgrep_path   = &find_command('pgrep');

    unless ((&find_command('cc') or &find_command('gcc')) and &find_command('make')) {
        ### disable compilation checks
        push @tests_to_exclude, qr/recompilation/;
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
        push @tests_to_exclude, qr/profile coverage/;
    }

    open UNAME, "uname |" or die "[*] Could not execute uname: $!";
    while (<UNAME>) {
        if (/linux/i) {
            $platform = $LINUX;
            last;
        } elsif (/freebsd/i) {
            $platform = $FREEBSD;
            last;
        }
    }
    close UNAME;

    unless ($platform eq $LINUX) {
        push @tests_to_exclude, qr/NAT/;
        push @tests_to_exclude, qr/iptables/;
    }
    unless ($platform eq $FREEBSD or $platform eq $MACOSX) {
        push @tests_to_exclude, qr|active/expire sets|;
    }

    for my $file ($default_digest_file, "${default_digest_file}-old") {
        if (-e $file) {
            unlink $file;
        }
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

sub import_previous_valgrind_coverage_info() {

    if ($previous_valgrind_coverage_dir) {
        die "[*] $previous_valgrind_coverage_dir does not exist"
            unless -d $previous_valgrind_coverage_dir;
    } else {
        ### try the previous output.last/valgrind-coverage dir first
        $previous_valgrind_coverage_dir = "${output_dir}.last/$valgrind_cov_dir";

        unless (-d $previous_valgrind_coverage_dir) {
            my $os = 'linux';
            $os = 'freebsd' if $platform == $FREEBSD;
            $previous_valgrind_coverage_dir = "valgrind-coverage/$os";
        }
    }

    return unless -d $previous_valgrind_coverage_dir;

    for my $file (glob("$previous_valgrind_coverage_dir/*.test")) {

        my $test_title = '';

        my $type = 'server';
        $type = 'client' if $file =~ /\d\.test/;
        my $found = 0;

        open F, "< $file" or die $!;
        while (<F>) {
            if (/TEST\:\s/) {
                $test_title = $_;
                chomp $test_title;
                next;
            }
            ### stop after the unique functions view
            last if /with\scall\sline\snumbers/;
            if ($test_title) {
                if (/^\s+(\d+)\s\:\s(.*)/) {
                    $prev_valgrind_cov{$type}{$test_title}{$2} = $1;
                    $found = 1;
                }
            }
        }
        close F;

        unless ($found) {
            $prev_valgrind_cov{$type}{$test_title}{'NO_FLAGGED_FCNS'} = '';
        }
    }

    return;
}

sub compile_execute_fko_wrapper() {
    my $rv = 1;

    unless (-d $fko_wrapper_dir) {
        &write_test_file("[-] fko wrapper directory " .
            "$fko_wrapper_dir does not exist.\n", $curr_test_file);
        return 0;
    }

    chdir $fko_wrapper_dir or die $!;

    ### 'make clean' as root
    unless (&run_cmd('make clean', "../$cmd_out_tmp",
            "../$curr_test_file")) {
        chdir '..' or die $!;
        return 0;
    }

    if ($sudo_path) {
        my $username = getpwuid((stat("../$test_suite_path"))[4]);
        die "[*] Could not determine ../$test_suite_path owner"
            unless $username;

        unless (&run_cmd("$sudo_path -u $username make",
                "../$cmd_out_tmp", "../$curr_test_file")) {
            unless (&run_cmd('make', "../$cmd_out_tmp",
                    "../$curr_test_file")) {
                chdir '..' or die $!;
                return 0;
            }
        }

    } else {

        unless (&run_cmd('make', "../$cmd_out_tmp",
                "../$curr_test_file")) {
            chdir '..' or die $!;
            return 0;
        }
    }

    unless (-e 'fko_wrapper' and -e 'run_valgrind.sh') {
        &write_test_file("[-] fko_wrapper or run_valgrind.sh does not exist.\n",
            "../$curr_test_file");
        chdir '..' or die $!;
        return 0;
    }

    &run_cmd('./run_valgrind.sh', "../$cmd_out_tmp", "../$curr_test_file");

    $rv = 0 unless &file_find_regex([qr/no\sleaks\sare\spossible/],
        $MATCH_ALL, "../$curr_test_file");

    chdir '..' or die $!;

    return $rv;
}

sub parse_valgrind_flagged_functions() {

    my $rv = 1;

    &import_previous_valgrind_coverage_info();

    if (%prev_valgrind_cov) {
        &write_test_file("[+] Imported previous valgrind data from: " .
            "$previous_valgrind_coverage_dir\n", $curr_test_file);
    } else {
        if (-d $previous_valgrind_coverage_dir) {
            &write_test_file("[-] Did not import previous valgrind data " .
                "from: $previous_valgrind_coverage_dir\n", $curr_test_file);
        } else {
            &write_test_file("[-] Previous valgrind data dir does not exist: " .
                "from: $previous_valgrind_coverage_dir\n", $curr_test_file);
        }
    }

    mkdir "$output_dir/$valgrind_cov_dir"
        unless -d "$output_dir/$valgrind_cov_dir";

    FILE: for my $file (glob("$output_dir/*.test")) {

        my $type = 'server';
        $type = 'client' if $file =~ /\d\.test/;

        my $filename = $1 if $file =~ m|.*/(.*)|;
        my %file_scope_flagged_fcns = ();
        my %file_scope_flagged_fcns_unique = ();
        my $test_title = '';

        open F, "< $file" or die $!;
        while (<F>) {
            ### ==30969==    by 0x4E3983A: fko_set_username (fko_user.c:65)
            if (/^==.*\sby\s\S+\:\s(\S+)\s(.*)/) {
                $valgrind_flagged_fcns{$type}{"$1 $2"}++;
                $valgrind_flagged_fcns_unique{$type}{$1}++;
                $file_scope_flagged_fcns{"$1 $2"}++;
                $file_scope_flagged_fcns_unique{$1}++;
            } elsif (/TEST\:\s/) {
                $test_title = $_;
                chomp $test_title;
                last if $test_title =~ /valgrind\soutput/;
            }
        }
        close F;

        next FILE if $test_title =~ /valgrind\soutput/;

        ### write out flagged fcns for this file
        if ($filename) {
            open F, "> $output_dir/$valgrind_cov_dir/$filename"
                or die "[*] Could not open file $output_dir/$valgrind_cov_dir/$filename: $!";
            print F $test_title, "\n";

            if (keys %file_scope_flagged_fcns_unique) {
                print F "\n[+] fwknop functions (unique view):\n";
                for my $fcn (sort {$file_scope_flagged_fcns_unique{$b}
                        <=> $file_scope_flagged_fcns_unique{$a}}
                        keys %file_scope_flagged_fcns_unique) {
                    printf F "    %5d : %s\n", $file_scope_flagged_fcns_unique{$fcn}, $fcn;
                }
            }
            if (keys %file_scope_flagged_fcns) {
                print F "\n[+] fwknop functions (with call line numbers):\n";
                for my $fcn (sort {$file_scope_flagged_fcns{$b}
                        <=> $file_scope_flagged_fcns{$a}} keys %file_scope_flagged_fcns) {
                    printf F "    %5d : %s\n", $file_scope_flagged_fcns{$fcn}, $fcn;
                }
            }
            close F;

            my $new_flagged_fcns = 0;

            ### look for differences in flagged functions between the two
            ### test runs
            for my $fcn (sort {$file_scope_flagged_fcns_unique{$b}
                    <=> $file_scope_flagged_fcns_unique{$a}}
                    keys %file_scope_flagged_fcns_unique) {
                if (defined $prev_valgrind_cov{$type}
                        and defined $prev_valgrind_cov{$type}{$test_title}) {
                    ### we're looking at a matching test results file at this point
                    if (defined $prev_valgrind_cov{$type}{$test_title}{$fcn}) {
                        my $prev_calls = $prev_valgrind_cov{$type}{$test_title}{$fcn};
                        my $curr_calls = $file_scope_flagged_fcns_unique{$fcn};
                        if ($curr_calls > $prev_calls) {
                            open F, ">> $curr_test_file" or die $!;
                            print F "[-] $filename ($type) '$test_title' --> Larger number of flagged calls to " .
                                "$fcn (current: $curr_calls, previous: $prev_calls)\n";
                            close F;
                            $new_flagged_fcns = 1;
                        }
                    } else {
                        open F, ">> $curr_test_file" or die $!;
                        print F "[-] $filename ($type) '$test_title' --> NEW valgrind flagged function: $fcn\n";
                        close F;
                        $new_flagged_fcns = 1;
                    }
                }
            }

            if ($new_flagged_fcns) {
                open F, ">> $curr_test_file" or die $!;
                print F "[-] $filename New and/or greater number of valgrind flagged function calls\n";
                close F;
                $rv = 0;
            } else {
                open F, ">> $curr_test_file" or die $!;
                print F "[+] $filename No new or greater number of valgrind flagged function calls\n";
                close F;
            }
        }
    }

    open F, ">> $curr_test_file" or die $!;
    for my $type ('client', 'server') {
        print F "\n[+] fwknop $type functions (unique view):\n";
        next unless defined $valgrind_flagged_fcns_unique{$type};
        for my $fcn (sort {$valgrind_flagged_fcns_unique{$type}{$b}
                <=> $valgrind_flagged_fcns_unique{$type}{$a}}
                keys %{$valgrind_flagged_fcns_unique{$type}}) {
            printf F "    %5d : %s\n", $valgrind_flagged_fcns_unique{$type}{$fcn}, $fcn;
        }
        print F "\n[+] fwknop $type functions (with call line numbers):\n";
        for my $fcn (sort {$valgrind_flagged_fcns{$type}{$b}
                <=> $valgrind_flagged_fcns{$type}{$a}} keys %{$valgrind_flagged_fcns{$type}}) {
            printf F "    %5d : %s\n", $valgrind_flagged_fcns{$type}{$fcn}, $fcn;
        }
        next unless defined $valgrind_flagged_fcns{$type};

    }
    close F;
    return $rv;
}

sub is_fw_rule_active() {
    my $test_hr = shift;

    my $conf_args = $default_server_conf_args;

    if ($test_hr->{'server_conf'}) {
        $conf_args = "-c $test_hr->{'server_conf'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file";
    }

    if ($test_hr->{'no_ip_check'}) {
        return 1 if &run_cmd("LD_LIBRARY_PATH=$lib_dir $fwknopdCmd " .
                qq{$conf_args --fw-list | grep -v "# DISABLED" |grep _exp_},
                $cmd_out_tmp, $curr_test_file);
    } else {
        return 1 if &run_cmd("LD_LIBRARY_PATH=$lib_dir $fwknopdCmd " .
                qq{$conf_args --fw-list | grep -v "# DISABLED" |grep $fake_ip |grep _exp_},
                $cmd_out_tmp, $curr_test_file);
    }

    return 0;
}

sub is_fwknopd_running() {

    sleep 2 if $enable_valgrind;

    &run_cmd("LD_LIBRARY_PATH=$lib_dir $fwknopdCmd $default_server_conf_args " .
        "--status", $cmd_out_tmp, $curr_test_file);

    return 1 if &file_find_regex([qr/Detected\sfwknopd\sis\srunning/i],
            $MATCH_ALL, $cmd_out_tmp);

    return 0;
}

sub stop_fwknopd() {

    &run_cmd("LD_LIBRARY_PATH=$lib_dir $fwknopdCmd " .
        "$default_server_conf_args -K", $cmd_out_tmp, $curr_test_file);

    if ($enable_valgrind) {
        &time_for_valgrind();
    } else {
        sleep 1;
    }

    return;
}

sub file_find_regex() {
    my ($re_ar, $match_style, $file) = @_;

    my $found_all_regexs = 1;
    my $found_single_match = 0;
    my @write_lines = ();
    my @file_lines = ();

    open F, "< $file" or die "[*] Could not open $file: $!";
    while (<F>) {
        push @file_lines, $_;
    }
    close F;

    for my $re (@$re_ar) {
        my $matched = 0;
        for my $line (@file_lines) {
            if ($line =~ $re) {
                push @write_lines, "[.] file_find_regex() " .
                    "Matched '$re' with line: $line";
                $matched = 1;
                $found_single_match = 1;
            }
        }
        unless ($matched) {
            push @write_lines, "[.] file_find_regex() " .
                "Did not match regex '$re' from regexs: '@$re_ar' " .
                "within file: $file\n";
            $found_all_regexs = 0;
        }
    }

    for my $line (@write_lines) {
        &write_test_file($line, $file);
    }

    if ($match_style == $MATCH_ANY) {
        return $found_single_match;
    }

    return $found_all_regexs;
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
    print <<_HELP_;

[+] $0 <options>

    -A   --Anonymize-results       - Prepare anonymized results at:
                                     $tarfile
    --diff                         - Compare the results of one test run to
                                     another.  By default this compares output
                                     in ${output_dir}.last to $output_dir
    --diff-dir1=<path>             - Left hand side of diff directory path,
                                     default is: ${output_dir}.last
    --diff-dir2=<path>             - Right hand side of diff directory path,
                                     default is: $output_dir
    --include=<regex>              - Specify a regex to be used over test
                                     names that must match.
    --exclude=<regex>              - Specify a regex to be used over test
                                     names that must not match.
    --enable-recompile             - Recompile fwknop sources and look for
                                     compilation warnings.
    --enable-valgrind              - Run every test underneath valgrind.
    --enable-ip-resolve            - Enable client IP resolution (-R) test -
                                     this requires internet access.
    --enable-distcheck             - Enable 'make dist' check.
    --enable-perl-module-checks    - Run a series of tests against libfko via
                                     the perl FKO module.
    --enable-perl-module-pkt-gen   - Generate a series of fuzzing packets via
                                     the perl FKO module (assumes a patched
                                     libfko code to accept fuzzing values).
                                     The generated packets are placed in:
                                     $fuzzing_pkts_file
    --enable-openssl-checks        - Enable tests to verify that Rijndael
                                     cipher usage is compatible with openssl.
    --enable-all                   - Enable tests that aren't enabled by
                                     default, except that --enable-valgrind
                                     must also be set if valgrind mode is
                                     desired.
    --fuzzing-pkts-file <file>     - Specify path to fuzzing packet file.
    --fuzzing-pkts-append          - When generating new fuzzing packets,
                                     append them to the fuzzing packets file.
    --List                         - List test names.
    --test-limit=<num>             - Limit the number of tests that will run.
    --loopback-intf=<intf>         - Specify loopback interface name (default
                                     depends on the OS where the test suite
                                     is executed).
    --output-dir=<path>            - Path to output directory, default is:
                                     $output_dir
    --fwknop-path=<path>           - Path to fwknop binary, default is:
                                     $fwknopCmd
    --fwknopd-path=<path>          - Path to fwknopd binary, default is:
                                     $fwknopdCmd
    --libfko-path=<path>           - Path to libfko, default is:
                                     $libfko_bin
    --valgrind-path=<path>         - Path to valgrind, default is:
                                     $valgrindCmd
    --valgrind-prev-cov-dir=<path> - Path to previous valgrind-coverage
                                     directory (can set to
                                     "output.last/valgrind-coverage").
    -h   --help                    - Display usage on STDOUT and exit.

_HELP_
    exit 0;
}
