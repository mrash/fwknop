#!/usr/bin/env perl
#
# This is the main driver program for the fwknop test suite.  Test definitions
# are imported from the tests/ directory.
#

use Cwd;
use File::Copy;
use File::Path;
use IO::Socket;
use Data::Dumper;
use Getopt::Long 'GetOptions';
use Getopt::Long 'GetOptionsFromString';
use strict;
use warnings;
use POSIX;

#==================== config =====================
my $logfile         = 'test.log';
our $local_key_file = 'local_spa.key';
our $long_key_file  = 'long_spa.key';  ### > 16 bytes
our $local_spa_key  = 'fwknoptest';
our $local_hmac_key_file = 'local_hmac_spa.key';
my $output_dir      = cwd() . '/output';
our $conf_dir       = cwd() . '/conf';
our $run_dir        = cwd() . '/run';
our $run_tmp_dir_top = 'runtmp';
our $run_tmp_dir    = "$run_tmp_dir_top/subdir1/subdir2";
my $cmd_out_tmp     = 'cmd.out';
my $server_cmd_tmp  = 'server_cmd.out';
my $openssl_cmd_tmp = 'openssl_cmd.out';
my $data_tmp        = 'data.tmp';
my $key_tmp         = 'key.tmp';
my $enc_save_tmp    = 'openssl_save.enc';
my $test_suite_path = 'test-fwknop.pl';
my $username        = '';
our $access_include_dir = "$conf_dir/access-include";
my $gpg_dirs_tar = 'gpg_dirs.tar.gz';
my $access_include_dirs_tar = 'access-include.tar.gz';
our $gpg_client_home_dir = "$conf_dir/client-gpg";
our $gpg_client_home_dir_no_pw = "$conf_dir/client-gpg-no-pw";
our $gpg_client_4096_bit_key_no_pw = "$conf_dir/client-gpg-large-no-pw";
our $gpg_client_subkey_no_pw = "$conf_dir/client-gpg-subkeys-no-pw";
our $replay_pcap_file     = "$conf_dir/spa_replay.pcap";
our $multi_pkts_pcap_file = "$conf_dir/multi_pkts.pcap";
our $fcs_pcap_file        = "$conf_dir/fcs_spa.pcap";
our $spa_over_http_pcap_file = "$conf_dir/spa_over_http.pcap";
our $spa_x_forwarded_for_pcap_file = "$conf_dir/spa_x_forwarded_for.pcap";
our $spa_allow_any_user_agent_pcap_file = "$conf_dir/spa_allow_any_user_agent.pcap";

our $lib_dir = '../lib/.libs';

our $default_digest_file  = "$run_dir/digest.cache";
our $default_pid_file     = "$run_dir/fwknopd.pid";
our $tmp_rc_file          = "$run_dir/fwknoprc";
our $rewrite_rc_file      = "$run_dir/rewrite_fwknoprc";
our $rewrite_fwknopd_conf = "$run_dir/rewrite_fwknopd.conf";
our $rewrite_access_conf  = "$run_dir/rewrite_access.conf";
our $rewrite_include_keys_access_conf  = "$run_dir/rewrite_include_keys_access.conf";
our $rewrite_digest_file  = "$run_dir/rewrite_digest.cache";
our $save_rc_file         = "$run_dir/save_fwknoprc";
our $tmp_pkt_file         = "$run_dir/tmp_spa.pkt";
our $tmp_args_file        = "$run_dir/args.save";

our $fwknopCmd  = '../client/.libs/fwknop';
our $fwknopdCmd = '../server/.libs/fwknopd';

our $gpg_server_key = '361BBAD4';
our $gpg_client_key = '6A3FAD56';
our $gpg_server_key2 = 'EF5AF06A';
our $gpg_client_large_key = '31415ADE';
our $gpg_server_large_key = '40051F51';

#gpg --homedir ./client-gpg-subkeys-no-pw/ --list-keys
#./client-gpg-subkeys-no-pw//pubring.gpg
#---------------------------------------
#pub   4096R/31415ADE 2015-03-23
#uid                  fwknop project (client multi subkeys, TESTING ONLY)
#sub   4096R/82E1000B 2015-03-23
#sub   2048R/8377E3D8 2015-03-25
#sub   2048R/9CF38326 2015-03-25

our $gpg_client_subkey = '9CF38326'; ### last subkey in the keyring as shown above,
                                     ### and GPG_REMOTE_ID must match in access.conf
our $loopback_ip       = '127.0.0.1';
our $loopback_ip6      = '::1';
our $fake_ip           = '127.0.0.2';
our $fake_ip6          = '::2';
our $spoof_ip          = '1.2.3.4';
our $internal_nat_host = '192.168.1.2';
our $force_nat_host    = '192.168.1.123';
our $force_nat_host2   = '123.4.4.4';
our $force_nat_host3   = '8.1.2.3';
our $force_snat_host   = '33.3.3.3';
our $default_spa_port  = 62201;
our $non_std_spa_port  = 12345;
our $invalid_key_file  = 'invalid.key';
our $invalid_key_file2 = 'invalid2.key';
our $invalid_key_file3 = 'invalid2.key';

our $FW_TYPE   = 'iptables'; ### default to iptables
our $FW_PREFIX = 'IPT';
our $fw_conf_prefix = 'ipt';
my $prefer_iptables = 0;
my $fw_bin = '';
my $fw_bin_and_prefix = '';

our $spoof_user = 'testuser';

my $valgrind_cov_dir = 'valgrind-coverage';
my $lcov_results_dir = 'lcov-results';

my $perl_mod_fko_dir = 'FKO';
my $python_fko_dir   = 'python_fko';
my $python_script    = 'fko-python.py';
my $python_path      = '';
our $cmd_exec_test_file = '/tmp/fwknoptest';
my $default_key = 'fwknoptest';
my $asan_dir = 'asan';
my $asan_instrumentation_check = 0;

my $tests_dir = './tests';

our $rerun_failed_mode = 0;

my @test_files = (
    "$tests_dir/configure_args.pl",
    "$tests_dir/build_security.pl",
    "$tests_dir/preliminaries.pl",
    "$tests_dir/code_structure.pl",
    "$tests_dir/basic_operations.pl",
    "$tests_dir/cunit_tests.pl",
    "$tests_dir/ipv6.pl",
    "$tests_dir/rijndael.pl",
    "$tests_dir/rijndael_cmd_exec.pl",
    "$tests_dir/rijndael_hmac_cmd_exec.pl",
    "$tests_dir/rijndael_hmac_cmd_open_close.pl",
    "$tests_dir/rijndael_replay_attacks.pl",
    "$tests_dir/rijndael_fuzzing.pl",
    "$tests_dir/rijndael_backwards_compatibility.pl",
    "$tests_dir/rijndael_hmac.pl",
    "$tests_dir/rijndael_hmac_fuzzing.pl",
    "$tests_dir/fault_injection.pl",
    "$tests_dir/afl_fuzzing.pl",
    "$tests_dir/address_sanitizer.pl",
    "$tests_dir/os_compatibility.pl",
    "$tests_dir/perl_FKO_module.pl",
    "$tests_dir/python_fko.pl",
    "$tests_dir/gpg_no_pw.pl",
    "$tests_dir/gpg_no_pw_hmac.pl",
    "$tests_dir/gpg.pl",
    "$tests_dir/gpg_hmac.pl",
);
#================== end config ===================

our @build_security_client        = ();  ### imported from tests/build_security.pl
our @build_security_server        = ();
our @build_security_libfko        = ();
our @preliminaries                = ();  ### from tests/preliminaries.pl
our @code_structure_errstr        = ();  ### from tests/code_structure.pl (may include Coccinelle matches eventually)
our @configure_args               = ();  ### from tests/configure_args.pl
our @basic_operations             = ();  ### from tests/basic_operations.pl
our @cunit_tests                  = ();  ### from tests/cunit_tests.pl
our @ipv6                         = ();  ### from tests/ipv6.pl
our @rijndael                     = ();  ### from tests/rijndael.pl
our @rijndael_cmd_exec            = ();  ### from tests/rijndael_cmd_exec.pl
our @rijndael_hmac_cmd_exec       = ();  ### from tests/rijndael_hmac_cmd_exec.pl
our @rijndael_hmac_cmd_open_close = ();  ### from tests/rijndael_hmac_cmd_open_close.pl
our @rijndael_replay_attacks      = ();  ### from tests/rijndael_replay_attacks.pl
our @rijndael_hmac                = ();  ### from tests/rijndael_hmac.pl
our @rijndael_fuzzing             = ();  ### from tests/rijndael_fuzzing.pl
our @rijndael_hmac_fuzzing        = ();  ### from tests/rijndael_hmac_fuzzing.pl
our @fault_injection              = ();  ### from tests/fault_injection.pl
our @afl_fuzzing                  = ();  ### from tests/alf_fuzzing.pl
our @address_sanitizer            = ();  ### from tests/address_sanitizer.pl
our @gpg_no_pw                    = ();  ### from tests/gpg_now_pw.pl
our @gpg_no_pw_hmac               = ();  ### from tests/gpg_now_pw_hmac.pl
our @gpg                          = ();  ### from tests/gpg.pl
our @gpg_hmac                     = ();  ### from tests/gpg_hmac.pl
our @perl_FKO_module              = ();  ### from tests/perl_FKO_module.pl
our @python_fko                   = ();  ### from tests/python_fko.pl
our @os_compatibility             = ();  ### from tests/os_compatibility.pl
our @rijndael_backwards_compatibility = ();  ### from tests/rijndael_backwards_compatibility.pl

my $passed = 0;
my $failed = 0;
my $executed = 0;
my $test_include = '';
my @tests_to_include = ();
my $test_exclude = '';
my @tests_to_exclude = ();
my %include_tracking = ();
my %exclude_tracking = ();
my $do_crash_check = 1;
my %valgrind_flagged_fcns = ();
my %valgrind_flagged_fcns_unique = ();
my $previous_valgrind_coverage_dir = '';
our $uniq_keys = 100;
my $test_limit = 0;
my $list_mode = 0;
my $diff_dir1 = '';
my $diff_dir2 = '';
our $loopback_intf = '';
my $default_pkt_tries = 20;
my $send_all_loop_once = 0;
my $detect_server_loop_once = 0;
my $default_server_tries = 10;
my $anonymize_results = 0;
my $orig_config_args = '';
my $curr_test_file = 'init';
my $init_file = $curr_test_file;
my $config_log = '../config.log';
my $tarfile = 'test_fwknop.tar.gz';
our $key_gen_file = "$output_dir/key_gen";
our $verbose_str  = "--verbose --verbose";
my $gdb_test_file = '';
our $resolve_url = 'http://www.cipherdyne.org/cgi-bin/myip/';  ### with trailing slash for test coverage
our $resolve_url_with_port = 'http://www.cipherdyne.org:80/cgi-bin/myip';
my $fuzzing_pkts_file = '../perl/FKO/t/fuzzing_spa_packets';
my $fuzzing_pkts_append = 0;
my $fuzzing_key = 'testtest';
my $fuzzing_num_pkts = 0;
my $fuzzing_test_tag = '';
my $fuzzing_class = 'bogus data';
my %fuzzing_spa_packets = ();
my $total_fuzzing_pkts = 0;
our $sudo_access_conf = "$run_dir/sudo_access.conf";
my $sudo_conf_testing = '';
my $server_test_file  = '';
my $client_only_mode = 0;
my $server_only_mode = 0;
my $enable_cores_pattern_mode = 0;
my $cores_pattern_sh = './generate_cores.sh';
my $enable_fault_injection = 0;
my $disable_fault_injection = 0;
my $enable_valgrind = 0;
my $disable_valgrind = 0;
my $enable_valgrind_gen_suppressions = 0;
my $valgrind_disable_suppressions = 0;
my $valgrind_disable_child_silent = 0;
my $valgrind_suppressions_file = cwd() . '/valgrind_suppressions';
our $valgrind_str = '';
my $asan_mode = 0;
my $ubsan_mode = 0;
my %cached_fw_policy  = ();
my $cpan_valgrind_mod = 'Test::Valgrind';
my %prev_valgrind_cov = ();
my %prev_valgrind_file_titles = ();
my $libfko_hdr_file    = '../lib/fko.h';
my $libfko_errstr_file = '../lib/fko_error.c';
my $perl_libfko_constants_file   = '../perl/FKO/lib/FKO_Constants.pl';
my $python_libfko_constants_file = '../python/fko.py';
our $fko_wrapper_dir = 'fko-wrapper';
our $wrapper_exec_script = 'run.sh';
our $wrapper_exec_script_valgrind = 'run_valgrind.sh';
my $fuzz_spa_payloads_file = $fko_wrapper_dir . '/fuzz_spa_payloads';
our $send_fuzz_payloads_file = $fko_wrapper_dir . '/send_spa_payloads';
my $python_spa_packet = '';
my $pkts_file = '';
my $enable_fuzzing_interfaces_tests = 0;
my $enable_client_ip_resolve_test = 0;
my $enable_all = 0;
my $enable_complete = 0;
my $saved_last_results = 0;
my $diff_mode = 0;
my $enc_dummy_key = 'A'x8;
my $fko_obj = ();
my $enable_recompilation_warnings_check = 0;
my $enable_configure_args_checks = 0;
my $enable_profile_coverage_check = 0;
my $enable_profile_coverage_init = 0;
my $profile_gen_report_sh = './gen-coverage-report.sh';
my $profile_init_sh = './init-lcov.sh';
my $profile_rm_files_sh = './rm-coverage-files.sh';
my $do_profile_init = 0;
my $enable_make_distcheck = 0;
my $enable_perl_module_checks = 0;
my $enable_perl_module_fuzzing_spa_pkt_generation = 0;
my $enable_python_module_checks = 0;
my $enable_openssl_compatibility_tests = 0;
my $disable_openssl_compatibility_tests = 0;
my $enable_cunit_tests = 0;
my $openssl_success_ctr = 0;
my $openssl_failure_ctr = 0;
my $openssl_ctr = 0;
my $openssl_hmac_success_ctr = 0;
my $openssl_hmac_failure_ctr = 0;
my $openssl_hmac_ctr = 0;
my $openssl_hmac_hexkey_supported = 0;
my $fuzzing_success_ctr = 0;
my $fuzzing_failure_ctr = 0;
my $fuzzing_ctr = 0;
my $include_permissions_warnings = 0;
my $lib_view_cmd = '';
my $git_path = '';
our $valgrind_path = '';
our $fiu_run_path = '';
our $sudo_path = '';
our $gcov_path = '';
my  $touch_path = '';
my  $lcov_path = '';
my  $coverage_diff_path = 'coverage_diff.py';
my  $genhtml_path = '';
our $killall_path = '';
our $pgrep_path   = '';
our $pkill_path   = '';
our $openssl_path = '';
our $base64_path  = '';
our $pinentry_fail = 0;
our $perl_path = '';
our $prove_path = '';
our $ifconfig_path = '';
our $ip_path = '';
my  $readelf_path = '';
our $platform = '';
our $help = 0;
our $YES = 1;
our $NO  = 0;
our $IGNORE = 2;
our $PRINT_LEN = 68;
our $USE_PREDEF_PKTS = 1;
our $READ_PKTS_FROM_FILE = 4;
our $USE_CLIENT = 2;
our $USE_PCAP_FILE = 3;
our $REQUIRED = 1;
our $OPTIONAL = 0;
our $OPTIONAL_NUMERIC = 2;
our $NEW_RULE_REQUIRED = 1;
our $REQUIRE_NO_NEW_RULE = 2;
our $NEW_RULE_REMOVED = 1;
our $REQUIRE_NO_NEW_REMOVED = 2;
our $MATCH_ANY = 1;
our $MATCH_ALL = 2;
our $REQUIRE_SUCCESS = 0;
our $REQUIRE_FAILURE = 1;
my $TIMESTAMP_DIFF = 2;
my $ENC_RIJNDAEL = 1;
my $ENC_GPG      = 2;
our $LINUX   = 1;
our $FREEBSD = 2;
our $MACOSX  = 3;
our $OPENBSD = 4;
our $start_time = time();
my $SERVER_RECEIVE_CHECK    = 1;
my $NO_SERVER_RECEIVE_CHECK = 2;
my $APPEND_RESULTS    = 1;
my $NO_APPEND_RESULTS = 2;
my %sigs = (
    'SIGHUP'   => 1,
    'SIGINT'   => 2,
    'SIGUSR1'  => 10,
    'SIGUSR2'  => 12,
    'SIGTSTP'  => 20,
);
my @sigs_ordered = (
    'SIGHUP',
    'SIGINT',
    'SIGUSR1',
    'SIGUSR2',
    'SIGTSTP',
);

my $ip_re = qr|(?:[0-2]?\d{1,2}\.){3}[0-2]?\d{1,2}|;  ### IPv4

my @args_cp = @ARGV;

exit 1 unless GetOptions(
    'Anonymize-results' => \$anonymize_results,
    'fwknop-path=s'     => \$fwknopCmd,
    'fwknopd-path=s'    => \$fwknopdCmd,
    'lib-dir=s'         => \$lib_dir,  ### for LD_LIBRARY_PATH
    'loopback-intf=s'   => \$loopback_intf,
    'test-include=s'    => \$test_include,
    'include=s'         => \$test_include,  ### synonym
    'test-exclude=s'    => \$test_exclude,
    'exclude=s'         => \$test_exclude,  ### synonym
    'enable-perl-module-checks' => \$enable_perl_module_checks,
    'enable-perl-module-pkt-generation' => \$enable_perl_module_fuzzing_spa_pkt_generation,
    'enable-python-module-checks' => \$enable_python_module_checks,
    'fuzzing-pkts-file=s' => \$fuzzing_pkts_file,
    'fuzzing-pkts-append' => \$fuzzing_pkts_append,
    'fuzzing-test-tag=s'  => \$fuzzing_test_tag,
    'fuzzing-class=s'     => \$fuzzing_class,
    'prefer-iptables' => \$prefer_iptables,
    'enable-recompile-check' => \$enable_recompilation_warnings_check,
    'enable-configure-args-checks' => \$enable_configure_args_checks,
    'enable-profile-coverage-check' => \$enable_profile_coverage_check,
    'enable-cores-pattern' => \$enable_cores_pattern_mode,
    'enable-profile-coverage-init' => \$enable_profile_coverage_init,
    'enable-ip-resolve' => \$enable_client_ip_resolve_test,
    'enable-distcheck'  => \$enable_make_distcheck,
    'enable-dist-check' => \$enable_make_distcheck,  ### synonym
    'enable-openssl-checks' => \$enable_openssl_compatibility_tests,
    'disable-openssl-checks' => \$disable_openssl_compatibility_tests,
    'enable-cunit' => \$enable_cunit_tests,
    'gdb-test=s'        => \$gdb_test_file,
    'List-mode'         => \$list_mode,
    'test-limit=i'      => \$test_limit,
    'enable-fault-injection'   => \$enable_fault_injection,
    'disable-fault-injection'  => \$disable_fault_injection,
    'enable-valgrind'   => \$enable_valgrind,
    'disable-valgrind'  => \$disable_valgrind,
    'valgrind-disable-suppressions'  => \$valgrind_disable_suppressions,
    'valgrind-disable-child-silent'  => \$valgrind_disable_child_silent,
    'enable-all'        => \$enable_all,
    'enable-complete'   => \$enable_complete,
    'enable-fuzzing-interfaces-tests' => \$enable_fuzzing_interfaces_tests,
    'valgrind-path=s'   => \$valgrind_path,
    'valgrind-suppression-file' => \$valgrind_suppressions_file,
    'enable-valgrind-gen-suppressions' => \$enable_valgrind_gen_suppressions,
    ### can set the following to "output.last/valgrind-coverage" if
    ### a full test suite run has already been executed with --enable-valgrind
    'valgrind-prev-cov-dir=s' => \$previous_valgrind_coverage_dir,
    'openssl-path=s'    => \$openssl_path,
    'fiu-run-path=s'    => \$fiu_run_path,
    'output-dir=s'      => \$output_dir,
    'cmd-verbose=s'     => \$verbose_str,
    'client-only-mode'  => \$client_only_mode,
    'server-only-mode'  => \$server_only_mode,
    'rerun-failed-mode'  => \$rerun_failed_mode,
    'diff'              => \$diff_mode,
    'diff-dir1=s'       => \$diff_dir1,
    'diff-dir2=s'       => \$diff_dir2,
    'help'              => \$help
);

&usage() if $help;

our @last_logfile = ();

if ($rerun_failed_mode) {
    unless (open (RE, "<", "test.log")) {  # check for test.log
        die "[*] Can't find test.log";
    }
    while (<RE>) {
        push @last_logfile, $_;
    }
    close RE;
    my $arg_line = "";
    for my $line (@last_logfile) {
        if ($line =~ /args:(.+)/) {
            $arg_line = $1;
            last;
        }
    }
    unless ($arg_line) {
        die "[*] Can't find arguments";
    }
    system("cp -f test.log test.log.bak");

    my $ret = 0;
    my $leftovers = "";
    ($ret, $leftovers) = GetOptionsFromString(
        $arg_line,
        'fwknop-path=s'     => \$fwknopCmd,
        'fwknopd-path=s'    => \$fwknopdCmd,
        'lib-dir=s'         => \$lib_dir,  ### for LD_LIBRARY_PATH
        'loopback-intf=s'   => \$loopback_intf,
        'test-include=s'    => \$test_include,
    'include=s'         => \$test_include,  ### synonym
    'test-exclude=s'    => \$test_exclude,
    'exclude=s'         => \$test_exclude,  ### synonym
    'enable-perl-module-checks' => \$enable_perl_module_checks,
    'enable-perl-module-pkt-generation' => \$enable_perl_module_fuzzing_spa_pkt_generation,
    'enable-python-module-checks' => \$enable_python_module_checks,
    'fuzzing-pkts-file=s' => \$fuzzing_pkts_file,
    'fuzzing-pkts-append' => \$fuzzing_pkts_append,
    'fuzzing-test-tag=s'  => \$fuzzing_test_tag,
    'fuzzing-class=s'     => \$fuzzing_class,
    'prefer-iptables' => \$prefer_iptables,
    'enable-recompile-check' => \$enable_recompilation_warnings_check,
    'enable-configure-args-checks' => \$enable_configure_args_checks,
    'enable-profile-coverage-check' => \$enable_profile_coverage_check,
    'enable-cores-pattern' => \$enable_cores_pattern_mode,
    'enable-profile-coverage-init' => \$enable_profile_coverage_init,
    'enable-ip-resolve' => \$enable_client_ip_resolve_test,
    'enable-distcheck'  => \$enable_make_distcheck,
    'enable-dist-check' => \$enable_make_distcheck,  ### synonym
    'enable-openssl-checks' => \$enable_openssl_compatibility_tests,
    'enable-cunit' => \$enable_cunit_tests,
    'gdb-test=s'        => \$gdb_test_file,
    'List-mode'         => \$list_mode,
    'test-limit=i'      => \$test_limit,
    'enable-fault-injection'   => \$enable_fault_injection,
    'disable-fault-injection'  => \$disable_fault_injection,
    'enable-valgrind'   => \$enable_valgrind,
    'disable-valgrind'  => \$disable_valgrind,
    'valgrind-disable-suppressions'  => \$valgrind_disable_suppressions,
    'valgrind-disable-child-silent'  => \$valgrind_disable_child_silent,
    'enable-all'        => \$enable_all,
    'enable-complete'   => \$enable_complete,
    'enable-fuzzing-interfaces-tests' => \$enable_fuzzing_interfaces_tests,
    'valgrind-path=s'   => \$valgrind_path,
    'valgrind-suppression-file' => \$valgrind_suppressions_file,
    'enable-valgrind-gen-suppressions' => \$enable_valgrind_gen_suppressions,
    ### can set the following to "output.last/valgrind-coverage" if
    ### a full test suite run has already been executed with --enable-valgrind
    'valgrind-prev-cov-dir=s' => \$previous_valgrind_coverage_dir,
    'openssl-path=s'    => \$openssl_path,
    'fiu-run-path=s'    => \$fiu_run_path,
    'output-dir=s'      => \$output_dir,
    'cmd-verbose=s'     => \$verbose_str,
    'client-only-mode'  => \$client_only_mode,
    'server-only-mode'  => \$server_only_mode,
    'diff'              => \$diff_mode,
    'diff-dir1=s'       => \$diff_dir1,
    'diff-dir2=s'       => \$diff_dir2
    );

}


&os_fw_detect();

### main configuration file paths
our %cf = (
    "${fw_conf_prefix}_nat"                  => "$conf_dir/${fw_conf_prefix}_nat_fwknopd.conf",
    "${fw_conf_prefix}_nat_disable_aging"    => "$conf_dir/${fw_conf_prefix}_nat_disable_aging_fwknopd.conf",
    "${fw_conf_prefix}_snat"                 => "$conf_dir/${fw_conf_prefix}_snat_fwknopd.conf",
    "${fw_conf_prefix}_snat_no_translate_ip" => "$conf_dir/${fw_conf_prefix}_snat_no_translate_ip_fwknopd.conf",
    "${fw_conf_prefix}_snat_translate_ip"    => "$conf_dir/${fw_conf_prefix}_snat_translate_ip_fwknopd.conf",
    'def'                          => "$conf_dir/default_fwknopd.conf",
    'def_access'                   => "$conf_dir/default_access.conf",
    'portrange_filter'             => "$conf_dir/portrange_fwknopd.conf",
    'hmac_access'                  => "$conf_dir/hmac_access.conf",
    'include1_hmac_access'         => "$conf_dir/include1_hmac_access.conf",
    'include2_hmac_access'         => "$conf_dir/include2_hmac_access.conf",
    'include_r1_hmac_access'       => "$conf_dir/include_r1_hmac_access.conf",
    'include_r2_hmac_access'       => "$conf_dir/include_r2_hmac_access.conf",
    'include_m1_hmac_access'       => "$conf_dir/include_m1_hmac_access.conf",
    'include_def_hmac_access'      => "$conf_dir/include_def_hmac_access.conf",
    'include_keys1_hmac_access'    => "$conf_dir/include_keys1_hmac_access.conf",
    'prepend_fwknopd'              => "$conf_dir/prepend_fwknopd.conf",
    "${fw_conf_prefix}_no_nat_dns_fwknopd" => "$conf_dir/${fw_conf_prefix}_no_nat_dns_fwknopd.conf",
    'hmac_cmd_access'              => "$conf_dir/hmac_cmd_access.conf",
    'hmac_cmd_setuid_access'       => "$conf_dir/hmac_cmd_setuid_access.conf",
    'hmac_cmd_giduid_access'       => "$conf_dir/hmac_cmd_giduid_access.conf",
    'hmac_get_key_access'          => "$conf_dir/hmac_get_key_access.conf",
    'hmac_equal_keys_access'       => "$conf_dir/hmac_equal_keys_access.conf",
    'hmac_no_b64_access'           => "$conf_dir/hmac_no_b64_access.conf",
    'hmac_md5_access'              => "$conf_dir/hmac_md5_access.conf",
    'hmac_md5_short_key_access'    => "$conf_dir/hmac_md5_short_key_access.conf",
    'hmac_md5_long_key_access'     => "$conf_dir/hmac_md5_long_key_access.conf",
    'hmac_sha1_access'             => "$conf_dir/hmac_sha1_access.conf",
    'hmac_sha1_short_key_access'   => "$conf_dir/hmac_sha1_short_key_access.conf",
    'hmac_sha1_long_key_access'    => "$conf_dir/hmac_sha1_long_key_access.conf",
    'hmac_sha256_access'           => "$conf_dir/hmac_sha256_access.conf",
    'hmac_sha3_256_access'         => "$conf_dir/hmac_sha3_256_access.conf",
    'hmac_sha256_digest1_mismatch_access' => "$conf_dir/hmac_sha256_digest1_mismatch_access.conf",
    'hmac_sha256_digest2_mismatch_access' => "$conf_dir/hmac_sha256_digest2_mismatch_access.conf",
    'hmac_sha256_digest3_mismatch_access' => "$conf_dir/hmac_sha256_digest3_mismatch_access.conf",
    'hmac_sha256_digest4_mismatch_access' => "$conf_dir/hmac_sha256_digest4_mismatch_access.conf",
    'hmac_sha256_short_key_access' => "$conf_dir/hmac_sha256_short_key_access.conf",
    'hmac_sha256_long_key_access'  => "$conf_dir/hmac_sha256_long_key_access.conf",
    'hmac_sha384_access'           => "$conf_dir/hmac_sha384_access.conf",
    'hmac_sha384_short_key_access' => "$conf_dir/hmac_sha384_short_key_access.conf",
    'hmac_sha384_long_key_access'  => "$conf_dir/hmac_sha384_long_key_access.conf",
    'hmac_sha512_access'           => "$conf_dir/hmac_sha512_access.conf",
    'hmac_sha3_512_access'         => "$conf_dir/hmac_sha3_512_access.conf",
    'hmac_sha512_short_key_access' => "$conf_dir/hmac_sha512_short_key_access.conf",
    'hmac_sha512_short_key2_access' => "$conf_dir/hmac_sha512_short_key2_access.conf",
    'hmac_sha512_long_key_access'  => "$conf_dir/hmac_sha512_long_key_access.conf",
    'hmac_simple_keys_access'      => "$conf_dir/hmac_simple_keys_access.conf",
    'hmac_invalid_type_access'     => "$conf_dir/hmac_invalid_type_access.conf",
    'hmac_cygwin_access'           => "$conf_dir/hmac_no_b64_cygwin_access.conf",
    'hmac_cmd_open_close_cycle_access' => "$conf_dir/hmac_cmd_open_close_cycle_access.conf",
    'hmac_cmd_open_close_cycle_access2' => "$conf_dir/hmac_cmd_open_close_cycle_access2.conf",
    'hmac_cmd_open_close_cycle_access3' => "$conf_dir/hmac_cmd_open_close_cycle_access3.conf",
    'hmac_cmd_open_close_cycle_access4' => "$conf_dir/hmac_cmd_open_close_cycle_access4.conf",
    'hmac_cmd_open_close_cycle_access5' => "$conf_dir/hmac_cmd_open_close_cycle_access5.conf",
    'hmac_cmd_open_close_cycle_access6' => "$conf_dir/hmac_cmd_open_close_cycle_access6.conf",
    'hmac_cmd_open_close_cycle_access7' => "$conf_dir/hmac_cmd_open_close_cycle_access7.conf",
    'hmac_cmd_open_close_cycle_access8' => "$conf_dir/hmac_cmd_open_close_cycle_access8.conf",
    'hmac_cmd_open_close_multi_cycle_access' => "$conf_dir/hmac_cmd_open_close_multi_cycle_access.conf",
    'spa_destination'              => "$conf_dir/destination_rule_fwknopd.conf",
    "${fw_conf_prefix}_spa_dst_snat" => "$conf_dir/${fw_conf_prefix}_spa_dst_snat_fwknopd.conf",
    'hmac_spa_destination_access'  => "$conf_dir/hmac_spa_destination_access.conf",
    'hmac_spa_destination2_access' => "$conf_dir/hmac_spa_destination2_access.conf",
    'hmac_spa_destination3_access' => "$conf_dir/hmac_spa_destination3_access.conf",
    'hmac_spa_destination4_access' => "$conf_dir/hmac_spa_destination4_access.conf",
    'hmac_spa_destination5_access' => "$conf_dir/hmac_spa_destination5_access.conf",
    'exp_access'                   => "$conf_dir/expired_stanza_access.conf",
    'future_exp_access'            => "$conf_dir/future_expired_stanza_access.conf",
    'exp_epoch_access'             => "$conf_dir/expired_epoch_stanza_access.conf",
    'invalid_exp_access'           => "$conf_dir/invalid_expire_access.conf",
    'require_force_nat_access'     => "$conf_dir/require_force_nat_access.conf",
    "${fw_conf_prefix}_output_chain"         => "$conf_dir/${fw_conf_prefix}_output_chain_fwknopd.conf",
    "invalid_${fw_conf_prefix}_input_chain"  => "$conf_dir/invalid_${fw_conf_prefix}_input_chain_fwknopd.conf",
    "invalid_${fw_conf_prefix}_input_chain2" => "$conf_dir/invalid_${fw_conf_prefix}_input_chain_2_fwknopd.conf",
    "invalid_${fw_conf_prefix}_input_chain3" => "$conf_dir/invalid_${fw_conf_prefix}_input_chain_3_fwknopd.conf",
    "invalid_${fw_conf_prefix}_input_chain4" => "$conf_dir/invalid_${fw_conf_prefix}_input_chain_4_fwknopd.conf",
    "invalid_${fw_conf_prefix}_input_chain5" => "$conf_dir/invalid_${fw_conf_prefix}_input_chain_5_fwknopd.conf",
    "invalid_${fw_conf_prefix}_input_chain6" => "$conf_dir/invalid_${fw_conf_prefix}_input_chain_6_fwknopd.conf",
    'invalid_run_dir_path'         => "$conf_dir/invalid_run_dir_path_fwknopd.conf",
    'force_nat_access'             => "$conf_dir/force_nat_access.conf",
    'hmac_force_nat_access'        => "$conf_dir/hmac_force_nat_access.conf",
    'hmac_force_nat_forward_all_access' => "$conf_dir/hmac_force_nat_forward_all_access.conf",
    'hmac_force_snat_access'       => "$conf_dir/hmac_force_snat_access.conf",
    'hmac_force_masq_access'       => "$conf_dir/hmac_force_masq_access.conf",
    'hmac_force_masq_no_dnat_access' => "$conf_dir/hmac_force_masq_no_dnat_access.conf",
    'hmac_forward_all_access'      => "$conf_dir/hmac_forward_all_access.conf",
    'hmac_forward_all_masq_access' => "$conf_dir/hmac_forward_all_masq_access.conf",
    'hmac_forward_all_and_dna_access' => "$conf_dir/hmac_forward_all_and_dnat_access.conf",
    'cmd_access'                   => "$conf_dir/cmd_access.conf",
    'cmd_setuid_access'            => "$conf_dir/cmd_setuid_access.conf",
    'cmd_giduid_access'            => "$conf_dir/cmd_giduid_access.conf",
    "${fw_conf_prefix}_local_nat"     => "$conf_dir/${fw_conf_prefix}_local_nat_fwknopd.conf",
    "${fw_conf_prefix}_no_flush_init" => "$conf_dir/${fw_conf_prefix}_no_flush_init_fwknopd.conf",
    "${fw_conf_prefix}_no_flush_exit" => "$conf_dir/${fw_conf_prefix}_no_flush_exit_fwknopd.conf",
    "${fw_conf_prefix}_no_flush_init_or_exit" => "$conf_dir/${fw_conf_prefix}_no_flush_init_or_exit_fwknopd.conf",
    'ipfw_active_expire'           => "$conf_dir/ipfw_active_expire_equal_fwknopd.conf",
    'hmac_android_access'          => "$conf_dir/hmac_android_access.conf",
    'hmac_android_fdroid_access'   => "$conf_dir/hmac_android_fdroid_access.conf",
    'android_access'               => "$conf_dir/android_access.conf",
    'android_legacy_iv_access'     => "$conf_dir/android_legacy_iv_access.conf",
    'dual_key_access'              => "$conf_dir/dual_key_usage_access.conf",
    'dual_key_legacy_iv_access'    => "$conf_dir/dual_key_legacy_iv_access.conf",
    'hmac_dual_key_access'         => "$conf_dir/hmac_dual_key_usage_access.conf",
    'no_exit_down_intf'            => "$conf_dir/no_exit_down_intf_fwknopd.conf",
    'gpg_access'                   => "$conf_dir/gpg_access.conf",
    'gpg_hmac_access'              => "$conf_dir/gpg_hmac_access.conf",
    'gpg_invalid_exe_access'       => "$conf_dir/gpg_invalid_exe_access.conf",
    'gpg_hmac_sha512_access'       => "$conf_dir/gpg_hmac_sha512_access.conf",
    'gpg_hmac_sha3_512_access'     => "$conf_dir/gpg_hmac_sha3_512_access.conf",
    'legacy_iv_access'             => "$conf_dir/legacy_iv_access.conf",
    'hmac_fuzzing_access'          => "$conf_dir/hmac_fuzzing_access.conf",
    'legacy_iv_long_key_access'    => "$conf_dir/legacy_iv_long_key_access.conf",
    'legacy_iv_long_key2_access'   => "$conf_dir/legacy_iv_long_key2_access.conf",
    'gpg_no_pw_access'             => "$conf_dir/gpg_no_pw_access.conf",
    'gpg_no_pw_fpr_access'         => "$conf_dir/gpg_no_pw_fpr_access.conf",
    'gpg_no_pw_bad_fpr_access'     => "$conf_dir/gpg_no_pw_bad_fpr_access.conf",
    'gpg_no_pw_no_fpr_access'      => "$conf_dir/gpg_no_pw_no_fpr_access.conf",
    'gpg_no_sig_no_fpr_access'     => "$conf_dir/gpg_no_sig_no_fpr_access.conf",
    'gpg_no_pw_hmac_access'        => "$conf_dir/gpg_no_pw_hmac_access.conf",
    'gpg_no_pw_hmac_clientdir_access' => "$conf_dir/gpg_no_pw_hmac_clientdir_access.conf",
    'gpg_no_pw_hmac_serverdir_access' => "$conf_dir/gpg_no_pw_hmac_serverdir_access.conf",
    'gpg_no_pw_hmac_sha512_access' => "$conf_dir/gpg_no_pw_hmac_sha512_access.conf",
    'gpg_no_sig_verify_access'     => "$conf_dir/gpg_no_sig_verify_access.conf",
    'gpg_invalid_sig_id_access'    => "$conf_dir/gpg_invalid_sig_id_access.conf",
    'gpg_large_signing_key_access' => "$conf_dir/gpg_large_signing_key_access.conf",
    'gpg_subkey_access'            => "$conf_dir/gpg_subkey_access.conf",
    'gpg_server_large_key_access'  => "$conf_dir/gpg_server_large_key_access.conf",
    'tcp_server'                   => "$conf_dir/tcp_server_fwknopd.conf",
    'udp_server'                   => "$conf_dir/udp_server_fwknopd.conf",
    'spa_over_http'                => "$conf_dir/spa_over_http_fwknopd.conf",
    'spa_x_forwarded_for'          => "$conf_dir/spa_x_forwarded_for_fwknopd.conf",
    'spa_allow_any_user_agent'     => "$conf_dir/spa_allow_any_user_agent_fwknopd.conf",
    'tcp_pcap_filter'              => "$conf_dir/tcp_pcap_filter_fwknopd.conf",
    'icmp_pcap_filter'             => "$conf_dir/icmp_pcap_filter_fwknopd.conf",
    'open_ports_access'            => "$conf_dir/open_ports_access.conf",
    'open_ports_force_masq_access' => "$conf_dir/open_ports_force_masq_access.conf",
    'hmac_open_ports_access'       => "$conf_dir/hmac_sha256_open_ports_access.conf",
    'multi_gpg_access'             => "$conf_dir/multi_gpg_access.conf",
    'multi_gpg_no_pw_access'       => "$conf_dir/multi_gpg_no_pw_access.conf",
    'multi_stanza_access'          => "$conf_dir/multi_stanzas_access.conf",
    'broken_keys_access'           => "$conf_dir/multi_stanzas_with_broken_keys.conf",
    'ecb_mode_access'              => "$conf_dir/ecb_mode_access.conf",
    'ctr_mode_access'              => "$conf_dir/ctr_mode_access.conf",
    'cfb_mode_access'              => "$conf_dir/cfb_mode_access.conf",
    'ofb_mode_access'              => "$conf_dir/ofb_mode_access.conf",
    'open_ports_mismatch'          => "$conf_dir/mismatch_open_ports_access.conf",
    'require_user_access'          => "$conf_dir/require_user_access.conf",
    'user_mismatch_access'         => "$conf_dir/mismatch_user_access.conf",
    'require_src_access'           => "$conf_dir/require_src_access.conf",
    'invalid_src_access'           => "$conf_dir/invalid_source_access.conf",
    'no_src_match'                 => "$conf_dir/no_source_match_access.conf",
    'no_subnet_match'              => "$conf_dir/no_subnet_source_match_access.conf",
    'no_multi_src'                 => "$conf_dir/no_multi_source_match_access.conf",
    'multi_src_access'             => "$conf_dir/multi_source_match_access.conf",
    'ip_src_match'                 => "$conf_dir/ip_source_match_access.conf",
    'subnet_src_match'             => "$conf_dir/ip_source_match_access.conf",
    'rc_def_key'                   => "$conf_dir/fwknoprc_with_default_key",
    'rc_def_b64_key'               => "$conf_dir/fwknoprc_with_default_base64_key",
    'rc_named_key'                 => "$conf_dir/fwknoprc_named_key",
    'rc_hmac_equal_keys'           => "$conf_dir/fwknoprc_hmac_equal_keys",
    'rc_invalid_b64_key'           => "$conf_dir/fwknoprc_invalid_base64_key",
    'rc_hmac_b64_key'              => "$conf_dir/fwknoprc_default_hmac_base64_key",
    'rc_hmac_defaults'             => "$conf_dir/fwknoprc_hmac_defaults",
    'rc_hmac_http_resolve'         => "$conf_dir/fwknoprc_hmac_http_resolve",
    'rc_hmac_https_resolve'        => "$conf_dir/fwknoprc_hmac_https_resolve",
    'rc_hmac_http_only_resolve'    => "$conf_dir/fwknoprc_hmac_http_only_resolve",
    'rc_hmac_nat_rand_b64_key'     => "$conf_dir/fwknoprc_hmac_nat_rand_base64_key",
    'rc_hmac_spoof_src_b64_key'    => "$conf_dir/fwknoprc_hmac_spoof_src_base64_key",
    'rc_hmac_sha512_b64_key'       => "$conf_dir/fwknoprc_hmac_sha512_base64_key",
    'rc_hmac_b64_key2'             => "$conf_dir/fwknoprc_hmac_key2",
    'rc_hmac_time_offset_mins'     => "$conf_dir/fwknoprc_hmac_time_offset_mins",
    'rc_hmac_time_offset_hours'    => "$conf_dir/fwknoprc_hmac_time_offset_hours",
    'rc_hmac_time_offset_days'     => "$conf_dir/fwknoprc_hmac_time_offset_days",
    'rc_rand_port_hmac_b64_key'    => "$conf_dir/fwknoprc_rand_port_hmac_base64_key",
    'rc_gpg_signing_pw'            => "$conf_dir/fwknoprc_gpg_signing_pw",
    'rc_gpg_named_signing_pw'      => "$conf_dir/fwknoprc_named_gpg_signing_pw",
    'rc_gpg_hmac_b64_key'          => "$conf_dir/fwknoprc_gpg_hmac_key",
    'rc_gpg_invalid_gpg_exe'       => "$conf_dir/fwknoprc_gpg_invalid_exe",
    'rc_gpg_hmac_sha512_b64_key'   => "$conf_dir/fwknoprc_gpg_hmac_sha512_key",
    'rc_gpg_args_hmac_b64_key'     => "$conf_dir/fwknoprc_gpg_args_hmac_key",
    'rc_gpg_args_no_pw_hmac_b64_key' => "$conf_dir/fwknoprc_gpg_args_no_pw_hmac_key",
    'rc_hmac_simple_key'           => "$conf_dir/fwknoprc_hmac_simple_keys",
    'rc_hmac_invalid_type'         => "$conf_dir/fwknoprc_hmac_invalid_type",
    'rc_hmac_invalid_type'         => "$conf_dir/fwknoprc_hmac_invalid_type",
    'rc_hmac_md5_key'              => "$conf_dir/fwknoprc_hmac_md5_key",
    'rc_hmac_md5_short_key'        => "$conf_dir/fwknoprc_hmac_md5_short_key",
    'rc_hmac_md5_long_key'         => "$conf_dir/fwknoprc_hmac_md5_long_key",
    'rc_hmac_sha1_key'             => "$conf_dir/fwknoprc_hmac_sha1_key",
    'rc_hmac_sha1_short_key'       => "$conf_dir/fwknoprc_hmac_sha1_short_key",
    'rc_hmac_sha1_long_key'        => "$conf_dir/fwknoprc_hmac_sha1_long_key",
    'rc_hmac_sha256_key'           => "$conf_dir/fwknoprc_hmac_sha256_key",
    'rc_hmac_sha3_256_key'         => "$conf_dir/fwknoprc_hmac_sha3_256_key",
    'rc_hmac_sha256_short_key'     => "$conf_dir/fwknoprc_hmac_sha256_short_key",
    'rc_hmac_sha256_long_key'      => "$conf_dir/fwknoprc_hmac_sha256_long_key",
    'rc_hmac_sha384_key'           => "$conf_dir/fwknoprc_hmac_sha384_key",
    'rc_hmac_sha384_short_key'     => "$conf_dir/fwknoprc_hmac_sha384_short_key",
    'rc_hmac_sha384_long_key'      => "$conf_dir/fwknoprc_hmac_sha384_long_key",
    'rc_hmac_sha512_key'           => "$conf_dir/fwknoprc_hmac_sha512_key",
    'rc_hmac_sha3_512_key'         => "$conf_dir/fwknoprc_hmac_sha3_512_key",
    'rc_hmac_sha512_short_key'     => "$conf_dir/fwknoprc_hmac_sha512_short_key",
    'rc_hmac_sha512_long_key'      => "$conf_dir/fwknoprc_hmac_sha512_long_key",
    'rc_stanza_list'               => "$conf_dir/fwknoprc_stanza_list",
    'rc_cmd_open_close_multi_cycle' => "$conf_dir/fwknoprc_hmac_multi_base64_key",
    'base64_key_access'            => "$conf_dir/base64_key_access.conf",
    "${fw_conf_prefix}_custom_input_chain" => "$conf_dir/${fw_conf_prefix}_custom_input_chain_fwknopd.conf",
    "${fw_conf_prefix}_custom_nat_chain"   => "$conf_dir/${fw_conf_prefix}_custom_nat_chain_fwknopd.conf",
    'disable_aging'                => "$conf_dir/disable_aging_fwknopd.conf",
    'disable_aging_nat'            => "$conf_dir/disable_aging_nat_fwknopd.conf",
    'fuzz_source'                  => "$conf_dir/fuzzing_source_access.conf",
    'fuzz_open_ports'              => "$conf_dir/fuzzing_open_ports_access.conf",
    'fuzz_restrict_ports'          => "$conf_dir/fuzzing_restrict_ports_access.conf",
);

our $lib_view_str = "LD_LIBRARY_PATH=$lib_dir";
our $libfko_bin = "$lib_dir/libfko.so";  ### this is usually a link
if ($enable_all or $enable_complete) {
    $enable_valgrind = 1;
    $enable_recompilation_warnings_check = 1;
    $enable_configure_args_checks = 1;
    $enable_make_distcheck = 1;
    $enable_client_ip_resolve_test = 1;
    $enable_perl_module_checks = 1;
    $enable_python_module_checks = 1;
    $enable_openssl_compatibility_tests = 1;
    $enable_cunit_tests = 1;
}

if ($enable_complete) {
    $enable_fault_injection = 1;
    $enable_profile_coverage_check = 1;
    $enable_fuzzing_interfaces_tests = 1;
    $enable_cores_pattern_mode = 1;
}

$enable_valgrind = 0 if $disable_valgrind;
$enable_fault_injection = 0 if $disable_fault_injection;

unless (-d $output_dir) {
    mkdir $output_dir or die "[*] Could not mkdir $output_dir: $!";
}

### allow OpenSSL tests to be disabled even when --enable-all is set
$enable_openssl_compatibility_tests = 0 if $disable_openssl_compatibility_tests;

### create an anonymized tar file of test suite results that can be
### emailed around to assist in debugging fwknop communications
exit &anonymize_results() if $anonymize_results;

exit &diff_test_results() if $diff_mode;

### run an fwknop command under gdb from a previous test run
exit &gdb_test_cmd() if $gdb_test_file;

### only need one of 'ip' or 'ifconfig', prefer 'ip'
$ip_path = &find_command('ip') unless $ip_path;
$ifconfig_path = &find_command('ifconfig') unless $ifconfig_path or $ip_path;
&identify_loopback_intf() unless $list_mode or $client_only_mode;

### make sure everything looks as expected before continuing
&init();

if ($enable_valgrind) {
    $valgrind_str = "$valgrind_path --leak-check=full " .
        "--show-reachable=yes --track-origins=yes";
    unless ($valgrind_disable_suppressions) {
        $valgrind_str .= " --suppressions=$valgrind_suppressions_file";
    }
    if ($enable_valgrind_gen_suppressions) {
        $valgrind_str .= ' --gen-suppressions=all';
    }
    unless ($valgrind_disable_child_silent) {
        $valgrind_str .= ' --child-silent-after-fork=yes';
    }
}

our $intf_str = "-i $loopback_intf --foreground $verbose_str";

our $default_client_args = "$lib_view_str $valgrind_str " .
    "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --get-key " .
    "$local_key_file --no-save-args $verbose_str";

our $default_client_args_long_key = "$lib_view_str $valgrind_str " .
    "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --get-key " .
    "$long_key_file --no-save-args $verbose_str";

our $default_client_args_no_get_key = "$lib_view_str " .
    "$valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip " .
    "--no-save-args $verbose_str";

our $default_client_args_ipv6_no_get_key = "$lib_view_str " .
    "$valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip6 -D $loopback_ip6 " .
    "--no-save-args $verbose_str";

our $default_client_args_no_verbose = "$lib_view_str " .
    "$valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip " .
    '--no-save-args ';

our $client_rewrite_rc_args = "$default_client_args_no_get_key " .
    "--rc-file $rewrite_rc_file --test";

our $client_save_rc_args = "$default_client_args_no_get_key " .
    "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test";

our $client_save_rc_args_no_verbose = "$default_client_args_no_verbose " .
    "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test";

our $client_save_rc_args_no_force = "$default_client_args_no_get_key " .
    "--rc-file $save_rc_file --save-rc-stanza --test";

our $client_save_rc_args_no_test = "$lib_view_str $valgrind_str " .
    "$fwknopCmd -A tcp/22 -D $loopback_ip --no-save-args " .
    "--rc-file $save_rc_file --save-rc-stanza --force-stanza -v -v -v";

our $server_rewrite_conf_files = "$lib_view_str $valgrind_str $fwknopdCmd " .
    "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
    "-d $default_digest_file -p $default_pid_file $intf_str";

our $default_client_hmac_args = "$default_client_args_no_get_key " .
    "--rc-file $cf{'rc_hmac_b64_key'}";

our $default_client_hmac_args_ipv6 = "$default_client_args_ipv6_no_get_key " .
    "--rc-file $cf{'rc_hmac_b64_key'}";

our $client_hmac_rc_defaults = "$lib_view_str $valgrind_str " .
    "$fwknopCmd --no-save-args --rc-file $cf{'rc_hmac_defaults'}";

our $client_hmac_rc_http_resolve = "$lib_view_str $valgrind_str " .
    "$fwknopCmd --no-save-args --rc-file $cf{'rc_hmac_http_resolve'}";

our $client_hmac_rc_https_resolve = "$lib_view_str $valgrind_str " .
    "$fwknopCmd --no-save-args --rc-file $cf{'rc_hmac_https_resolve'}";

our $client_hmac_rc_http_only_resolve = "$lib_view_str $valgrind_str " .
    "$fwknopCmd --no-save-args --rc-file $cf{'rc_hmac_http_only_resolve'}";

our $client_ip_resolve_args = "$lib_view_str $valgrind_str " .
    "$fwknopCmd -A tcp/22 -R -D $loopback_ip --get-key " .
    "$local_key_file $verbose_str";

our $client_ip_resolve_hmac_args = "$lib_view_str $valgrind_str " .
    "$fwknopCmd -A tcp/22 -R -D $loopback_ip --rc-file " .
    "$cf{'rc_hmac_b64_key'} $verbose_str";

our $default_client_gpg_args = "$default_client_args " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key " .
    "--gpg-home-dir $gpg_client_home_dir";

our $default_client_gpg_args_no_homedir = "$default_client_args " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key ";

our $default_client_gpg_args_same_key_signer = "$default_client_args " .
    "--gpg-recipient-key $gpg_client_key " .
    "--gpg-signer-key $gpg_client_key ";

our $default_client_gpg_args_same_key_recip = "$default_client_args " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_server_key ";

our $default_client_gpg_args_no_get_key = "$default_client_args_no_get_key " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key " .
    "--gpg-home-dir $gpg_client_home_dir";

our $default_client_gpg_args_no_pw = "$default_client_args_no_get_key " .
    "--gpg-no-signing-pw " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key " .
    "--gpg-home-dir $gpg_client_home_dir_no_pw";

our $client_gpg_large_key_args_no_pw = "$default_client_args_no_get_key " .
    "--gpg-no-signing-pw " .
    "--gpg-recipient-key $gpg_server_key2 " .
    "--gpg-signer-key $gpg_client_large_key " .
    "--gpg-home-dir $gpg_client_4096_bit_key_no_pw";

our $client_gpg_subkey_args_no_pw = "$default_client_args_no_get_key " .
    "--gpg-no-signing-pw " .
    "--gpg-recipient-key $gpg_server_key2 " .
    "--gpg-signer-key $gpg_client_subkey " .
    "--gpg-home-dir $gpg_client_subkey_no_pw";

our $client_gpg_server_4096_args_no_pw = "$default_client_args_no_get_key " .
    "--gpg-no-signing-pw " .
    "--gpg-recipient-key $gpg_server_large_key " .
    "--gpg-signer-key $gpg_client_subkey " .
    "--gpg-home-dir $gpg_client_subkey_no_pw";

our $client_and_server_gpg_4096_args_no_pw = "$default_client_args_no_get_key " .
    "--gpg-no-signing-pw " .
    "--gpg-recipient-key $gpg_server_large_key " .
    "--gpg-signer-key $gpg_client_large_key " .
    "--gpg-home-dir $gpg_client_4096_bit_key_no_pw";

our $default_server_conf_args = "-c $cf{'def'} -a $cf{'def_access'} " .
    "-d $default_digest_file -p $default_pid_file";

our $default_server_hmac_conf_args = "-c $cf{'def'} -a $cf{'hmac_access'} " .
    "-d $default_digest_file -p $default_pid_file";

our $default_server_gpg_args = "$lib_view_str " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_access'} $intf_str " .
    "-d $default_digest_file -p $default_pid_file";

our $default_server_gpg_args_no_pw = "$lib_view_str " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_no_pw_access'} $intf_str " .
    "-d $default_digest_file -p $default_pid_file";

our $default_server_gpg_args_hmac = "$lib_view_str " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_hmac_access'} $intf_str " .
    "-d $default_digest_file -p $default_pid_file";

our $invalid_gpg_exe_server_args = "$lib_view_str " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_invalid_exe_access'} $intf_str " .
    "-d $default_digest_file -p $default_pid_file";

our $default_server_gpg_args_no_pw_hmac = "$lib_view_str " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_no_pw_hmac_access'} $intf_str " .
    "-d $default_digest_file -p $default_pid_file";

### point the compiled binaries at the local library path
### instead of any installed libfko instance
$ENV{'LD_LIBRARY_PATH'}   = $lib_dir;
$ENV{'DYLD_LIBRARY_PATH'} = $lib_dir if $lib_view_cmd =~ /otool/;

### import the tests from the various tests/ files
&import_test_files();

###
### main array that defines the tests we will run
###
my @tests = (
    {
        'category' => 'recompilation',
        'detail'   => 'recompile and look for compilation warnings',
        'function' => \&compile_warnings,
    },
    {
        'category' => 'make distcheck',
        'detail'   => 'ensure proper distribution creation',
        'function' => \&make_distcheck,
    },
    {
        'category' => 'Makefile.am',
        'detail'   => 'test suite conf/ files included',
        'function' => \&test_suite_conf_files,
    },
    {
        'category' => 'max coverage',
        'detail'   => 'interact with terminal for pw - TYPE ANY KEY HERE:',
        'cmdline'  => "$fwknopCmd -A tcp/22 -a 1.1.1.1 -D $loopback_ip -v -v -v ",
        'function' => \&use_terminal_run_client,
    },
    @build_security_client,
    @build_security_server,
    @build_security_libfko,
    @preliminaries,
    @code_structure_errstr,
    @basic_operations,
    @cunit_tests,
    @rijndael,
    @rijndael_cmd_exec,
    @rijndael_hmac_cmd_exec,
    @rijndael_hmac_cmd_open_close,
    @rijndael_replay_attacks,
    @rijndael_backwards_compatibility,
    @rijndael_fuzzing,
    @rijndael_hmac,
    @rijndael_hmac_fuzzing,
    @ipv6,
    @fault_injection,
    @address_sanitizer,
    @afl_fuzzing,
    @os_compatibility,
    @perl_FKO_module,
    @python_fko,
    @gpg_no_pw,
    @gpg_no_pw_hmac,
    @gpg,
    @gpg_hmac,
);

if ($enable_profile_coverage_check) {
    push @tests,
    {
        'category' => 'profile coverage',
        'detail'   => 'gcov profile coverage',
        'function' => \&profile_coverage
    };
}

### the configure args tests recompile fwknop, so only do this
### after the profile coverage stats have been created for the main
### test run
push @tests, @configure_args;

if ($enable_valgrind) {
    push @tests,
    {
        'category' => 'valgrind output',
        'subcategory' => 'flagged functions',
        'detail'   => '',
        'function' => \&parse_valgrind_flagged_functions
    };
}

if ($do_crash_check) {
    push @tests,
    {
        'category' => 'Look for crashes',
        'detail'   => 'checking for segfault/core dump messages',
        'function' => \&look_for_crashes
    };
}

my %test_keys = (
    'category'        => $REQUIRED,
    'subcategory'     => $OPTIONAL,
    'detail'          => $REQUIRED,
    'function'        => $REQUIRED,
    'binary'          => $OPTIONAL,
    'multi_cmds'      => $OPTIONAL,
    'cmdline'         => $OPTIONAL,
    'fwknopd_cmdline' => $OPTIONAL,
    'fatal'           => $OPTIONAL_NUMERIC,
    'key_file'        => $OPTIONAL,
    'exec_err'        => $OPTIONAL,
    'server_exec_err' => $OPTIONAL,
    'fw_rule_created' => $OPTIONAL,
    'fw_rule_removed' => $OPTIONAL,
    'sudo_test'       => $OPTIONAL,
    'sudo_conf'       => $OPTIONAL,
    'sudo_exec_user'  => $OPTIONAL,
    'sudo_exec_group' => $OPTIONAL,
    'exec_user'       => $OPTIONAL,
    'server_conf'     => $OPTIONAL,
    'client_only'     => $OPTIONAL_NUMERIC,
    'server_only'     => $OPTIONAL_NUMERIC,
    'pkt'             => $OPTIONAL,
    'spa_pkts_file'   => $OPTIONAL,
    'fuzzing_pkt'     => $OPTIONAL,
    'pkt_prefix'      => $OPTIONAL,
    'no_ip_check'     => $OPTIONAL,
    'get_key'         => $OPTIONAL,
    'get_hmac_key'    => $OPTIONAL,
    'set_legacy_iv'   => $OPTIONAL,
    'sleep_cycles'    => $OPTIONAL_NUMERIC,
    'write_rc_file'   => $OPTIONAL,
    'save_rc_stanza'  => $OPTIONAL,
    'client_pkt_tries' => $OPTIONAL_NUMERIC,
    'max_pkt_tries'    => $OPTIONAL_NUMERIC,
    'client_popen'     => $OPTIONAL,
    'disable_valgrind' => $OPTIONAL,
    'wrapper_compile'  => $OPTIONAL,
    'wrapper_script'   => $OPTIONAL,
    'wrapper_binary'   => $OPTIONAL,
    'fiu_run'             => $OPTIONAL_NUMERIC,
    'fiu_injection_style' => $OPTIONAL,
    'fiu_iterations'      => $OPTIONAL_NUMERIC,
    'server_access_file'  => $OPTIONAL,
    'server_include_keys_access_file' => $OPTIONAL,
    'server_conf_file'    => $OPTIONAL,
    'digest_cache_file'   => $OPTIONAL,
    'cmd_cycle_open_file'  => $OPTIONAL,
    'cmd_cycle_close_file' => $OPTIONAL,
    'cmd_exec_file_owner' => $OPTIONAL,
    'cmd_exec_file_not_created' => $OPTIONAL,
    'user_group_mismatch'       => $OPTIONAL,
    'sudo_user_group_mismatch'  => $OPTIONAL,
    'rm_rule_mid_cycle'   => $OPTIONAL,
    'server_receive_re'   => $OPTIONAL,
    'no_exit_intf_down'   => $OPTIONAL,
    'positive_output_matches' => $OPTIONAL,
    'negative_output_matches' => $OPTIONAL,
    'client_and_server_mode'  => $OPTIONAL_NUMERIC,
    'insert_rule_before_exec'    => $OPTIONAL,
    'insert_rule_while_running'  => $OPTIONAL,
    'insert_duplicate_rule_while_running' => $OPTIONAL,
    'fw_dupe_rule_args'          => $OPTIONAL,
    'expect_server_stopped'      => $OPTIONAL,
    'ignore_client_error'        => $OPTIONAL,
    'weak_server_receive_check'  => $OPTIONAL,
    'search_for_rule_after_exit' => $OPTIONAL,
    'rc_positive_output_matches' => $OPTIONAL,
    'rc_negative_output_matches' => $OPTIONAL,
    'mv_and_restore_replay_cache' => $OPTIONAL,
    'relax_receive_cycle_num_check' => $OPTIONAL,
    'client_positive_output_matches' => $OPTIONAL,
    'client_negative_output_matches' => $OPTIONAL,
    'server_positive_output_matches' => $OPTIONAL,
    'server_positive_num_matches'    => $OPTIONAL,
    'server_negative_output_matches' => $OPTIONAL,
    'server_negative_num_matches'    => $OPTIONAL,
    'client_cycles_per_server_instance' => $OPTIONAL_NUMERIC,
    'iptables_rm_chains_after_server_start' => $OPTIONAL,
);

&validate_test_hashes();

### make sure no fwknopd instance is currently running
die "[*] Please stop the running fwknopd instance."
    if &global_fwknopd_pgrep_check();

if ($rerun_failed_mode) {
    my $test_num = 0;
    my $test_category = "";
    my $test_subcategory = "";
    my $test_detail = "";
    &logr("\nRunning previously failed tests\n");

    for my $line (@last_logfile) {
        if ($line =~ /fail \((\d+)\)/ || $line =~ /valgrind output/ || $line =~ /Look for crashes/ || $line =~ /profile coverage/ ) {
            $test_num = $line =~ /\((\d+)\)\n/;
            $test_num = $1;
            $executed = $test_num - 1;
            if( $line =~ /\[(.+)\]\s+\[(.+)\]\s+([\w \(\)\/\-\>]+)/) {
                $test_category = $1;
                $test_subcategory = $2;
                $test_detail = $3;
            } elsif ($line =~ /^\[(.+)\]\s+\[(.+)\]/) {
                $test_category = $1;
                $test_subcategory = $2;
            } elsif ($line =~ /^\[(.+)\]/) {
                $test_category = $1;
            }
            for my $test_hr (@tests) {
                if ($test_hr->{'category'} eq $test_category
                        && $test_hr->{'detail'} eq $test_detail) {
                    &run_test($test_hr);
                } elsif ($test_hr->{'category'} eq "valgrind output" && $test_category eq "valgrind output") {
                    &run_test($test_hr);
                    if ($line =~ /pass \(\d+\)/) {
                        $passed--;
                    }
                } elsif ($test_hr->{'category'} eq "profile coverage" && $test_category eq "profile coverage") {
                    &run_test($test_hr);
                    if ($line =~ /pass \(\d+\)/) {
                        $passed--;
                    }
                } elsif ($test_hr->{'category'} eq "Look for crashes" && $test_category eq "Look for crashes") {
                    &run_test($test_hr);
                    if ($line =~ /pass \(\d+\)/) {
                        $passed--;
                    }
                }
            }

        } elsif ($line =~ /Run time: ([\d\.]+) minutes/) {
            my $total_elapsed_seconds = time() - $start_time;
            my $total_elapsed_minutes = sprintf "%.2f", ($total_elapsed_seconds / 60);
            $total_elapsed_minutes = $total_elapsed_minutes + $1;
            &logr("    Run time: $total_elapsed_minutes minutes\n");

        } elsif ($line =~ /Run time: ([\d\.]+) seconds/) {
            my $total_elapsed_seconds = time() - $start_time + $1;
            if ($total_elapsed_seconds > 60) {
                my $total_elapsed_minutes = sprintf "%.2f", ($total_elapsed_seconds / 60);
                &logr("    Run time: $total_elapsed_minutes minutes\n");
            } else {
                &logr("    Run time: $total_elapsed_seconds seconds\n");
            }

#        } elsif ($line =~ /OpenSSL tests passed/) {

#        } elsif ($line =~ /OpenSSL HMAC tests passed/) {

#        } elsif ($line =~ /Fuzzing tests passed/) {

        } elsif ($line =~ /(\d+)\/(\d+)\/(\d+) test buckets passed/) {
            $passed = $1 + $passed;
            $executed = $3;
            &logr("[+] $passed/$failed/$executed test buckets passed/failed/executed\n");
        } else {
            &logr($line);
        }
    }
    exit 0;
}

### now that we're ready to run, preserve any previous test
### suite output
&preserve_previous_test_run_results();

&logr("\n[+] Starting the fwknop test suite...\n\n" .
    "    args: @args_cp\n\n"
);

### save the results from any previous test suite run
### so that we can potentially compare them with --diff
if ($saved_last_results) {
    &logr("    Saved results from previous run " .
        "to: ${output_dir}.last/\n\n");
}

unless ($list_mode) {
    copy $init_file, "$output_dir/init" if -e $init_file;
}

if ($enable_valgrind) {
    if ($previous_valgrind_coverage_dir) {
        die "[*] $previous_valgrind_coverage_dir does not exist"
            unless -d $previous_valgrind_coverage_dir;
        if (-d "${previous_valgrind_coverage_dir}/valgrind-coverage") {
            $previous_valgrind_coverage_dir .= '/valgrind-coverage';
        }
    } else {
        ### try the previous output.last/valgrind-coverage dir first
        $previous_valgrind_coverage_dir = "${output_dir}.last/$valgrind_cov_dir";

        unless (-d $previous_valgrind_coverage_dir) {
            my $os = 'linux';
            $os = 'freebsd' if $platform == $FREEBSD;
            $previous_valgrind_coverage_dir = "valgrind-coverage/$os";
        }

    }
    if (-d $previous_valgrind_coverage_dir) {
        &logr("    Valgrind mode enabled, will import previous coverage from:\n" .
            "        $previous_valgrind_coverage_dir/\n\n");
    }
}

### print a summary of how many test buckets will be run
my $test_buckets = 0;
for my $test_hr (@tests) {
    next unless &process_include_exclude(&get_msg($test_hr));
    $test_buckets++;
    if ($test_limit > 0) {
        last if $test_buckets >= $test_limit;
    }
}
&logr("[+] Total test buckets to execute: $test_buckets\n\n");

### main loop through all of the tests
my $run_flag = 1;
for my $test_hr (@tests) {
    if ($run_flag
            or $test_hr->{'category'} eq 'valgrind output'
            or $test_hr->{'category'} eq 'Look for crashes'
            or $test_hr->{'category'} eq 'ASAN'
            or $test_hr->{'category'} eq 'profile coverage') {
        &run_test($test_hr);
    }
    if ($test_limit > 0) {
        $run_flag = 0 if $executed >= $test_limit;
    }
}

&logr("\n");

unless ($list_mode) {
    &remove_permissions_warnings() unless $include_permissions_warnings;
    &restore_dir($gpg_dirs_tar);
    &restore_dir($access_include_dirs_tar);
}

my $total_elapsed_seconds = time() - $start_time;
my $total_elapsed_minutes = sprintf "%.2f", ($total_elapsed_seconds / 60);

if ($total_elapsed_seconds > 60) {
    &logr("    Run time: $total_elapsed_minutes minutes\n");
} else {
    &logr("    Run time: $total_elapsed_seconds seconds\n");
}

if (@tests_to_include and keys %include_tracking) {
    my $tot_included = 0;
    for my $re (keys %include_tracking) {
        $tot_included += keys %{$include_tracking{$re}};
        for my $test (keys %{$include_tracking{$re}}) {
            &write_test_file("$re: $test\n", "$output_dir/tests.included");
        }
    }
    &logr("    Tests included (see $output_dir/tests.included): "
        . $tot_included . "\n");
}
if (@tests_to_exclude and keys %exclude_tracking) {
    my $tot_excluded = 0;
    for my $re (keys %exclude_tracking) {
        $tot_excluded += keys %{$exclude_tracking{$re}};
        for my $test (keys %{$exclude_tracking{$re}}) {
            &write_test_file("$re: $test\n", "$output_dir/tests.excluded");
        }
    }
    &logr("    Tests excluded (see $output_dir/tests.excluded): "
        . $tot_excluded . "\n");
}

&logr("\n");

if ($enable_openssl_compatibility_tests) {
    &logr("[+] $openssl_success_ctr/$openssl_failure_ctr/$openssl_ctr " .
        "OpenSSL tests passed/failed/executed\n");
    &logr("[+] $openssl_hmac_success_ctr/$openssl_hmac_failure_ctr/$openssl_hmac_ctr " .
        "OpenSSL HMAC tests passed/failed/executed\n");
}
if ($fuzzing_ctr > 0) {
    &logr("[+] $fuzzing_success_ctr/$fuzzing_failure_ctr/$fuzzing_ctr " .
        "Fuzzing tests passed/failed/executed\n");
}
&logr("[+] $passed/$failed/$executed test buckets passed/failed/executed\n\n");

unless ($list_mode) {
    copy $logfile, "$output_dir/$logfile" or die $!;
}

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

    &validate_test_hash($test_hr);

    ### prepare for test run
    &rm_tmp_files();

    my $msg = &get_msg($test_hr);

    $msg =~ s/REPLPKTS/-->$total_fuzzing_pkts<-- pkts/;

    if ($client_only_mode) {
        return unless $test_hr->{'client_only'}
            or $test_hr->{'subcategory'} eq 'client'
            or $test_hr->{'category'} eq 'perl FKO module'
            or $test_hr->{'category'} eq 'python fko extension';
        return if $msg =~ /server/i;
    } elsif ($server_only_mode) {
        return unless $test_hr->{'server_only'}
            or $test_hr->{'subcategory'} eq 'server'
            or $test_hr->{'category'} eq 'perl FKO module'
            or $test_hr->{'category'} eq 'python fko extension';
        return if $msg =~ /client/i;
    }

    if ($list_mode) {
        if (&process_include_exclude($msg)) {
            print $msg, "\n";
        } else {
            print "$msg (requires an --enable-* arg, see -h)\n";
        }
        return;
    }

    return unless &process_include_exclude($msg);

    &dots_print($msg);

    $executed++;
    $curr_test_file   = "$output_dir/$executed.test";
    $server_test_file = "$output_dir/${executed}_fwknopd.test";

    &write_test_file("[+] TEST: $msg\n", $curr_test_file);

    $test_hr->{'msg'} = $msg;

    if ($test_hr->{'mv_and_restore_replay_cache'}) {
        unlink "${default_digest_file}.mv"
            if -e "${default_digest_file}.mv";
        move $default_digest_file, "${default_digest_file}.mv";
    }

    my $rv = &{$test_hr->{'function'}}($test_hr);

    ### if we're in valgrind mode, make sure there were no memory leaks
    if ($enable_valgrind) {
        for my $file ($curr_test_file, $server_test_file) {
            next unless -e $file;
            if ($rv) {
                &write_test_file("[+] VERDICT: pass ($executed)\n", $file);
            } else {
                &write_test_file("[-] VERDICT: fail ($executed)\n", $file);
            }
            if (&file_find_regex([qr/^==\d+==\sHEAP\sSUMMARY/],
                    $MATCH_ALL, $NO_APPEND_RESULTS, $file)) {
                unless (&valgrind_results($file)) {
                    &write_test_file("[-] valgrind criteria failed, setting rv=0.\n",
                        $file);
                    $rv = 0;
                }
            }
        }
    }

    if ($rv) {
        &logr("pass ($executed)\n");
        $passed++;
    } else {
        &logr("fail ($executed)\n");
        $failed++;

        if ($test_hr->{'fatal'} eq $YES) {
            die "[*] required test failed, exiting.";
        }
    }

    if ($test_hr->{'mv_and_restore_replay_cache'}) {
        unlink $default_digest_file if -e $default_digest_file;
        move "${default_digest_file}.mv", $default_digest_file;
    }

    if ($enable_valgrind and &is_valgrind_running()) {
        if ($pkill_path) {
            for my $cmd ('memcheck', 'valgrind') {
                system "$pkill_path -f $cmd";
            }
        } elsif ($killall_path) {
            for my $cmd ('memcheck', 'valgrind') {
                system "$killall_path -g -r $cmd > /dev/null 2>&1";
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

    if ($enable_profile_coverage_check) {
        if ($username) {
            for my $extension ('*.gcno', '*.gcda', '*.gcov') {
                system qq/find .. -name $extension | xargs -r chown $username/;
            }
        }
        for my $extension ('*.gcno', '*.gcda', '*.gcov') {
            system qq/find .. -name $extension | xargs -r chmod a+w/;
        }
    }

    ### clean up tmp files now that the test is complete
    &rm_tmp_files();

    return;
}

sub precise_sleep {
    my ($sleeptime) = @_;
    select(undef, undef, undef, $sleeptime);
}

sub get_msg() {
    my $test_hr = shift;

    my $msg = "[$test_hr->{'category'}]";
    $msg .= " [$test_hr->{'subcategory'}]" if $test_hr->{'subcategory'};
    $msg .= " $test_hr->{'detail'}";

    return $msg;
}

sub process_include_exclude() {
    my $msg = shift;

    ### inclusions/exclusions
    if (@tests_to_include) {
        my $found = 0;
        for my $test (@tests_to_include) {
            if ($msg =~ $test or &always_run($msg)) {
                $include_tracking{$test}{$msg} = '';
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
                $exclude_tracking{$test}{$msg} = '';
                $found = 1;
                last;
            }
        }
        return 0 if $found;
    }
    return 1;
}

sub always_run() {
    my $msg = shift;

    if (($enable_valgrind and $msg =~ /valgrind\soutput/)
            or ($enable_profile_coverage_check and $msg =~ /profile\scoverage/)
            or ($asan_instrumentation_check and $msg =~ /Address\sSanitizer\sinstrumentation\scheck/)
            or ($msg =~ /segfault.*dump\smessages/)) {
        return 1;
    }
    return 0;
}

sub gdb_test_cmd() {

    die "[*] previous test file: $gdb_test_file does not exist."
        unless -e $gdb_test_file;

    my $gdb_cmd = '';

    open F, "< $gdb_test_file" or die "[*] Could not open $gdb_test_file: $!";
    while (<F>) {
        if (/CMD\:\sLD_LIBRARY_PATH=(\S+).*\s($fwknopCmd\s.*)/
                or /CMD\:\sLD_LIBRARY_PATH=(\S+).*\s($fwknopdCmd\s.*)/) {
            $gdb_cmd = "LD_LIBRARY_PATH=$1 gdb --args $2";
            last;
        }
    }
    close F;

    print "\n[+] Running the following command under gdb: $gdb_cmd\n\n";

    if ($gdb_cmd) {
        system $gdb_cmd;
    } else {
        die "[*] Could not extract fwknop/fwknopd command from $gdb_test_file";
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

    open F, "< $dir/$logfile" or die "[*] Could not open $dir/$logfile: $!";
    while (<F>) {
        if (/^(.*?)\.\.\..*(pass|fail)\s\((\d+)\)/) {
            $hr->{$1}{'pass_fail'} = $2;
            $hr->{$1}{'num'}       = $3;
        }
    }
    return;
}

sub is_asan_instrumentation_working() {
    my $test_hr = shift;

    my $rv = 1;
    chdir $asan_dir or die $!;

    for my $file ('Makefile-m32', 'Makefile') {
        $rv = 1;
        unless (&run_cmd("make -f $file clean", "../$cmd_out_tmp",
                $curr_test_file)) {
            $rv = 0;
            next;
        }

        if ($sudo_path) {
            unless (&run_cmd("$sudo_path -u $username make -f $file",
                    "../$cmd_out_tmp", $curr_test_file)) {
                unless (&run_cmd("make -f $file", "../$cmd_out_tmp",
                        $curr_test_file)) {
                    $rv = 0;
                    next;
                }
            }
        } else {
            unless (&run_cmd("make -f $file", "../$cmd_out_tmp",
                    $curr_test_file)) {
                $rv = 0;
                next;
            }
        }

        if ($rv) {
            &run_cmd('./a.out', "../$cmd_out_tmp", $curr_test_file);
            chdir '..' or die $!;
            if (&is_sanitizer_crash($curr_test_file)) {
                chdir $asan_dir or die $!;
                $rv = 1;
                last;
            } else {
                $rv = 0;
                chdir $asan_dir or die $!;
                next;
            }
        }
    }
    chdir '..' or die $!;
    return $rv;
}

sub compile_warnings() {

    my $curr_pwd = cwd() or die $!;
    chdir '..' or die $!;

    &config_recompile('');

    ### look for compilation warnings - something like:
    ###     warning: ‘test’ is used uninitialized in this function
    if (&file_find_regex([qr/\swarning:\s/i, qr/gcc\:.*\sunused/],
            $MATCH_ANY, $APPEND_RESULTS, $curr_test_file)) {
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

    my $rv = 1;

    ### check for any *.gcno files - if they don't exist, then fwknop was
    ### not compiled with profile support
    unless (glob('../client/*.gcno') and glob('../server/*.gcno')) {
        &write_test_file("[-] ../client/*.gcno and " .
            "../server/*.gcno files do not exist.\n", $curr_test_file);
        return 0;
    }

    my $curr_dir = getcwd() or die $!;

    unless ($lcov_path) {
        &write_test_file(
            "[-] lcov command not found, skipping code coverage report generation.",
            $curr_test_file);
        return 0;
    }

    &run_cmd($profile_gen_report_sh, $cmd_out_tmp, $curr_test_file);

    if (-d $lcov_results_dir) {
        move $lcov_results_dir, "$output_dir/$lcov_results_dir";
        for my $f ('lcov_coverage.info', 'lcov_coverage_final.info') {
            move $f, "$output_dir/$f" if -e $f;
        }
    } else {
        &write_test_file("[-] $lcov_results_dir does not exist.",
            $cmd_out_tmp, $curr_test_file);
        $rv = 0;
    }

    if (-d "${output_dir}.last") {
        &run_cmd("./$coverage_diff_path", $cmd_out_tmp, $curr_test_file);
    }

    if ($username) {
        for my $extension ('*.gcno', '*.gcda', '*.gcov') {
            system qq/find .. -name $extension | xargs -r chown $username/;
        }
    }

    for my $extension ('*.gcno', '*.gcda', '*.gcov') {
        system qq/find .. -name $extension | xargs -r chmod a+w/;
    }

    return $rv;
}

sub fiu_run_fault_injection() {
    my $test_hr = shift;
    my $rv = 1;

     my $iterations = $test_hr->{'fiu_iterations'};
     $iterations = 1 if $iterations < 1;  ### assume we want at least 1

     for (my $i=0; $i < $iterations; $i++) {
         &run_cmd("$lib_view_str $fiu_run_path -x " .
             "-c '$test_hr->{'fiu_injection_style'}' $test_hr->{'cmdline'}",
             $cmd_out_tmp, $curr_test_file);
     }

    return $rv;
}

sub fault_injection_tag() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created    = 0;
    my $fw_rule_removed    = 0;

    my $tag_name = '';
    if ($test_hr->{'cmdline'}) {
        if ($test_hr->{'cmdline'} =~ /fault\-injection\-tag\s(S+)/) {
            $tag_name = $1;
        }
    } elsif ($test_hr->{'fwknopd_cmdline'}) {
        if ($test_hr->{'fwknopd_cmdline'} =~ /fault\-injection\-tag\s(S+)/) {
            $tag_name = $1;
        }
    }

    if ($tag_name) {
        unless ($test_hr->{'detail'} =~ /\s$tag_name/) {
            &write_test_file(
                "[-] tag_name '$tag_name' not in test message.\n",
                $curr_test_file);
            return 0;
        }
    }

    if ($test_hr->{'pkt'}
            or ($test_hr->{'cmdline'} and $test_hr->{'fwknopd_cmdline'})) {

        ### we are testing the fwknopd server

        if ($test_hr->{'pkt'}) {
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
        } else {
            ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
                    = &client_server_interaction($test_hr, [], $USE_CLIENT);
        }

        $rv = 0 unless $server_was_stopped;

        if ($test_hr->{'server_positive_output_matches'}) {
            unless (&file_find_regex(
                    $test_hr->{'server_positive_output_matches'},
                    $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
                &write_test_file(
                    "[-] server_positive_output_matches not met, setting rv=0\n",
                    $curr_test_file);
                $rv = 0;
            }
        }

    } else {

        ### we are testing the fwknop client, server, or other command
        ### and expect an error
        $rv = not &run_cmd($test_hr->{'cmdline'}, $cmd_out_tmp, $curr_test_file);

        if ($test_hr->{'positive_output_matches'}) {
            unless (&file_find_regex(
                    $test_hr->{'positive_output_matches'},
                    $MATCH_ALL, $APPEND_RESULTS, $curr_test_file)) {
                &write_test_file(
                    "[-] positive_output_matches not met, setting rv=0\n",
                    $curr_test_file);
                $rv = 0;
            }
        }
    }

    return $rv;
}

sub fko_wrapper_exec() {
    my $test_hr = shift;

    my $make_arg = $test_hr->{'wrapper_compile'};

    $make_arg = 'asan' if $asan_mode;
    $make_arg = 'ubsan' if $ubsan_mode;

    if ($test_hr->{'wrapper_binary'} =~ m|/fko_wrapper$|) {
        if ($enable_fuzzing_interfaces_tests) {
            $make_arg = 'fuzzing';
            ### generate the fko-wrapper/fuzz_spa_payloads file
            ### if necessary - it is consumed by the wrapper in
            ### -DFUZZING_INTERFACES mode
            &write_test_file("[+] Generating SPA fuzzing packets " .
                "file: $fuzz_spa_payloads_file with ./spa_fuzzing.py...\n",
                $curr_test_file);
            unless (-e $fuzz_spa_payloads_file) {
                system "./spa_fuzzing.py > $fuzz_spa_payloads_file";
            }
        }
    }

    my $rv = &compile_wrapper($make_arg);

    if ($rv) {

        chdir $fko_wrapper_dir or die $!;

        my $iterations = $test_hr->{'fiu_iterations'};
        $iterations = 1 if $iterations < 1;  ### assume we want at least 1

        if ($test_hr->{'fiu_run'} == $YES) {
            my $lib_path = $lib_view_str;
            $lib_path =~ s|_PATH=|_PATH=../|; ### hack
            for (my $i=0; $i < $iterations; $i++) {
                &run_cmd("$lib_path $fiu_run_path -x " .
                    "-c '$test_hr->{'fiu_injection_style'}' $test_hr->{'wrapper_binary'}",
                    "../$cmd_out_tmp", $curr_test_file);
            }
        } else {
            &run_cmd("./$test_hr->{'wrapper_script'} $test_hr->{'wrapper_binary'}",
                "../$cmd_out_tmp", $curr_test_file);

            if ($test_hr->{'wrapper_script'} =~ /valgrind/) {
                $rv = 0 unless &valgrind_results($curr_test_file);
            }
        }

        chdir '..' or die $!;

        if ($test_hr->{'wrapper_binary'} =~ m|/fko_wrapper$|) {
            if ($enable_fuzzing_interfaces_tests) {
                ### make sure the send_spa_payloads file exists
                unless (-e $send_fuzz_payloads_file) {
                    &write_test_file("[+] Generating SPA fuzzing packets " .
                        "file: $send_fuzz_payloads_file for fwknopd consumption...\n",
                        $curr_test_file);
                    unless (-e $send_fuzz_payloads_file) {
                        system "grep PKT_ID $curr_test_file > $send_fuzz_payloads_file";
                    }
                }
            }
        }

        $rv = 0 if &is_crash($curr_test_file);

    } else {
        ### could not compile, so disable remaining fault injection
        ### "tag" tests
        push @tests_to_exclude, qr/fault\sinjection.*\stag\s/;
    }

    return $rv;
}

sub valgrind_results() {
    my $file = shift;

    my $rv = 1;

    $rv = 0 if &file_find_regex(
        [qr/definitely\slost\:\s[1-9]\d*\sbytes/],
        $MATCH_ALL, $APPEND_RESULTS, $file);
    $rv = 0 if &file_find_regex(
        [qr/indirectly\slost\:\s[1-9]\d*\sbytes/],
        $MATCH_ALL, $APPEND_RESULTS, $file);

    return $rv;
}

sub test_suite_conf_files() {
    my $make_file = '../Makefile.am';
    my $rv = 1;

    my %makefile_conf_files = ();
    my %makefile_test_scripts = ();

    unless (-e $make_file) {
        &write_test_file("[-] $make_file does not exist.\n",
            $curr_test_file);
        return 0;
    }

    open F, "< $make_file" or die $!;
    while (<F>) {
        if (m|conf/(\S+)|) {
            $makefile_conf_files{$1} = '';
        } elsif (m|test/tests/(\S+)|) {
            $makefile_test_scripts{$1} = '';
        }
    }
    close F;

    for my $f (glob("conf/*")) {
        next if -d $f;
        next unless $f =~ /\.conf/ or $f =~ /fwknop/;
        if ($f =~ m|$conf_dir/(\S+)|) {
            unless (defined $makefile_conf_files{$1}) {
                &write_test_file("[-] test suite conf file $1 not in $make_file.\n",
                    $curr_test_file);
                $rv = 0;
            }
        }
    }

    for my $f (glob("tests/*.pl")) {
        if ($f =~ m|tests/(\S+)|) {
            unless (defined $makefile_test_scripts{$1}) {
                &write_test_file("[-] test suite script file $1 not in $make_file.\n",
                    $curr_test_file);
                $rv = 0;
            }
        }
    }

    return $rv;
}

sub look_for_crashes() {
    my $rv = 1;

    for my $f (glob("$output_dir/*")) {

        next if -d $f;
        next unless $f =~ /\.test$/;

        ### only look for ASAN crashes in normal test files
        next if &file_find_regex([qr/ASAN.*crash\sverification/i],
                $MATCH_ALL, $NO_APPEND_RESULTS, $f);

        $rv = 0 if &is_crash($f);
    }

    $do_crash_check = 0;

    return $rv;
}

sub is_sanitizer_crash() {
    my $file = shift;

    my $rv = 0;

    if (&file_find_regex([qr/ERROR\:\s\w+Sanitizer/,
                qr/SUMMARY\:\s\w+Sanitizer/],
            $MATCH_ANY, $NO_APPEND_RESULTS, $file)) {
        &write_test_file("[-] Sanitizer crash found in: $file\n",
            $curr_test_file);
        $rv = 1;
    }

    return $rv;
}

sub is_crash() {
    my $file = shift;
    my $rv = 0;
    if (&file_find_regex([qr/segmentation\sfault/i, qr/core\sdumped/i],
            $MATCH_ANY, $NO_APPEND_RESULTS, $file)) {
        &write_test_file("[-] crash message found in: $file\n",
            $curr_test_file);
        $rv = 1;
    }

    $rv = 1 if &is_sanitizer_crash($file);

    ### ASan and valgrind don't appear to be compatible, and and ASan
    ### will throw an error when the two are mixed
    if (&file_find_regex([qr/Shadow memory range interleaves/],
            $MATCH_ANY, $NO_APPEND_RESULTS, $file)) {
        &write_test_file("[-] Sanitizer infrastructure not " .
                "compatible with valgrind: $file\n",
            $curr_test_file);
        $rv = 1;
    }

    return $rv;
}

sub config_recompile() {
    my $config_cmd = shift;

    my $rv = 1;

    &run_cmd('make clean', $cmd_out_tmp, $curr_test_file);

    if ($config_cmd) {
        &run_cmd($config_cmd, $cmd_out_tmp, $curr_test_file);
    }

    if ($sudo_path) {
        unless (&run_cmd("$sudo_path -u $username make",
                $cmd_out_tmp, $curr_test_file)) {
            $rv = 0 unless &run_cmd('make', $cmd_out_tmp,
                    $curr_test_file);
        }
    } else {
        $rv = 0 unless &run_cmd('make', $cmd_out_tmp,
            $curr_test_file);
    }

    unless ($rv) {
        ### override the failure if makeinfo is missing since this
        ### this doesn't affect run time operations
        if (&file_find_regex([qr/makeinfo.*is\smissing/], $MATCH_ALL,
                $NO_APPEND_RESULTS, $cmd_out_tmp)) {
            $rv = 1;
        }
    }

    return 1;
}

sub configure_args_restore_orig() {
    my $rv = 1;

    my $curr_pwd = cwd() or die $!;

    chdir '..' or die $!;

    unless (&config_recompile($orig_config_args)) {
        &write_test_file("[-] configure/recompile failure.\n",
            $curr_test_file);
        chdir $curr_pwd or die $!;
        $rv = 0;
    }

    chdir $curr_pwd or die $!;

    return $rv;
}

sub configure_args_disable_execvp() {
    my $rv = 1;

    my $curr_pwd = cwd() or die $!;

    chdir '..' or die $!;

    unless (&config_recompile('./extras/apparmor/configure_args.sh --disable-execvp')) {
        &write_test_file("[-] configure/recompile failure.\n",
            $curr_test_file);
        chdir $curr_pwd or die $!;
        $rv = 0;
    }

    chdir $curr_pwd or die $!;

    return $rv;
}

sub configure_args_udp_server_no_libpcap() {
    my $rv = 1;

    my $curr_pwd = cwd() or die $!;

    chdir '..' or die $!;

    unless (&config_recompile('./extras/apparmor/configure_args.sh --enable-udp-server')) {
        &write_test_file("[-] configure/recompile failure.\n",
            $curr_test_file);
        $rv = 0;
    }

    chdir $curr_pwd or die $!;

    &run_cmd("$lib_view_str $lib_view_cmd $fwknopdCmd", $cmd_out_tmp, $curr_test_file);

    if (&file_find_regex([qr/pcap/], $MATCH_ALL, $APPEND_RESULTS, $cmd_out_tmp)) {
        &write_test_file("[-] fwknopd appears to still link against libpcap.\n",
            $curr_test_file);
        $rv = 0;
    }

    return $rv;
}

sub code_structure_search_sources_for_non_ascii_chars() {

    my $rv = 1;

    for my $src_dir ('client', 'server', 'win32', 'common', 'lib') {
        next unless (glob("../$src_dir/*.c"))[0];
        &run_cmd($perl_path . q{ -lwne 'print "non-ascii char in $ARGV" and exit 0 if /[^\w\s\x20-\x7e]/' } . "../$src_dir/*.c",
            $cmd_out_tmp, $curr_test_file);
        next unless (glob("../$src_dir/*.h"))[0];
        &run_cmd($perl_path . q{ -lwne 'print "non-ascii char in $ARGV" and exit 0 if /[^\w\s\x20-\x7e]/' } . "../$src_dir/*.h",
            $cmd_out_tmp, $curr_test_file);
    }

    if (&file_find_regex(
            [qr/^non\-ascii/],
            $MATCH_ALL, $APPEND_RESULTS, $curr_test_file)) {
        &write_test_file(
            "[-] non-ascii char found in source file, setting rv=0\n",
            $curr_test_file);
        $rv = 0;
    }

    return $rv;
}

sub code_structure_fko_error_strings() {

    my $rv = 1;

    ### parse error codes from lib/fko.h and make sure each is handled in
    ### fko_errstr(), and that both the perl and python libfko extensions also
    ### handle each error code.

    for my $file ($libfko_hdr_file, $libfko_errstr_file,
            $perl_libfko_constants_file, $python_libfko_constants_file) {
        unless (-e $file) {
            &write_test_file("[-] file: $file does not exist.\n",
                $curr_test_file);
            return 0;
        }
    }

    ### this is a basic parser that relies on the current structure of fko.h
    my $found_starting_code = 0;
    my @fko_error_codes = ();
    my $starting_code = 'FKO_SUCCESS';
    open F, "< $libfko_hdr_file" or die "[*] Could not open $libfko_hdr_file: $!";
    while (<F>) {
        if (/$starting_code\s=\s0/) {
            $found_starting_code = 1;
            push @fko_error_codes, $starting_code;
            next;
        }
        next unless $found_starting_code;
        if (/^\s{4}([A-Z]\S+),/) {
            push @fko_error_codes, $1;
        }
        last if $found_starting_code and /^\}\sfko_error_codes_t\;/;
    }
    close F;

    ### now make sure that lib/fko_error.c has an error string for each code
    ### in order
    my $found_errstr_func  = 0;
    my $expected_var_index = 0;
    my $prev_var = $fko_error_codes[0];
    open F, "< $libfko_errstr_file" or die "[*] Could not open $libfko_errstr_file: $!";
    while (<F>) {
        if (/^fko_errstr\(/) {
            $found_errstr_func = 1;
            next;
        }
        next unless $found_errstr_func;
        if (/^\s+case\s(\S+)\:/) {
            my $var_str = $1;
            if ($fko_error_codes[$expected_var_index] eq 'GPGME_ERR_START') {
                $expected_var_index++;
            }
            if ($fko_error_codes[$expected_var_index] eq $var_str) {
                $expected_var_index++;
                $prev_var = $var_str;
            } else {
                &write_test_file("[-] $libfko_errstr_file: expected var $fko_error_codes[$expected_var_index] " .
                    "in position: $expected_var_index in fko_errstr(), previous var: $prev_var\n",
                    $curr_test_file);
                $rv = 0;
                last;
            }
        }
        last if $found_errstr_func and /^\}/;

    }
    close F;

    ### validate perl error code constants
    $expected_var_index = 0;
    $prev_var = $fko_error_codes[0];
    my $found_err_code_arr = 0;
    open F, "< $perl_libfko_constants_file" or die "[*] Could not open $perl_libfko_constants_file: $!";
    while (<F>) {
        if (/our\s\@ERROR_CODES\s=/) {
            $found_err_code_arr = 1;
            next;
        }
        next unless $found_err_code_arr;
        if (/^\s{4}(\S+)/) {
            my $var_str = $1;
            if ($fko_error_codes[$expected_var_index] eq $var_str) {
                $expected_var_index++;
                $prev_var = $var_str;
            } else {
                &write_test_file("[-] $perl_libfko_constants_file: perl FKO module - " .
                    "expected var $fko_error_codes[$expected_var_index] " .
                    "at position: $expected_var_index in ERROR_CODES array, previous var: $prev_var\n",
                    $curr_test_file);
                $rv = 0;
                last;
            }
        }
        last if $found_err_code_arr and /^\)\;/;
    }
    close F;

    ### same thing, but now validate 'use constant' values too
    $expected_var_index = 0;
    $prev_var = $fko_error_codes[0];
    my $found_use_constant = 0;
    my $found_fko_success = 0;
    open F, "< $perl_libfko_constants_file" or die "[*] Could not open $perl_libfko_constants_file: $!";
    while (<F>) {
        if (/^use\sconstant\s\{/) {
            $found_use_constant = 1;
            next;
        }
        next unless $found_use_constant;
        if (/^\s{4}$starting_code\s+=\>\s(\d+),/) {
            my $val = $1;
            unless ($fko_error_codes[$val] eq $starting_code) {
                &write_test_file("[-] $perl_libfko_constants_file: perl FKO module " .
                    "- expected var $starting_code " .
                    "value of zero, got $val\n", $curr_test_file);
                $rv = 0;
                last;
            }
            $found_fko_success = 1;
        }
        next unless $found_fko_success;
        if (/^\s{4}([A-Z]\S+)\s+=\>\s(\d+),/) {
            my $var_str = $1;
            my $val     = $2;
            if ($fko_error_codes[$val] eq $var_str) {
                $expected_var_index++;
                $prev_var = $var_str;
            } else {
                &write_test_file("[-] $perl_libfko_constants_file: perl FKO module " .
                    "- expected var $fko_error_codes[$expected_var_index] " .
                    "in position: $expected_var_index in 'use constants' definition, previous var: $prev_var\n",
                    $curr_test_file);
                $rv = 0;
                last;
            }
        }
        last if $found_fko_success and /^\)\;/;
    }
    close F;

    ### validate python error code constants
    $expected_var_index = 0;
    $prev_var = $fko_error_codes[0];
    $found_use_constant = 0;
    $found_fko_success = 0;
    open F, "< $python_libfko_constants_file" or die "[*] Could not open $python_libfko_constants_file: $!";
    while (<F>) {
        if (/^$starting_code\s=\s0/) {
            $found_fko_success = 1;
            next;
        }
        next unless $found_fko_success;
        if (/^([A-Z]\S+)\s=\s(\d+)/) {
            my $var_str = $1;
            my $val     = $2;
            if ($fko_error_codes[$val] eq $var_str) {
                $expected_var_index++;
                $prev_var = $var_str;
            } else {
                &write_test_file("[-] python extension - expected var $fko_error_codes[$expected_var_index] " .
                    "in position: $expected_var_index in FKO constants section, previous var: $prev_var\n",
                    $curr_test_file);
                $rv = 0;
                last;
            }
        }
        last if $found_fko_success and /^\s/;
    }
    close F;

    return $rv;
}

sub make_distcheck() {

    ### 'make clean' as root
    return 0 unless &run_cmd('make -C .. distcheck',
        $cmd_out_tmp, $curr_test_file);

    return 1 if &file_find_regex([qr/archives\sready\sfor\sdistribution/],
        $MATCH_ALL, $APPEND_RESULTS, $curr_test_file);

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
            $MATCH_ALL, $APPEND_RESULTS, $curr_test_file);
    }
    return 0;
}

sub write_rc_file() {
    my ($rc_hr, $rc_file) = @_;

    open RC, "> $rc_file"
        or die "[*] Could not open $rc_file: $!";
    for my $hr (@$rc_hr) {
        print RC "[$hr->{'name'}]\n";
        for my $var (keys %{$hr->{'vars'}}) {
            print RC "$var      $hr->{'vars'}->{$var}\n";
        }
    }
    print RC "#\n"; ### to max code coverage
    close RC;

    return;
}

sub cunit_tests() {
    my $test_hr = shift;

    my $rv = 1;

    &run_cmd("$lib_view_str $valgrind_str" . $test_hr->{'cmdline'},
            $cmd_out_tmp, $curr_test_file);
    if ($test_hr->{'negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'negative_output_matches'},
            $MATCH_ANY, $APPEND_RESULTS, $curr_test_file);
    }
return $rv

}

sub server_start_stop_cycle() {
    my $test_hr = shift;

    my $rv = 1;

    &write_test_file("[+] TEST: " . &get_msg($test_hr) . "\n",
        $server_test_file);

    &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd $default_server_conf_args -S",
            $cmd_out_tmp, $curr_test_file);
    &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd $default_server_conf_args -K",
            $cmd_out_tmp, $curr_test_file);
    &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd $default_server_conf_args -R",
            $cmd_out_tmp, $curr_test_file);

    ### send additional signals for code coverage
    for my $sig_name (@sigs_ordered) {
        my $sig = $sigs{$sig_name};

        &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd $default_server_conf_args " .
            "-i $loopback_intf $verbose_str",
            $cmd_out_tmp, $curr_test_file);

        sleep 1;
        open F, "< $default_pid_file" or
            die "[*] Could not open $default_pid_file: $!";
        my $pid = <F>;
        close F;
        chomp $pid;

        if (kill 0, $pid) {
            &write_test_file(
                "[+] Sending daemonized fwknopd PID: $pid signal: $sig_name($sig)\n",
                $curr_test_file);
            kill $sig, $pid;

            sleep 1;

            if (kill 0, $pid) {
                &run_cmd(
                    "$lib_view_str $valgrind_str $fwknopdCmd $default_server_conf_args -K",
                    $cmd_out_tmp, $curr_test_file);
            }
        } else {
            &write_test_file(
                "[-] Daemonized fwknopd PID: $pid not running?\n",
                $curr_test_file);
        }
    }

    &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd $default_server_conf_args -S",
            $cmd_out_tmp, $curr_test_file);
    &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd $default_server_conf_args -K",
            $cmd_out_tmp, $curr_test_file);

    ### now send the signals against a non-daemon fwknopd process
    for my $sig_name (@sigs_ordered) {
        my $sig = $sigs{$sig_name};

        &do_fwknopd_cmd("$lib_view_str $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args -i $loopback_intf -f");

        open F, "< $default_pid_file" or
            die "[*] Could not open $default_pid_file: $!";
        my $pid = <F>;
        close F;
        chomp $pid;

        if (kill 0, $pid) {
            &write_test_file(
                "[+] Sending foreground fwknopd PID: $pid signal: $sig_name($sig)\n",
                $curr_test_file);
            kill $sig, $pid;
            sleep 1;

            if (kill 0, $pid) {
                &run_cmd(
                    "$lib_view_str $valgrind_str $fwknopdCmd $default_server_conf_args -K",
                    $cmd_out_tmp, $curr_test_file);
            }
        } else {
            &write_test_file(
                "[-] Foreground fwknopd PID: $pid not running?\n",
                $curr_test_file);
        }
    }

    return $rv;
}

sub server_conf_files() {
    my $test_hr = shift;

    my $rv = 1;

    if ($test_hr->{'digest_cache_file'}) {
        &write_server_conf_file($test_hr->{'digest_cache_file'},
            $rewrite_digest_file);
    }

    if ($test_hr->{'server_access_file'}) {
        if ($test_hr->{'sudo_user_group_mismatch'} eq $YES) {
            push @{$test_hr->{'server_access_file'}},
                "CMD_SUDO_EXEC_USER      $username";
            push @{$test_hr->{'server_access_file'}},
                "CMD_SUDO_EXEC_GROUP     root";
        }
        if ($test_hr->{'user_group_mismatch'} eq $YES) {
            push @{$test_hr->{'server_access_file'}},
                "CMD_EXEC_USER      $username";
            push @{$test_hr->{'server_access_file'}},
                "CMD_EXEC_GROUP     root";
        }
        &write_server_conf_file($test_hr->{'server_access_file'},
            $rewrite_access_conf);
    }

    if ($test_hr->{'server_include_keys_access_file'}) {
        &write_server_conf_file($test_hr->{'server_include_keys_access_file'},
            $rewrite_include_keys_access_conf);
    }

    if ($test_hr->{'server_conf_file'}) {
        &write_server_conf_file($test_hr->{'server_conf_file'},
            $rewrite_fwknopd_conf);
    }

    $rv = 0 unless &run_cmd($test_hr->{'fwknopd_cmdline'},
            $cmd_out_tmp, $curr_test_file);

    if ($rv == 0) {
        $rv = 1 if $test_hr->{'exec_err'} eq $YES;
    }

    if ($test_hr->{'positive_output_matches'}) {
        unless (&file_find_regex(
                $test_hr->{'positive_output_matches'},
                $MATCH_ALL, $APPEND_RESULTS, $curr_test_file)) {
            &write_test_file(
                "[-] positive_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    if ($test_hr->{'negative_output_matches'}) {
        if (&file_find_regex(
                $test_hr->{'negative_output_matches'},
                $MATCH_ANY, $APPEND_RESULTS, $curr_test_file)) {
            &write_test_file(
                "[-] negative_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    return $rv;
}

sub write_server_conf_file() {
    my ($lines_ar, $file) = @_;

    open F, "> $file"
        or die "[*] Could not open $file $!";
    &write_test_file("[+] write_server_conf_file(): $file\n", $curr_test_file);
    for my $line (@$lines_ar) {
        &write_test_file("$line\n", $curr_test_file);
        print F $line, "\n";
    }
    close F;

    return;
}

sub client_rc_file() {
    my $test_hr = shift;

    my $rv = 1;
    my $rc_file = '';

    if ($test_hr->{'write_rc_file'}) {
        &write_rc_file($test_hr->{'write_rc_file'}, $rewrite_rc_file);
        $rc_file = $rewrite_rc_file;
    } elsif ($test_hr->{'save_rc_stanza'}) {
        &write_rc_file($test_hr->{'save_rc_stanza'}, $save_rc_file);
        $rc_file = $save_rc_file;
    } else {
        &write_test_file(
            "[-] test hash does not include 'write_rc_file' or 'save_rc_stanza'\n",
            $curr_test_file);
        return 0;
    }

    if ($test_hr->{'client_popen'}) {
        $rv = &popen_cmd($test_hr, $cmd_out_tmp, $curr_test_file);
    } else {
        $rv = 0 unless &run_cmd($test_hr->{'cmdline'},
                $cmd_out_tmp, $curr_test_file);
    }
    if ($rv == 0) {
        $rv = 1 if $test_hr->{'exec_err'} eq $YES;
    }

    unless ($test_hr->{'cmdline'} =~ /key\-gen/ or $test_hr->{'cmdline'} =~ /\-k/
            or $test_hr->{'exec_err'} eq $YES) {
        $rv = 0 unless &file_find_regex([qr/Final\sSPA\sData/i],
            $MATCH_ALL, $NO_APPEND_RESULTS, $curr_test_file);
    }

    if ($test_hr->{'positive_output_matches'}) {
        unless (&file_find_regex(
                $test_hr->{'positive_output_matches'},
                $MATCH_ALL, $APPEND_RESULTS, $curr_test_file)) {
            &write_test_file(
                "[-] positive_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    if ($test_hr->{'negative_output_matches'}) {
        if (&file_find_regex(
                $test_hr->{'negative_output_matches'},
                $MATCH_ANY, $APPEND_RESULTS, $curr_test_file)) {
            &write_test_file(
                "[-] negative_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    unless (&validate_fko_decode()) {
        &write_test_file(
            "[-] validate_fko_decode() returned zero, setting rv=0\n",
            $curr_test_file);
        $rv = 0;
    }

    if ($test_hr->{'rc_positive_output_matches'}) {
        unless (&file_find_regex(
                $test_hr->{'rc_positive_output_matches'},
                $MATCH_ALL, $NO_APPEND_RESULTS, $rc_file)) {
            &write_test_file(
                "[-] rc_positive_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    if ($test_hr->{'rc_negative_output_matches'}) {
        if (&file_find_regex(
                $test_hr->{'rc_negative_output_matches'},
                $MATCH_ANY, $NO_APPEND_RESULTS, $rc_file)) {
            &write_test_file(
                "[-] rc_negative_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    return $rv;
}

sub validate_fko_decode() {

    return 0 unless -e $curr_test_file;

    ### make sure that the before and after FKO decode
    ### sections are the same - this ensures that libfko
    ### encoding / decoding cycles match up

    my @before_lines = ();
    my @after_lines  = ();

    my $found_fko_field_values = 0;
    my $finished_first_section = 0;
    open F, "< $curr_test_file"
        or die "[*] Could not open $curr_test_file: $!";
    while (<F>) {
        if (/^FKO\sField\sValues/) {
            $found_fko_field_values = 1;
            next;
        }
        next unless $found_fko_field_values;
        if (/Final\sSPA\sData/) {
            $found_fko_field_values = 0;
            last if $finished_first_section;
            $finished_first_section = 1;
        }
        if ($found_fko_field_values) {
            if ($finished_first_section) {
                push @after_lines, $_ if $_ =~ /\S/;
            } else {
                push @before_lines, $_ if $_ =~ /\S/;
            }
        }
    }
    close F;

    my $found_difference = 0;
    for (my $i=0; $i < $#before_lines; $i++) {
        unless (defined $after_lines[$i]) {
            $found_difference = 1;
            last;
        }
        if ($before_lines[$i] ne $after_lines[$i]) {
            chomp $before_lines[$i];
            chomp $after_lines[$i];
            &write_test_file(
                "[-] Line mismatch, before '$before_lines[$i]', after '$after_lines[$i]'\n",
                $curr_test_file);
            $found_difference = 1;
        }
    }

    if ($found_difference) {
        return 0;
    }
    return 1;
}

sub insert_dupe_rule() {
    my $test_hr = shift;

    ### insert duplicate rules
    my ($prv, $lib_path, $fwknopd_conf, $access_conf)
             = &parse_fwknopd_cmdline($test_hr);

    return unless $prv;

    &write_test_file("[+] Policy before inserting duplicate rules:\n",
        $curr_test_file);
    &run_cmd("LD_LIBRARY_PATH=$lib_path $fwknopdCmd -c " .
        "$fwknopd_conf -a $access_conf --fw-list",
        $cmd_out_tmp, $curr_test_file);
    my $time_now = time();
    for (my $i=0; $i < 15; $i++) {
        my $time_prefix = '_exp_' . ($time_now + 45+$i); ### default timeout
        &write_test_file("[+] Inserting duplicate rule with expire comment: $time_prefix\n",
            $curr_test_file);
        if ($test_hr->{'fw_dupe_rule_args'}) {
            for my $fw_args (@{$test_hr->{'fw_dupe_rule_args'}}) {
                my $cp = $fw_args;
                if ($cp =~ /EXP_TIME/) {
                    $cp =~ s/EXP_TIME/$time_prefix/;
                }
                &run_cmd("$fw_bin_and_prefix $cp",
                    $cmd_out_tmp, $curr_test_file);
            }
        } else {
            ### assume SSH
            &run_cmd("$fw_bin_and_prefix -A FWKNOP_INPUT -p 6 -s $fake_ip -d 0.0.0.0/0 " .
                "--dport 22 -m comment --comment $time_prefix -j ACCEPT",
                $cmd_out_tmp, $curr_test_file);
        }
    }
    &write_test_file("[+] Policy after inserting duplicate rules:\n",
        $curr_test_file);
    &run_cmd("LD_LIBRARY_PATH=$lib_path $fwknopdCmd -c " .
        "$fwknopd_conf -a $access_conf --fw-list",
        $cmd_out_tmp, $curr_test_file);

    &cache_fw_policy($cmd_out_tmp);

until($time_now + 44 < time()) {
sleep 1;
}
    return;
}

sub client_send_spa_packet() {
    my $test_hr = shift;
    my $client_cycles = 1;
    $client_cycles = $test_hr->{'client_cycles_per_server_instance'}
        if $test_hr->{'client_cycles_per_server_instance'} > 0;
    return &_client_send_spa_packet($test_hr, $client_cycles, $SERVER_RECEIVE_CHECK);
}

sub _client_send_spa_packet() {
    my ($test_hr, $cycle_ctr, $server_receive_check) = @_;

    my $rv = 1;

    if ($test_hr->{'get_key'}) {
        &write_key($test_hr->{'get_key'}->{'key'},
            $test_hr->{'get_key'}->{'file'});
    } else {
        &write_key($default_key, $local_key_file);
    }

    if ($test_hr->{'get_hmac_key'}) {
        &write_key($test_hr->{'get_hmac_key'}->{'key'},
            $test_hr->{'get_hmac_key'}->{'file'});
    } else {
        &write_key($default_key, $local_key_file);
    }

    if (-e $server_cmd_tmp) {

        my $tries = 0;
        my $quickcount = 0;
        my $nummatches = 0;
        for (;;) {
            $rv = 1;
            $tries++;

            ### default stanza regex match
            my $server_receive_re = qr/stanza\s.*\sSPA Packet from IP/;

            $server_receive_re = $test_hr->{'server_receive_re'}
                if $test_hr->{'server_receive_re'};

            my $matches = &file_find_num_matches($server_receive_re,
                $NO_APPEND_RESULTS, $server_cmd_tmp);

            if ($test_hr->{'weak_server_receive_check'}) {
                last if $matches > 0;
            } else {
                last if $matches == $cycle_ctr+1;
            }

            &write_test_file("[.] client_send_spa_packet() " .
                "executing client and looking for fwknopd receiving " .
                "packet, try: $tries\n",
                $curr_test_file);

            ### run the client
            if ($test_hr->{'multi_cmds'}) {
                for my $cmd (@{$test_hr->{'multi_cmds'}}) {
                    $rv = 0 unless &run_cmd($cmd,
                            $cmd_out_tmp, $curr_test_file);
                }
            } else {
                $rv = 0 unless &run_cmd($test_hr->{'cmdline'},
                        $cmd_out_tmp, $curr_test_file);
            }

            $quickcount = 0;
            $nummatches = 0;
            $nummatches = &file_find_num_matches(qr/Final\sSPA\sData/, $NO_APPEND_RESULTS, $server_cmd_tmp);
            while ($nummatches < 1 && $quickcount < 10 ) {
                print ".";
                precise_sleep(.5);
                $quickcount++;
                $nummatches = &file_find_num_matches(qr/Final\sSPA\sData/, $NO_APPEND_RESULTS, $server_cmd_tmp);
            };

            if ($test_hr->{'relax_receive_cycle_num_check'}) {
                $rv = 0 unless &file_find_regex([qr/Final\sSPA\sData/],
                    $MATCH_ALL, $NO_APPEND_RESULTS, $curr_test_file);
            } else {
                $rv = 0 unless (&file_find_num_matches(qr/Final\sSPA\sData/,
                    $NO_APPEND_RESULTS, $server_cmd_tmp) > 0) || (&file_find_num_matches(qr/SPA\sPacket\sfrom\sIP:/,
                    $NO_APPEND_RESULTS, $server_cmd_tmp) > 0) || (&file_find_num_matches(qr/SPA\sdata:/,
                    $NO_APPEND_RESULTS, $server_cmd_tmp) > 0);
            }

            last if $server_receive_check == $NO_SERVER_RECEIVE_CHECK;
            if ($test_hr->{'client_pkt_tries'} > 0) {
                last if $tries == $test_hr->{'client_pkt_tries'};
            } else {
                last if $tries == 10;
            }
            sleep 1;
        }
    } else {
        &write_test_file("[.] client_send_spa_packet() " .
            "server tmp file $server_cmd_tmp does not exist.\n",
            $curr_test_file);

        ### run the client
        if ($test_hr->{'multi_cmds'}) {
            for my $cmd (@{$test_hr->{'multi_cmds'}}) {
                $rv = 0 unless &run_cmd($cmd,
                        $cmd_out_tmp, $curr_test_file);
            }
        } else {
            $rv = 0 unless &run_cmd($test_hr->{'cmdline'},
                    $cmd_out_tmp, $curr_test_file);
        }
        $rv = 0 unless &file_find_regex([qr/Final\sSPA\sData/i],
            $MATCH_ALL, $NO_APPEND_RESULTS, $curr_test_file);
    }

    unless ($server_receive_check == $NO_SERVER_RECEIVE_CHECK) {
        if ($rv) {
            &write_test_file("[+] fwknopd received SPA packet.\n",
                $curr_test_file);
        } else {
            &write_test_file("[-] fwknopd did not receive SPA packet.\n",
                $curr_test_file);
        }
    }

    if ($enable_openssl_compatibility_tests) {

        ### extract the SPA packet from the cmd tmp file
        my $encoded_msg = '';
        my $digest = '';
        my $enc_mode = 0;
        my $is_hmac_type = 1;
        my $hmac_digest = '';
        my $hmac_mode = 'sha256';
        open SPA, "< $cmd_out_tmp" or die $!;
        while (<SPA>) {
            if (/^\s+Encoded\sData\:\s+(\S+)/) {
                $encoded_msg = $1;
            } elsif (/Data\sDigest\:\s(\S+)/) {
                $digest = $1;
            } elsif (/Encryption\sMode\:\s+(\d+)/) {
                $enc_mode = $1;
            } elsif (/^\s+HMAC\:\s\<NULL\>/) {
                $is_hmac_type = 0;
            } elsif (/^\s+HMAC\:\s(\S+)/) {
                $hmac_digest = $1;
            } elsif (/^\s+HMAC\sType\:\s\d+\s\((\S+)\)/) {
                $hmac_mode = lc($1);
            }
        }
        close SPA;

        $encoded_msg .= ":$digest";

        my $ssl_test_flag = $REQUIRE_SUCCESS;
        $ssl_test_flag = $REQUIRE_FAILURE if $enc_mode != 2;  ### CBC mode
        $ssl_test_flag = $REQUIRE_FAILURE if $is_hmac_type;

        my $encrypted_msg = &get_spa_packet_from_file($cmd_out_tmp);

        my $key = '';
        my $hmac_key = '';
        my $num_hmac_keys = 0;
        my $b64_decode_key = 0;
        if ($test_hr->{'key_file'}) {
            open K, "< $test_hr->{'key_file'}" or die $!;
            while (<K>) {
                if (/^KEY_BASE64\:?\s+(\S+)/) {
                    $key = $1;
                    $b64_decode_key = 1;
                } elsif (/^KEY\:?\s+(\S+)/) {
                    $key = $1;
                } elsif (/^HMAC_KEY_BASE64\:?\s+(\S+)/) {
                    $hmac_key = $1;
                    $b64_decode_key = 1;
                    $num_hmac_keys++;
                } elsif (/^HMAC_KEY\:?\s+(\S+)/) {
                    $hmac_key = $1;
                    $num_hmac_keys++;
                }
            }
            close K;
        }
        $key = $default_key unless $key;

        unless (&openssl_enc_verification($encrypted_msg,
                $encoded_msg, '', $key, $b64_decode_key,
                $ssl_test_flag)) {
            $rv = 0;
        }

        if ($is_hmac_type and $hmac_key) {
            my $enc_mode = $ENC_RIJNDAEL;
            $enc_mode = $ENC_GPG if $test_hr->{'msg'} =~ /gpg/i
                    or $test_hr->{'msg'} =~ /gnupg/i;
            if ($num_hmac_keys == 1) {
                unless (&openssl_hmac_verification($encrypted_msg,
                        $encoded_msg, '', $hmac_key, $b64_decode_key,
                        $hmac_digest, $hmac_mode, $enc_mode, 0)) {
                    $rv = 0;
                }
            } else { #Try for each of the keys
                my $found_success = 0;
                open K, "< $test_hr->{'key_file'}" or die $!;
                while (<K>) {
                    if (/^HMAC_KEY_BASE64\:?\s+(\S+)/) {
                        $hmac_key = $1;
                        $b64_decode_key = 1;
                        if (&openssl_hmac_verification($encrypted_msg,
                                $encoded_msg, '', $hmac_key, $b64_decode_key,
                                $hmac_digest, $hmac_mode, $enc_mode, 1)) {
                            $found_success = 1;
                        }
                    } elsif (/^HMAC_KEY\:?\s+(\S+)/) {
                        $hmac_key = $1;
                        if (&openssl_hmac_verification($encrypted_msg,
                                $encoded_msg, '', $hmac_key, $b64_decode_key,
                                $hmac_digest, $hmac_mode, $enc_mode, 1)) {
                            $found_success = 1;
                        }
                    }
                }
                close K;
                if (!$found_success) {
                    $rv = 0;
                }
            }
        }
    }

    &write_test_file("[.] client_send_spa_packet() rv: $rv\n",
        $curr_test_file);

    return $rv;
}

sub permissions_check() {
    my $test_hr = shift;

    for my $f (keys %cf) {
        next unless -f $cf{$f};
        chmod 0777, $cf{$f} or die $!;
    }

    my $rv = &spa_cycle($test_hr);

    for my $f (keys %cf) {
        next unless -f $cf{$f};
        chmod 0600, $cf{$f} or die $!;
    }

    return $rv;
}

sub rotate_digest_file() {
    my $test_hr = shift;
    my $rv = 1;

    unless (-e $default_digest_file) {
        open DIGEST, "> $default_digest_file"
            or die "[*] Could not open $default_digest_file: $!";
        print DIGEST "# <digest> <proto> <src_ip> "
            . "<src_port> <dst_ip> <dst_port> <time>\n";
        close DIGEST;
    }

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

sub use_terminal_run_client() {
    my $test_hr = shift;

    return &run_cmd($test_hr->{'cmdline'}, $cmd_out_tmp, $curr_test_file);
}

sub predef_pkts_spa_cycle() {
    my $test_hr = shift;

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => $test_hr->{'pkt'},
        },
    );

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
            = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    $rv = 0 unless &process_output_matches($test_hr);

    return $rv;
}

sub spa_cycle() {
    my $test_hr = shift;

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
            = &client_server_interaction($test_hr, [], $USE_CLIENT);

    $rv = 0 unless &process_output_matches($test_hr);

    return $rv;
}

sub tcp_spa_cycle() {
    my $test_hr = shift;

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
            = &client_server_interaction($test_hr, [], $USE_CLIENT);
    if (!$rv) {
        $rv = 1;
        #start netcat listening on tcp/62201
        system("nc -k -l 62201 > /dev/null 2>&1 &");
        my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
                = &client_server_interaction($test_hr, [], $USE_CLIENT);

        #stop netcat
        system("killall nc");
}
    $rv = 0 unless &process_output_matches($test_hr);

    return $rv;
}

sub iptables_no_flush_init_exit() {
    my $test_hr = shift;

    my $rv = 1;

    &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd " .
        "$default_server_conf_args --fw-flush $verbose_str",
        $cmd_out_tmp, $curr_test_file);

    if ($test_hr->{'insert_rule_before_exec'}) {
        ### first create the fwknop chains and add a rule, then check for
        ### this rule to either not be deleted at init or exit
        &run_cmd("iptables -N FWKNOP_INPUT", $cmd_out_tmp, $curr_test_file);
        &run_cmd("iptables -A FWKNOP_INPUT -p tcp -s $fake_ip --dport 1234 -j ACCEPT",
            $cmd_out_tmp, $curr_test_file);
    }

    $rv = &spa_cycle($test_hr);

    if ($test_hr->{'search_for_rule_after_exit'}) {
        &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd " .
            "$default_server_conf_args --fw-list $verbose_str",
            $cmd_out_tmp, $curr_test_file);
        $rv = 0 unless &file_find_regex([qr/ACCEPT.*$fake_ip\s.*dpt\:1234/],
            $MATCH_ALL, $APPEND_RESULTS, $curr_test_file);
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
            push @tests_to_exclude, qr/gpg/i;
            push @tests_to_exclude, qr/gnupg/i;
            $pinentry_fail = 1;
        }
    } else {
        die "[*] Could not run the fwknop client: $!" unless defined $pid;
        exec qq{$test_hr->{'cmdline'} > /dev/null 2>&1 };
    }

    return $rv;
}

sub python_fko_compile_install() {
    my $test_hr = shift;

    my $rv = 1;

    if (-d $python_fko_dir) {
        rmtree $python_fko_dir or die $!;
    }
    mkdir $python_fko_dir or die "[*] Could not mkdir $python_fko_dir: $!";

    my $curr_pwd = cwd() or die $!;

    chdir '../python' or die $!;

    &run_cmd("$python_path setup.py build", $cmd_out_tmp,
        "../test/$curr_test_file");
    &run_cmd("$python_path setup.py install --prefix=../test/$python_fko_dir",
        $cmd_out_tmp, "../test/$curr_test_file");

    if (&file_find_regex(
            [qr/fatal\serror.*Python\.h/],
            $MATCH_ALL, $APPEND_RESULTS, "../test/$curr_test_file")) {
        ### python-devel is missing, disable all python tests
        push @tests_to_exclude, qr/python/;
        $rv = 0;
    }


    chdir $curr_pwd or die $!;

    return $rv;
}

sub python_fko_basic_exec() {
    my $test_hr = shift;

    my $rv = 1;

    my $site_dir = "$python_fko_dir/lib";

    unless (-d $site_dir) {
        $site_dir = "$python_fko_dir/lib64";
        unless (-d $site_dir) {
            &write_test_file("[-] $site_dir directory dir does not exist.\n",
                $curr_test_file);
            return 0;
        }
    }

    for my $dir (glob("$site_dir/python*")) {
        $site_dir = $dir;
        last;
    }
    $site_dir .= '/site-packages';

    unless (-d $site_dir) {
        &write_test_file("[-] $site_dir directory dir does not exist.\n",
            $curr_test_file);
        return 0;
    }

    $rv = &run_cmd("$lib_view_str " .
        "PYTHONPATH=$site_dir $python_path ./$python_script",
        $cmd_out_tmp, $curr_test_file);

    if ($rv) {

        $python_spa_packet = '';

        ### get the SPA packet data
        open GSPA, "< $curr_test_file" or die $!;
        while (<GSPA>) {
            if (/SPA\spacket\sdata\:\s(\S+)/) {
                $python_spa_packet = $1;
                last;
            }
        }
        close GSPA;

        unless ($python_spa_packet) {
            &write_test_file("[-] could not acquite SPA packet from python output\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    return $rv;
}

sub python_fko_client_to_C_server() {
    my $test_hr = shift;

    my @packets = (
        {
            'proto'  => 'udp',
            'port'   => $default_spa_port,
            'dst_ip' => $loopback_ip,
            'data'   => $python_spa_packet,
        },
    );

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

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

    &run_cmd("$perl_path Makefile.PL PREFIX=../../test/$perl_mod_fko_dir " .
        "LIB=../../test/$perl_mod_fko_dir", $cmd_out_tmp,
        "../../test/$curr_test_file");

    &run_cmd('make', $cmd_out_tmp, "../../test/$curr_test_file");

    if (&file_find_regex([qr/rerun\sthe\smake\scommand/],
            $MATCH_ALL, $APPEND_RESULTS, "../../test/$curr_test_file")) {
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

sub perl_fko_module_make_test() {
    my $test_hr = shift;

    my $rv = 1;

    my $curr_pwd = cwd() or die $!;

    chdir '../perl/FKO' or die $!;

    my $lib_path_cp = $lib_view_str;

    ### fix up relative path for lib directory
    $lib_path_cp =~ s|\.\./|../../|g;

    &run_cmd("$lib_path_cp make test", $cmd_out_tmp, "../../test/$curr_test_file");

    chdir $curr_pwd or die $!;

    if ($test_hr->{'positive_output_matches'}) {
        unless (&file_find_regex(
                $test_hr->{'positive_output_matches'},
                $MATCH_ALL, $APPEND_RESULTS, $curr_test_file)) {
            &write_test_file(
                "[-] positive_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    return $rv;
}

sub perl_fko_module_make_test_valgrind() {
    my $test_hr = shift;

    my $rv = 1;

    my $curr_pwd = cwd() or die $!;

    chdir '../perl/FKO' or die $!;

    &run_cmd("$prove_path --exec 'perl -Iblib/lib -Iblib/arch -M$cpan_valgrind_mod' t/*.t",
        $cmd_out_tmp, "../../test/$curr_test_file");

    chdir $curr_pwd or die $!;

    if ($test_hr->{'positive_output_matches'}) {
        unless (&file_find_regex(
                $test_hr->{'positive_output_matches'},
                $MATCH_ALL, $APPEND_RESULTS, $curr_test_file)) {
            &write_test_file(
                "[-] positive_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    if ($test_hr->{'negative_output_matches'}) {
        if (&file_find_regex(
                $test_hr->{'negative_output_matches'},
                $MATCH_ANY, $APPEND_RESULTS, $curr_test_file)) {
            &write_test_file(
                "[-] negative_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
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

    my $fko_username = $fko_obj->username();

    if ($fko_username) {
        &write_test_file("[+] got username(): $fko_username\n",
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

sub perl_fko_module_long_keys() {
    my $test_hr = shift;

    my $rv = 1;

    for my $msg (@{valid_access_messages()}) {
        for my $key (@{fuzzing_encryption_keys()}) {

            $fko_obj = FKO->new();

            unless ($fko_obj) {
                &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                    $curr_test_file);
                return 0;
            }

            ### set message and then encrypt
            my $status = $fko_obj->spa_message($msg);

            $status = $fko_obj->spa_data_final($key, '');

            if ($status == FKO->FKO_SUCCESS) {
                &write_test_file("[-] Accepted fuzzing key '$key' for $msg\n",
                    $curr_test_file);
                $rv = 0;
                $fko_obj->destroy();
                last;
            } else {
                &write_test_file("[+] Rejected fuzzing key '$key' for $msg: " .
                    FKO::error_str() . "\n",
                    $curr_test_file);
            }
            $fko_obj->destroy();
        }
    }

    return $rv;
}

sub perl_fko_module_long_hmac_keys() {
    my $test_hr = shift;

    my $rv = 1;

    for my $msg (@{valid_access_messages()}) {
        for my $hmac_type (@{valid_spa_hmac_types()}) {
            for my $hmac_key (@{fuzzing_hmac_keys()}) {

                $fko_obj = FKO->new();

                unless ($fko_obj) {
                    &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                        $curr_test_file);
                    return 0;
                }

                ### set message and then encrypt
                my $status = $fko_obj->spa_message($msg);
                $fko_obj->hmac_type($hmac_type);

                $status = $fko_obj->spa_data_final($enc_dummy_key, $hmac_key);

                if ($status == FKO->FKO_SUCCESS) {
                    &write_test_file("[-] Accepted fuzzing hmac key '$hmac_key' for $msg\n",
                        $curr_test_file);
                    $rv = 0;
                    $fko_obj->destroy();
                    last;
                } else {
                    &write_test_file("[+] Rejected fuzzing hmac key '$hmac_key' for $msg: " .
                        FKO::error_str() . "\n",
                        $curr_test_file);
                }
                $fko_obj->destroy();
            }
        }
    }

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
        'part1 part2',
        'U%ER',
        'USER001',
        -1,
        '00001',
        '00$01'
    );
    return \@users;
}

sub fuzzing_usernames() {
    my @users = (
        'A'x1000,
        ",1",
#        pack('a', ""),
        '123>123',
        '123<123',
        '123' . pack('a', "\x10"),
        '*-user',
        '?user',
        'User+',
        'U+er',
        'part1|part2',
        'a:b'
    );
    return \@users;
}

sub fuzzing_encryption_keys() {
    my @keys = (
        'A'x33,
        'A'x34,
        'A'x128,
        'A'x1000,
        'A'x2000,
        'as3fa3dfs2fsda3as2fasdfsa3sdaffdjskalfjdsklafjsldkafjdsajdkajsklfdafsklfjjdkljdsafjdjd' .
        'sklfjsf3safjdslfdkjdljsajdskjdskafjdldsljdkafdsljdslafdslaldldajdskajlddslajsl',
    );
    return \@keys;
}

sub fuzzing_hmac_keys() {
    my @keys = (
#        'A'x129,
        'A'x1000,
        'A'x2000,
    );
    return \@keys;
}

sub valid_encryption_keys() {
    my @keys = (
        '!@#$%',
        'asdfasdfsafsdafasdfasdfsafsdaf',
        '$',
        'asdfasdfsafsdaf',
        'testtest',
        '12341234',
        '1',
        '1234',
        'a',
    );
    return \@keys;
}

sub valid_hmac_keys() {
    my @keys = (
        '!@#$%',
        'asdfasdfsafsdafasdfasdfsafsdaf',
        '$',
        'A'x33,
        'A'x128,
        'A'x120,
        'asdfasdfsafsdaf',
        '1234',
        'a',
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

sub valid_spa_hmac_types() {
    my @types = (
        FKO->FKO_HMAC_MD5,
        FKO->FKO_HMAC_SHA1,
        FKO->FKO_HMAC_SHA256,
        FKO->FKO_HMAC_SHA384,
        FKO->FKO_HMAC_SHA512
    );
    return \@types;
}

sub hmac_type_to_str() {
    my $hmac_type = shift;

    if ($hmac_type == FKO->FKO_HMAC_MD5) {
        return 'md5';
    } elsif ($hmac_type == FKO->FKO_HMAC_SHA1) {
        return 'sha1';
    } elsif ($hmac_type == FKO->FKO_HMAC_SHA256) {
        return 'sha256';
    } elsif ($hmac_type == FKO->FKO_HMAC_SHA384) {
        return 'sha384';
    } elsif ($hmac_type == FKO->FKO_HMAC_SHA512) {
        return 'sha512';
    }
    return 'Unknown';
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

sub perl_fko_module_key_with_null() {
    my $test_hr = shift;

    my $rv = 1;

    my $msg         = @{valid_access_messages()}[0];
    my $user        = @{valid_usernames()}[0];
    my $digest_type = @{valid_spa_digest_types()}[0];

    my $key_with_null = 'AAAA' . pack('a', "") . 'AAAA';

    &write_test_file("\n\n[+] ------ KEY: $key_with_null (" . length($key_with_null) . " bytes)\n",
        $curr_test_file);

    &write_test_file("\n    MSG: $msg, user: $user, " .
        "digest type: $digest_type (orig key: $key_with_null)\n",
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
    $fko_obj->spa_data_final($key_with_null, '');

    my $encrypted_msg = $fko_obj->spa_data();

    $fko_obj->destroy();

    for (my $j=1; $j < length($key_with_null); $j++) {
        ### now get new object for decryption
        $fko_obj = FKO->new();
        unless ($fko_obj) {
            &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                $curr_test_file);
            return 0;
        }
        $fko_obj->spa_data($encrypted_msg);

        my $truncated_key = $key_with_null;
        $truncated_key =~ s/^(.{$j}).*/$1/;
        &write_test_file("    Trying truncated key: $truncated_key\n",
            $curr_test_file);
        if ($fko_obj->decrypt_spa_data($truncated_key) == FKO->FKO_SUCCESS) {
            &write_test_file("[-] $msg decrypt success with truncated key " .
                "($key_with_null -> $truncated_key)\n",
                $curr_test_file);
            $rv = 0;
        } else {
            &write_test_file("[+] $msg decrypt rejected truncated " .
                "key ($key_with_null -> $truncated_key)\n",
                $curr_test_file);
        }

        $fko_obj->destroy();
    }
    &write_test_file("\n", $curr_test_file);

    return $rv;
}

sub perl_fko_module_rijndael_truncated_keys() {
    my $test_hr = shift;

    my $rv = 1;

    my $msg         = @{valid_access_messages()}[0];
    my $user        = @{valid_usernames()}[0];
    my $digest_type = @{valid_spa_digest_types()}[0];

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
            $fko_obj->spa_data_final($key, '');

            my $encrypted_msg = $fko_obj->spa_data();

            $fko_obj->destroy();

            if ($enable_openssl_compatibility_tests) {
                unless (&openssl_enc_verification($encrypted_msg,
                        '', $msg, $key, 0, $REQUIRE_SUCCESS)) {
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
            if ($fko_obj->decrypt_spa_data($truncated_key) == FKO->FKO_SUCCESS) {
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
                unless (&openssl_enc_verification($encrypted_msg,
                        '', $msg, $truncated_key, 0, $REQUIRE_FAILURE)) {
                    $rv = 0;
                }
            }
        }
        &write_test_file("\n", $curr_test_file);
    }

    return $rv;
}

sub perl_fko_module_complete_cycle_hmac() {
    my $test_hr = shift;

    my $rv = 1;

    for my $msg (@{valid_access_messages()}) {
        for my $user (@{valid_usernames()}) {
            for my $digest_type (@{valid_spa_digest_types()}) {
                for my $hmac_type (@{valid_spa_hmac_types()}) {
                    my $key_ctr = 0;
                    KEY: for my $key (@{valid_encryption_keys()}) {
                        $key_ctr++;
                        last KEY if $key_ctr >= 2;
                        if ($test_hr->{'set_legacy_iv'} eq $YES
                                and (length($key) > 16)) {
                            &write_test_file("[.] Legacy IV mode is set, " .
                                "skipping long key '$key'.\n",
                                $curr_test_file);
                            next KEY;
                        }

                        my $hmac_key_ctr = 0;
                        HMAC_KEY: for my $hmac_key (@{valid_hmac_keys()}) {
                            $hmac_key_ctr++;
                            last HMAC_KEY if $hmac_key_ctr >= 4;

                            if ($test_hr->{'set_legacy_iv'} eq $YES
                                    and (length($hmac_key) > 16)) {
                                &write_test_file("[.] Legacy IV mode is set, " .
                                    "skipping long key '$hmac_key'.\n",
                                    $curr_test_file);
                                next HMAC_KEY;
                            }

                            &write_test_file("[+] msg: $msg, user: $user, " .
                                "digest type: $digest_type, hmac digest type: " .
                                "$hmac_type, key: $key, hmac_key: $hmac_key\n",
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
                            $fko_obj->hmac_type($hmac_type);

                            my $enc_mode = FKO->FKO_ENC_MODE_CBC;
                            $enc_mode = FKO->FKO_ENC_MODE_CBC_LEGACY_IV
                                if $test_hr->{'set_legacy_iv'} eq $YES;
                            $fko_obj->encryption_mode($enc_mode);

                            $fko_obj->spa_data_final($key, $hmac_key);

                            my $encrypted_msg = $fko_obj->spa_data();

                            $fko_obj->destroy();

                            ### now get new object for decryption
                            $fko_obj = FKO->new($encrypted_msg, $key, $enc_mode, $hmac_key, $hmac_type);
                            unless ($fko_obj) {
                                &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                                    $curr_test_file);
                                return 0;
                            }
                            $fko_obj->spa_data($encrypted_msg);
                            $fko_obj->hmac_type($hmac_type);
                            $fko_obj->encryption_mode($enc_mode);
                            my $hmac_digest = $fko_obj->spa_hmac();

                            $fko_obj->decrypt_spa_data($key);

                            if ($msg ne $fko_obj->spa_message()) {
                                &write_test_file("[-] $msg encrypt/decrypt mismatch\n",
                                    $curr_test_file);
                                $rv = 0;
                            }

                            $fko_obj->destroy();

                            if ($enable_openssl_compatibility_tests) {
                                unless (&openssl_hmac_verification($encrypted_msg,
                                        '', $msg, $hmac_key, 0, $hmac_digest,
                                        &hmac_type_to_str($hmac_type), $ENC_RIJNDAEL, 0)) {
                                    $rv = 0;
                                }

#                                my $flag = $REQUIRE_SUCCESS;
#                                $flag = $REQUIRE_FAILURE if $test_hr->{'set_legacy_iv'} eq $YES;
#                                unless (&openssl_enc_verification($encrypted_msg,
#                                        '', $msg, $key, 0, $flag)) {
#                                    $rv = 0;
#                                }
                            }
                        }
                    }
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
                KEY: for my $key (@{valid_encryption_keys()}) {

                    if ($test_hr->{'set_legacy_iv'} eq $YES
                            and (length($key) > 16)) {
                        &write_test_file("[.] Legacy IV mode is set, " .
                            "skipping long key '$key'.\n",
                            $curr_test_file);
                        next KEY;
                    }

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
                    $fko_obj->spa_data_final($key, '');

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
                    $fko_obj->decrypt_spa_data($key);

                    if ($msg ne $fko_obj->spa_message()) {
                        &write_test_file("[-] $msg encrypt/decrypt mismatch\n",
                            $curr_test_file);
                        $rv = 0;
                    }

                    $fko_obj->destroy();

                    if ($enable_openssl_compatibility_tests) {
                        my $flag = $REQUIRE_SUCCESS;
                        $flag = $REQUIRE_FAILURE if $test_hr->{'set_legacy_iv'} eq $YES;
                        unless (&openssl_enc_verification($encrypted_msg,
                                '', $msg, $key, 0, $flag)) {
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
                KEY: for my $key (@{valid_encryption_keys()}) {

                    if ($test_hr->{'set_legacy_iv'} eq $YES
                            and (length($key) > 16)) {
                        &write_test_file("[.] Legacy IV mode is set, " .
                            "skipping long key '$key'.\n",
                            $curr_test_file);
                        next KEY;
                    }

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
                    $fko_obj->spa_data_final($key, '');

                    my $encrypted_msg = $fko_obj->spa_data();

                    $fko_obj->spa_data($encrypted_msg);
                    $fko_obj->decrypt_spa_data($key);

                    if ($msg ne $fko_obj->spa_message()) {
                        &write_test_file("[-] $msg encrypt/decrypt mismatch\n",
                            $curr_test_file);
                        $rv = 0;
                    }

                    $fko_obj->destroy();

                    if ($enable_openssl_compatibility_tests) {
                        my $flag = $REQUIRE_SUCCESS;
                        $flag = $REQUIRE_FAILURE if $test_hr->{'set_legacy_iv'} eq $YES;
                        unless (&openssl_enc_verification($encrypted_msg,
                                '', $msg, $key, 0, $flag)) {
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
        $fko_obj->spa_data_final($fuzzing_key, '');

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
        $fko_obj->spa_data_final($fuzzing_key, '');

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
        $fko_obj->spa_data_final($fuzzing_key, '');

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
        $fko_obj->spa_data_final($fuzzing_key, '');

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
        $fko_obj->spa_data_final($fuzzing_key, '');

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
        $fko_obj->spa_data_final($fuzzing_key, '');

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
        $fko_obj->spa_data_final($fuzzing_key, '');

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
        $fko_obj->spa_data_final($fuzzing_key, '');

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
        $fko_obj->spa_data_final($fuzzing_key, '');

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
        $fko_obj->spa_data_final($fuzzing_key, '');

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

                my $status = $fko_obj->decrypt_spa_data($fuzzing_key);

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
    $fko_obj->spa_data_final($default_key, '');
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

sub write_sudo_access_conf() {
    my $test_hr = shift;
    unlink $sudo_access_conf if -e $sudo_access_conf;

    # mbr   localhost = NOPASSWD: /usr/bin/cat, /usr/bin/touch
    # mbr   localhost = NOPASSWD: /usr/bin/cat, (root) /usr/bin/touch
    # mbr   localhost = NOPASSWD: /usr/bin/cat, (mbr : mbr) /usr/bin/touch
    if ($test_hr->{'sudo_conf'}) {
        open ST, "> $sudo_conf_testing" or die $!;
        $test_hr->{'sudo_conf'} =~ s/USER/$username/g;
        if ($test_hr->{'sudo_conf'} =~ /TOUCH/) {
            if ($touch_path) {
                $test_hr->{'sudo_conf'} =~ s/TOUCH/$touch_path/;
            } else {
                $test_hr->{'sudo_conf'} =~ s|TOUCH|/bin/touch|;
            }
        }
        print ST $test_hr->{'sudo_conf'}, "\n";
        close ST;
        &write_test_file(
            "[+] Setting $sudo_conf_testing file to:\n$test_hr->{'sudo_conf'}\n",
            $curr_test_file);
    }

    copy $cf{'hmac_cmd_access'}, $sudo_access_conf or die $!;

    open CA, ">> $sudo_access_conf" or die $!;
    print CA "ENABLE_CMD_SUDO_EXEC    Y\n";

    if ($test_hr->{'exec_user'} eq $YES) {
        print CA "CMD_EXEC_USER           $username\n";
    }
    if ($test_hr->{'sudo_exec_user'} eq $YES) {
        print CA "CMD_SUDO_EXEC_USER           $username\n";
    }
    if ($test_hr->{'sudo_exec_group'} eq $YES) {
        print CA "CMD_EXEC_GROUP                $username\n";
        print CA "CMD_SUDO_EXEC_GROUP           $username\n";
    }

    close CA;

    return;
}

sub spa_cmd_open_close_exec_cycle() {
    my $test_hr = shift;

    if ($test_hr->{'cmd_cycle_open_file'}) {
        for my $file (@{$test_hr->{'cmd_cycle_open_file'}}) {
            unlink $file if -e $file;
        }
    }
    if ($test_hr->{'cmd_cycle_close_file'}) {
        for my $file (@{$test_hr->{'cmd_cycle_close_file'}}) {
            next if $file eq 'NONE';
            unlink $file if -e $file;
        }
    }

    my $rv = &spa_cycle($test_hr);

    if ($test_hr->{'cmd_cycle_open_file'}) {
        unless (&file_check_and_remove('cycle open file',
                $test_hr->{'cmd_cycle_open_file'})) {
            $rv = 0;
        }
    }

    if ($test_hr->{'cmd_cycle_close_file'}) {
        unless ($test_hr->{'cmd_cycle_close_file'} eq 'NONE') {
            unless (&file_check_and_remove('cycle close file',
                    $test_hr->{'cmd_cycle_close_file'})) {
                $rv = 0;
            }
        }
    }

    return $rv;
}

sub file_check_and_remove() {
    my ($log_str, $files_ar) = @_;
    my $rv = 1;

    for my $file (@$files_ar) {
        next if $file eq 'NONE';
        if (-e $file) {
            &write_test_file(
                "[+] $log_str $file exists after SPA cycle.\n",
                $curr_test_file);
            unlink $file;
        } else {
            &write_test_file(
                "[-] $log_str $file does not exist after SPA cycle.\n",
                $curr_test_file);
            $rv = 0;
        }
    }
    return $rv;
}

sub spa_cmd_exec_cycle() {
    my $test_hr = shift;

    unlink $cmd_exec_test_file if -e $cmd_exec_test_file;

    if ($test_hr->{'sudo_test'} eq $YES) {
        ### we need to write the access.conf file based on sudo
        ### requirements
        &write_sudo_access_conf($test_hr);

        ### make sure the path to sudo is set properly
        if ($test_hr->{'fwknopd_cmdline'}) {
            $test_hr->{'fwknopd_cmdline'} .= " --sudo-exe $sudo_path";
        }
    }

    if (-e $cmd_exec_test_file) {
        &write_test_file("[-] $cmd_exec_test_file file exists before SPA cycle.\n",
            $curr_test_file);
    } else {
        &write_test_file("[+] $cmd_exec_test_file does not exist before SPA cycle.\n",
            $curr_test_file);
    }

    my $rv = &spa_cycle($test_hr);

    if (-e $cmd_exec_test_file) {
        &run_cmd("ls -l $cmd_exec_test_file", $cmd_out_tmp, $curr_test_file);
        if ($test_hr->{'cmd_exec_file_owner'}) {
            $test_hr->{'cmd_exec_file_owner'} =~ s/USER/$username/;
            my $user = (getpwuid((stat($cmd_exec_test_file))[4]))[0];
            if ($user and $user eq $test_hr->{'cmd_exec_file_owner'}) {
                &write_test_file("[+] $cmd_exec_test_file is owned by user: $user\n",
                    $curr_test_file);
                $rv = 1;
            } else {
                &write_test_file("[-] $cmd_exec_test_file is not " .
                    "owned by user: $test_hr->{'cmd_exec_file_owner'}\n",
                    $curr_test_file);
                $rv = 0;
            }
        }
        if ($test_hr->{'cmd_exec_file_not_created'}) {
            &write_test_file("[-] $cmd_exec_test_file file exists, setting rv=0.\n",
                $curr_test_file);
            $rv = 0;
        }
        unlink $cmd_exec_test_file;
    } else {
        if ($test_hr->{'cmd_exec_file_not_created'}) {
            &write_test_file("[+] $cmd_exec_test_file file does not exist.\n",
                $curr_test_file);
            $rv = 1;
        } else {
            &write_test_file("[-] $cmd_exec_test_file file does not exist, setting rv=0.\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    return $rv;
}

sub replay_detection() {
    my $test_hr = shift;

    ### do a complete SPA cycle and then parse the SPA packet out of the
    ### current test file and re-send

    &spa_cycle($test_hr);

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

    sleep 1;

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
            = &client_server_interaction($test_hr, \@packets, $USE_PREDEF_PKTS);

    return $rv;
}

sub digest_cache_structure() {
    my $test_hr = shift;
    my $rv = 1;

    &run_cmd("file $default_digest_file", $cmd_out_tmp, $curr_test_file);

    if (&file_find_regex([qr/ASCII/i], $MATCH_ALL,
            $APPEND_RESULTS, $cmd_out_tmp)) {

        ### the format should be:
        ### <digest> <proto> <src_ip> <src_port> <dst_ip> <dst_port> <time>
        open D1, "< $default_digest_file" or
            die "[*] could not open $default_digest_file: $!";
        while (<D1>) {
            next if /^#/;
            next unless /\S/;
            unless (m|^\S+\s+\d+\s+$ip_re\s+\d+\s+$ip_re\s+\d+\s+\d+|) {
                &write_test_file("[-] invalid digest.cache line: $_",
                    $curr_test_file);
                $rv = 0;
                last;
            }
        }
        close D1;
    } elsif (&file_find_regex([qr/dbm/i], $MATCH_ALL, $cmd_out_tmp)) {
        &write_test_file("[+] DBM digest file format, " .
            "assuming this is valid.\n", $APPEND_RESULTS,
            $curr_test_file);
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
    my $tries = 0;

    while ($tries < 5) {

        $rv = &iptables_rules_not_duplicated_account_for_timestamps($test_hr);

        if ($rv == 1) {
            &write_test_file("[+] iptables rules not duplicated.\n",
                $curr_test_file);
            last;
        } elsif ($rv == 0) {
            &write_test_file("[-] iptables rules duplicated.\n",
                $curr_test_file);
            last;
        } elsif ($rv == $TIMESTAMP_DIFF) {
            &write_test_file("[-] iptables rules spanned one second " .
                "difference in fwknopd output, try: $tries.\n", $curr_test_file);
        }

        &rm_tmp_files();
        $tries++;
    }

    $rv = 0 if $rv == $TIMESTAMP_DIFF;

    return $rv;
}

sub iptables_rules_not_duplicated_account_for_timestamps() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    my @packets = ();

    for (my $i=0; $i < 3; $i++) {
        unless (&_client_send_spa_packet($test_hr, 1, $NO_SERVER_RECEIVE_CHECK)) {
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
    my $time_stamp  = 0;
    my $time_stamp2 = 0;
    open IPT, "< $server_cmd_tmp" or die $!;
    while (<IPT>) {
        ### 1    ACCEPT    tcp  --  127.0.0.2    0.0.0.0/0   tcp dpt:22 /* _exp_1359688354 */
        if (m|^1\s+.*$fake_ip\s+.*_exp_(\d+)|) {
            $time_stamp = $1;
            next;
        }
        if ($time_stamp) {
            if (/^2\s+.*$fake_ip\s+.*_exp_$time_stamp/) {
                $rv = 0;
                last;
            } elsif (/^2\s+.*$fake_ip\s+.*_exp_(\d+)/) {
                $time_stamp2 = $1;
                last;
            }
        }
    }
    close IPT;

    if ($rv == 1) {
        if ($time_stamp and $time_stamp2 and $time_stamp2 > $time_stamp) {
            $rv = $TIMESTAMP_DIFF;
        } else {
            ### require the "already exists" string
            unless (&file_find_regex([qr/\s$fake_ip\s.*already\s+exists/],
                    $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
                $rv = 0;
            }
        }
    }

    return $rv;
}

sub server_bpf_ignore_packet() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    unless (&_client_send_spa_packet($test_hr, 1, $NO_SERVER_RECEIVE_CHECK)) {
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
            $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
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

    unless (&_client_send_spa_packet($test_hr, 1, $SERVER_RECEIVE_CHECK)) {
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

sub os_compatibility() {
    my $test_hr = shift;

    return &backwards_compatibility($test_hr);
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

    if ($rv) {
        $fuzzing_success_ctr++;
    } else {
        $fuzzing_failure_ctr++;
    }
    $fuzzing_ctr++;

    return $rv;
}

sub cached_pkts_fuzzer() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    $pkts_file = $test_hr->{'spa_pkts_file'};

    unless (-e $pkts_file) {
        &write_test_file("[-] The SPA packets file: $pkts_file does not exist, " .
            "create with 'grep PKT_ID output/<fko-wrapper-test-num>.test > $pkts_file'\n",
            $curr_test_file);
        return 0;
    }

    ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, {}, $READ_PKTS_FROM_FILE);

    $pkts_file = '';

    $rv = 0 unless $server_was_stopped;

    if ($fw_rule_created) {
        &write_test_file("[-] new fw rule created.\n", $curr_test_file);
        $rv = 0;
    } else {
        &write_test_file("[+] new fw rule not created.\n", $curr_test_file);
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

    unless (&_client_send_spa_packet($test_hr, 1, $NO_SERVER_RECEIVE_CHECK)) {
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
            $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
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

    unless (&_client_send_spa_packet($test_hr, 1, $NO_SERVER_RECEIVE_CHECK)) {
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
            $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
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

    unless (&_client_send_spa_packet($test_hr, 1, $NO_SERVER_RECEIVE_CHECK)) {
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
            $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
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

    unless (&_client_send_spa_packet($test_hr, 1, $NO_SERVER_RECEIVE_CHECK)) {
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
            $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
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

    unless (&_client_send_spa_packet($test_hr, 1, $NO_SERVER_RECEIVE_CHECK)) {
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
            $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
        $rv = 0;
    }

    return $rv;
}

sub server_start() {
    my $test_hr = shift;

    my ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed)
        = &client_server_interaction($test_hr, [], $USE_PREDEF_PKTS);

    unless (&file_find_regex([qr/Starting\sfwknopd\smain\sevent\sloop/],
            $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
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

    if (&file_find_regex([qr/count\slimit\sof\s1\sreached/],
            $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
        $rv = 1;
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

    if (&file_find_regex([qr/count\slimit\sof\s1\sreached/],
            $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
        $rv = 1;
    }

    return $rv;
}

sub down_interface() {
    my $test_hr = shift;

    my $rv = 1;

    &start_fwknopd($test_hr);

    if ($ip_path) {
        &run_cmd("$ip_path link set $loopback_intf down", $cmd_out_tmp, $curr_test_file);
        sleep 5;
        &run_cmd("$ip_path link set $loopback_intf up", $cmd_out_tmp, $curr_test_file);
    } else {
        &run_cmd("$ifconfig_path $loopback_intf down", $cmd_out_tmp, $curr_test_file);
        sleep 5;
        &run_cmd("$ifconfig_path $loopback_intf up", $cmd_out_tmp, $curr_test_file);
    }

    if (&is_fwknopd_running()) {
        $rv = 0 unless $test_hr->{'no_exit_intf_down'} eq $YES;
        &stop_fwknopd();
    }

    $rv = 0 unless &process_output_matches($test_hr);

    return $rv;
}

sub client_server_interaction() {
    my ($test_hr, $pkts_hr, $spa_client_flag) = @_;

    my $rv = 1;
    my $server_was_stopped = 1;
    my $fw_rule_created = 1;
    my $fw_rule_removed = 0;
    my $max_pkt_tries = $default_pkt_tries;

    $max_pkt_tries = $test_hr->{'max_pkt_tries'}
        if $test_hr->{'max_pkt_tries'};

    ### start fwknopd to monitor for the SPA packet over the loopback interface
    my $fwknopd_parent_pid = &start_fwknopd($test_hr);
    sleep 1;

    if ($test_hr->{'server_exec_err'}) {
        if (&is_fwknopd_running()) {
            &write_test_file("[-] server is running, but required server_exec_err.\n",
                $curr_test_file);
            &stop_fwknopd();
            return (0, 0, 0, 0);
        }
        return ($rv, 0, 0, 0);
    }

    if ($test_hr->{'insert_rule_while_running'}) {
        ### we're assuming iptables/firewalld here
        &run_cmd("$fw_bin_and_prefix -A FWKNOP_INPUT -p tcp -s $fake_ip " .
            "--dport 1234 -j ACCEPT", $cmd_out_tmp, $curr_test_file);
    }

    if ($test_hr->{'insert_duplicate_rule_while_running'}) {
        &insert_dupe_rule($test_hr);
    }

    &iptables_rm_chains($test_hr)
        if $test_hr->{'iptables_rm_chains_after_server_start'};

    my $client_cycles = 1; ### default
    $client_cycles = $test_hr->{'client_cycles_per_server_instance'}
        if $test_hr->{'client_cycles_per_server_instance'} > 0;

    for (my $cycle_ctr=0; $cycle_ctr < $client_cycles; $cycle_ctr++) {

        $fw_rule_created = 1;
        $fw_rule_removed = 0;

        if ($client_cycles > 1) {
            &write_test_file("[+] Start client cycle: " . ($cycle_ctr+1) . "\n",
                $curr_test_file);
        }

        ### send the SPA packet(s) to the server either manually using IO::Socket or
        ### with the fwknopd client
        if ($spa_client_flag == $USE_CLIENT) {
            unless (&_client_send_spa_packet($test_hr,
                        $cycle_ctr, $SERVER_RECEIVE_CHECK)) {
                if ($enable_openssl_compatibility_tests) {
                    &write_test_file(
                        "[-] fwknop client execution and/or OpenSSL error.\n",
                        $curr_test_file);
                } else {
                    &write_test_file("[-] fwknop client execution error.\n",
                        $curr_test_file);
                }
                $rv = 0 unless $test_hr->{'ignore_client_error'};
            }
        } elsif ($spa_client_flag == $USE_PREDEF_PKTS) {
            &send_packets($pkts_hr, $max_pkt_tries);
        } elsif ($spa_client_flag == $READ_PKTS_FROM_FILE) {
            &send_packets_from_file();
        } else {
            ### pcap file mode, nothing to do
        }
        my $quickcount = 0; ### Adds up to 5 seconds of time
        while (&file_find_num_matches(qr/SPA\sData/, $NO_APPEND_RESULTS, $server_cmd_tmp) == 0 ) {
            precise_sleep(.5);
            print ".";
            $quickcount += 1;
            if ($quickcount > 10) {
                last;
            }
        }
        precise_sleep(.5); # brief timeout to avoid race condition
        ### check to see if the SPA packet resulted in a new fw access rule
        ($rv, $fw_rule_created, $fw_rule_removed)
            = &fw_check($rv, $fw_rule_created, $fw_rule_removed, $test_hr);
    }

    if (&is_fwknopd_running()) {
        &stop_fwknopd();
        $server_was_stopped = 0 if &is_fwknopd_running();
    } else {
        &write_test_file("[-] server is not running.\n", $curr_test_file);
        $server_was_stopped = 0;
    }

    unless ($server_was_stopped) {
        if ($test_hr->{'expect_server_stopped'}) {
            &write_test_file("[+] Expecting server to not be running.\n",
                $curr_test_file);
        } else {
            &write_test_file("[-] server_was_stopped=0, so setting rv=0.\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    &write_test_file("[.] client_server_interaction() summary: rv: $rv, " .
        "server_was_stopped: $server_was_stopped, " .
        "fw_rule_created: $fw_rule_created, fw_rule_removed: $fw_rule_removed\n",
        $curr_test_file);

    return ($rv, $server_was_stopped, $fw_rule_created, $fw_rule_removed);
}

sub fw_check() {
    my ($rv, $fw_rule_created, $fw_rule_removed, $test_hr) = @_;

    my $ctr = 0;
    while (not &is_fw_rule_active($test_hr)) {
        &write_test_file("[.] new fw rule does not exist.\n",
            $curr_test_file);
        $ctr++;
        if ($test_hr->{'sleep_cycles'}) {
            last if $ctr == $test_hr->{'sleep_cycles'};
        } else {
            last if $ctr == 12;
        }
        precise_sleep(.2);
    }
    if ($test_hr->{'sleep_cycles'} and ($ctr == $test_hr->{'sleep_cycles'})) {
        $fw_rule_created = 0;
        $fw_rule_removed = 0;
    } else {
        if ($ctr == 12) {
            $fw_rule_created = 0;
            $fw_rule_removed = 0;
        }
    }

    if ($fw_rule_created or $test_hr->{'insert_duplicate_rule_while_running'}) {
        if ($test_hr->{'rm_rule_mid_cycle'}) {
            &write_test_file("[+] Flushing firewall rules out from under fwknopd...\n",
                $curr_test_file);
            &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd " .
                "$default_server_conf_args --fw-flush $verbose_str",
                $cmd_out_tmp, $curr_test_file);
        }

        my $timeout_loop = 0;
        while ($timeout_loop < 15) {
            $timeout_loop++;
            if (!&is_fw_rule_active($test_hr)) {
                &write_test_file("[+] new fw rule timed out.\n", $curr_test_file);
                $fw_rule_removed = 1;
                last;
            }
            sleep 1;
        }
        if (!$fw_rule_removed) {
            if ($test_hr->{'fw_rule_removed'} ne $REQUIRE_NO_NEW_REMOVED) {
                &write_test_file("[-] new fw rule not timed out, setting rv=0.\n",
                    $curr_test_file);
                $rv = 0;
            }
        } else {
            &write_test_file("[+] new fw rule timed out.\n", $curr_test_file);
            $fw_rule_removed = 1;
        }
    }

    $rv = 0 unless &fw_rule_criteria($fw_rule_created,
            $fw_rule_removed, $test_hr);

    return $rv, $fw_rule_created, $fw_rule_removed;
}

sub fw_rule_criteria() {
    my ($fw_rule_created, $fw_rule_removed, $test_hr) = @_;

    my $rv = 1;

    if ($test_hr->{'fw_rule_created'} eq $NEW_RULE_REQUIRED) {
        unless ($fw_rule_created) {
            &write_test_file(
                "[-] fw_rule_created=0 but new rule required, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    } elsif ($test_hr->{'fw_rule_created'} eq $REQUIRE_NO_NEW_RULE) {
        if ($fw_rule_created) {
            &write_test_file(
                "[-] fw_rule_created=1 but new rule NOT required, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    if ($test_hr->{'fw_rule_removed'} eq $NEW_RULE_REMOVED) {
        unless ($fw_rule_removed) {
            &write_test_file(
                "[-] fw_rule_removed=0 but new rule removal required, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    } elsif ($test_hr->{'fw_rule_removed'} eq $REQUIRE_NO_NEW_REMOVED) {
        if ($fw_rule_removed) {
            &write_test_file(
                "[-] fw_rule_removed=1 but new rule removal NOT required, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    return $rv;
}

sub process_output_matches() {
    my $test_hr = shift;

    my $rv = 1;

    if ($test_hr->{'client_positive_output_matches'}) {
        unless (&file_find_regex(
                $test_hr->{'client_positive_output_matches'},
                $MATCH_ALL, $APPEND_RESULTS, $curr_test_file)) {
            &write_test_file(
                "[-] client_positive_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    if ($test_hr->{'client_negative_output_matches'}) {
        if (&file_find_regex(
                $test_hr->{'client_negative_output_matches'},
                $MATCH_ANY, $APPEND_RESULTS, $curr_test_file)) {
            &write_test_file(
                "[-] client_negative_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    if ($test_hr->{'server_positive_output_matches'}) {
        unless (&file_find_regex(
                $test_hr->{'server_positive_output_matches'},
                $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
            &write_test_file(
                "[-] server_positive_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    if ($test_hr->{'server_positive_num_matches'}) {
        for my $hr (@{$test_hr->{'server_positive_num_matches'}}) {
            my $count = &file_find_num_matches($hr->{'re'},
                    $APPEND_RESULTS, $server_test_file);
            unless ($count == $hr->{'num'}) {
                &write_test_file(
                    "[-] server_positive_num_matches not met ($hr->{'re'} " .
                    "match count = $count, expected $hr->{'num'}, " .
                    "setting rv=0\n", $curr_test_file);
                $rv = 0;
            }
        }
    }

    if ($test_hr->{'server_negative_output_matches'}) {
        if (&file_find_regex(
                $test_hr->{'server_negative_output_matches'},
                $MATCH_ANY, $APPEND_RESULTS, $server_test_file)) {
            &write_test_file(
                "[-] server_negative_output_matches not met, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

    return $rv;
}

sub iptables_rm_chains() {
    my $test_hr = shift;

    ### this deletes fwknop chains out from under the running fwknopd
    ### instance (tests whether it is able to recover with
    ### chain_exists(), etc.)
    my ($prv, $lib_path, $fwknopd_conf, $access_conf)
             = &parse_fwknopd_cmdline($test_hr);
    if ($prv) {
        &write_test_file("[+] fwknopd iptables policy before flush:\n",
            $curr_test_file);
        &run_cmd("LD_LIBRARY_PATH=$lib_path $fwknopdCmd -c " .
            "$fwknopd_conf -a $access_conf --fw-list",
            $cmd_out_tmp, $curr_test_file);
        &run_cmd("LD_LIBRARY_PATH=$lib_path $fwknopdCmd -c " .
            "$fwknopd_conf -a $access_conf --fw-flush",
            $cmd_out_tmp, $curr_test_file);
        &write_test_file("[+] fwknopd iptables policy after flush:\n",
            $curr_test_file);
        &run_cmd("LD_LIBRARY_PATH=$lib_path $fwknopdCmd -c " .
            "$fwknopd_conf -a $access_conf --fw-list",
            $cmd_out_tmp, $curr_test_file);
    }
    return;
}

sub parse_fwknopd_cmdline() {
    my $test_hr = shift;
    if ($test_hr->{'fwknopd_cmdline'}
            =~ /LD_LIBRARY_PATH=(\S+)\s.*\s\-c\s(\S+)\s\-a\s(\S+)/) {
        return 1, $1, $2, $3;
    }
    return 0, '', '', '';
}

sub get_spa_packet_from_file() {
    my $file = shift;

    my $spa_pkt = '';
    open G2, "< $file" or die "[*] Could not open file $file: $!";
    while (<G2>) {
        if (/Final\sSPA\sData\:\s(\S+)/) {
            $spa_pkt = $1;
        }
    }
    close G2;

    return $spa_pkt;
}

sub send_packets_from_file() {

    ### send 100 SPA packets at a time
    my @packets = ();
    open S, "< $pkts_file" or die $!;
    my @lines = <S>;
    close S;

    my $pkt_ctr = 1;
    for (@lines) {
        ### PKT_ID: 60, PKT: +h1JUC/aipIDfugDoVpsOqChr5KBwbP...
        if (/PKT_ID\:\s+(\d+)\,\sPKT\:\s(\S+)/) {
            push @packets,
                {
                    'proto'  => 'udp',
                    'port'   => $default_spa_port,
                    'dst_ip' => $loopback_ip,
                    'data'   => $2,
                };
            if (($pkt_ctr % 100) == 0) {
                &send_all_pkts(\@packets);
                @packets = ();
            }
            $pkt_ctr++;
        }
    }
    close F;

    if ($#packets > -1) {
        &send_all_pkts(\@packets);
    }
    return;
}

sub send_packets() {
    my ($pkts_ar, $max_tries) = @_;

    open S2, ">> $curr_test_file" or die $!;
    print S2 "[+] send_packets(): Sending the following packets...\n";
    print S2 Dumper $pkts_ar;
    close S2;

    if (-e $server_cmd_tmp) {

        &send_all_pkts($pkts_ar);
        #precise_sleep(.5);

        my $tries = 0;
        while (not &file_find_regex(
                [qr/stanza\s.*\sSPA Packet from IP/],
                $MATCH_ALL, $NO_APPEND_RESULTS, $server_cmd_tmp)) {

            &write_test_file("[.] send_packets() looking for " .
                "fwknopd to receive packet(s), try: $tries\n",
                $curr_test_file);

            &send_all_pkts($pkts_ar);

            $tries++;

            if ($send_all_loop_once) {
                last if $tries == $max_tries;
            } else {
                last if $tries == $max_tries * 10;
            }
            precise_sleep(.5);
        }

        $default_pkt_tries = $tries+5 if $tries > $default_pkt_tries;
        $send_all_loop_once = 1;

    } else {
        &send_all_pkts($pkts_ar);
    }
    return;
}

sub send_all_pkts() {
    my $pkts_ar = shift;
    for my $pkt_hr (@$pkts_ar) {
        my $sent = 0;
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
            $sent = 1;
        } elsif ($pkt_hr->{'proto'} eq 'http') {
            ### FIXME
        } elsif ($pkt_hr->{'proto'} eq 'icmp') {
            ### FIXME
        }
        &write_test_file("    send_all_pkts() sent packet: $pkt_hr->{'data'}\n",
            $curr_test_file) if $sent;

        sleep $pkt_hr->{'delay'} if defined $pkt_hr->{'delay'};
    }
    return;
}

sub rc_file_exists() {
    my $test_hr = shift;

    my $rv = 1;

    if (-e $tmp_rc_file) {
        $rv = 0 unless &file_find_regex([qr/This\sfile\scontains/],
            $MATCH_ALL, $APPEND_RESULTS, $tmp_rc_file);
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

sub run_last_args() {
    my $test_hr = shift;

    unlink $tmp_args_file if -e $tmp_args_file;

    ### add a few extra spaces to ensure this is handled properly
    &write_test_file("fwknop -A tcp/22 -s    -D 127.0.0.1 --verbose " .
        "--get-key $local_key_file\n", $tmp_args_file);

    return &generic_exec($test_hr);
}

sub rm_last_args() {
    my $test_hr = shift;

    my $last_args_file = $ENV{'HOME'} . '/.fwknop.run';
    if (-e $last_args_file) {
        move $last_args_file, $last_args_file . '.orig';
    }

    my $rv = &generic_exec($test_hr);

    if (-e $last_args_file . '.orig') {
        move $last_args_file . '.orig', $last_args_file;
    }

    return $rv;
}

sub generic_exec() {
    my $test_hr = shift;
    my $num_loops = 0;
    my $rv = 1;
    my $pid = fork();
    die "[*] Could not fork: $!" unless defined $pid;

    if ($pid == 0) {
        exit &run_cmd($test_hr->{'cmdline'},
                    $cmd_out_tmp, $curr_test_file);
    }

    while (1) {
        sleep 5;
        $num_loops++;
        $rv = waitpid($pid, WNOHANG);
        if ($rv != 0) {
            $rv = 1;
            last;
        }
        if ($num_loops > 99) { #5 minutes to run
            $rv = 0;
            kill(9, $pid);
            &write_test_file("Command timed out, killing process\n", $curr_test_file);
            last;
        }
    }

    my $exec_rv = $?;

    if ($test_hr->{'exec_err'} eq $YES) {
        $rv = 0 if $exec_rv;
    } elsif ($test_hr->{'exec_err'} eq $NO) {
        $rv = 0 unless $exec_rv;
    } ### else it must be $IGNORE so ignore the $exec_rv value

    if ($test_hr->{'positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'positive_output_matches'},
            $MATCH_ALL, $APPEND_RESULTS, $curr_test_file);
    }

    if ($test_hr->{'negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'negative_output_matches'},
            $MATCH_ANY, $APPEND_RESULTS, $curr_test_file);
    }

    return $rv;
}

sub key_gen_uniqueness() {
    my $test_hr = shift;

    my %rijndael_keys = ();
    my %hmac_keys     = ();

    my $rv = 1;

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

    $rv = 0 if $found_dup;

    $rv = 0 unless keys %rijndael_keys == $uniq_keys;
    $rv = 0 unless keys %hmac_keys == $uniq_keys;

    return $rv;
}

### check for PIE
sub pie_binary() {
    my $test_hr = shift;
    return 0 unless -e $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $curr_test_file);
    return 1 if &file_find_regex([qr/Position\sIndependent.*:\syes/i],
        $MATCH_ALL, $APPEND_RESULTS, $curr_test_file);
    return 0;
}

### check for stack protection
sub stack_protected_binary() {
    my $test_hr = shift;
    return 0 unless -e $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $curr_test_file);
    return 1 if &file_find_regex([qr/Stack\sprotected.*:\syes/i],
        $MATCH_ALL, $APPEND_RESULTS, $curr_test_file);
    return 0;
}

### check for fortified source functions
sub fortify_source_functions() {
    my $test_hr = shift;
    return 0 unless -e $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $curr_test_file);
    return 1 if &file_find_regex([qr/Fortify\sSource\sfunctions:\syes/i],
        $MATCH_ALL, $APPEND_RESULTS, $curr_test_file);
    return 0;
}

### check for read-only relocations
sub read_only_relocations() {
    my $test_hr = shift;
    return 0 unless -e $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $curr_test_file);
    return 1 if &file_find_regex([qr/Read.only\srelocations:\syes/i],
        $MATCH_ALL, $APPEND_RESULTS, $curr_test_file);
    return 0;
}

### check for immediate binding
sub immediate_binding() {
    my $test_hr = shift;
    return 0 unless -e $test_hr->{'binary'};
    &run_cmd("./hardening-check $test_hr->{'binary'}",
            $cmd_out_tmp, $curr_test_file);
    return 1 if &file_find_regex([qr/Immediate\sbinding:\syes/i],
        $MATCH_ALL, $APPEND_RESULTS, $curr_test_file);
    return 0;
}

sub openssl_hmac_verification() {
    my ($encrypted_msg, $encoded_msg, $access_msg, $tmp_key,
        $b64_decode_key, $hmac_digest, $hmac_mode, $enc_mode, $tolerate_failure) = @_;

    my $hmac_key = '';
    my $enc_msg_without_hmac = '';
    my $openssl_hmac = '';

    if ($b64_decode_key) {
        $hmac_key = decode_base64($tmp_key);
    } else {
        $hmac_key = $tmp_key;
    }

    my $enc_mode_str = 'Rijndael';
    $enc_mode_str = 'GPG' if $enc_mode == $ENC_GPG;

    &write_test_file("[+] OpenSSL HMAC $hmac_mode verification, (encoded msg: " .
        "$encoded_msg) (access: $access_msg), hmac_key: $tmp_key, " .
        "encrypted+encoded msg: $encrypted_msg, hmac_digest: $hmac_digest, " .
        "enc_mode: $enc_mode_str\n",
        $curr_test_file);

    if ($hmac_key =~ /\W/ and not $openssl_hmac_hexkey_supported) {
        &write_test_file("[-] openssl hex key not supported and key " .
            "contains syntax busting chars, skipping hmac test.\n",
            $curr_test_file);
        return 1;
    }

    $openssl_hmac_ctr++;

    my $hmac_digest_search = quotemeta $hmac_digest;
    ### see if OpenSSL produces the same HMAC digest value from the encrypted
    ### data and corresponding HMAC key

    if ($encrypted_msg =~ m|(\S+)${hmac_digest_search}$|) {
        $enc_msg_without_hmac = $1;
    }

    unless ($enc_msg_without_hmac) {
        &write_test_file("    Msg not in the form <enc_msg><hmac_digest>\n",
            $curr_test_file);
        $openssl_hmac_failure_ctr++;
        return 0;
    }

    ### transform encrypted message into the format that openssl expects
    if ($enc_mode == $ENC_RIJNDAEL) {
        $enc_msg_without_hmac = 'U2FsdGVkX1' . $enc_msg_without_hmac
            unless $enc_msg_without_hmac =~ /^U2FsdGVkX1/;
    } else {
        $enc_msg_without_hmac = 'hQ' . $enc_msg_without_hmac
            unless $enc_msg_without_hmac =~ /^hQ/;
    }

    &write_test_file("    Calculating HMAC over: '$enc_msg_without_hmac'\n",
        $curr_test_file);

    open D3, "> $data_tmp" or die $!;
    print D3 $enc_msg_without_hmac;
    close D3;

    my $hex_hmac_key = '';
    for my $char (split //, $hmac_key) {
        $hex_hmac_key .= sprintf "%02x", ord($char);
    }

    my $openssl_hmac_cmd = "$openssl_path dgst -binary -${hmac_mode} ";
    if ($openssl_hmac_hexkey_supported) {
        $openssl_hmac_cmd .= "-mac HMAC -macopt hexkey:$hex_hmac_key $data_tmp ";
    } else {
        $openssl_hmac_cmd .= "-hmac $hmac_key $data_tmp ";
    }

    $openssl_hmac_cmd .= "| $base64_path" if $base64_path;

    unless (&run_cmd($openssl_hmac_cmd, $openssl_cmd_tmp, $curr_test_file)) {
        &write_test_file("[-] Could not run openssl command: '$openssl_hmac_cmd'\n",
            $curr_test_file);
        $openssl_hmac_failure_ctr++;
        return 0;
    }

    ### for HMAC SHA512 this output will span two lines
    my $openssl_hmac_line = '';
    {
        local $/ = undef;
        open HMAC1, "< $openssl_cmd_tmp" or die $!;
        $openssl_hmac_line = <HMAC1>;
        close HMAC1;
    }
    if ($openssl_hmac_line =~ /unknown option/) { ###Primarily for SHA 3, not supported at this time
        &write_test_file("[.] Openssl doesn't support this command: '$openssl_hmac_cmd'\n",
            $curr_test_file);
        return 1;
    }

    if ($base64_path) {
        $openssl_hmac = $openssl_hmac_line;
    } else {
        $openssl_hmac = encode_base64($openssl_hmac_line);
    }

    $openssl_hmac =~ s|=||g;
    $openssl_hmac =~ s|\n||g;

    if ($openssl_hmac eq $hmac_digest) {
        &write_test_file("[+] OpenSSL HMAC match '$openssl_hmac'\n",
            $curr_test_file);
    } else {
        &write_test_file("[-] OpenSSL HMAC mismatch " .
            "(openssl): '$openssl_hmac' != (fwknop): '$hmac_digest'\n",
            $curr_test_file);
        unless ($tolerate_failure){
            $openssl_hmac_failure_ctr++;
        }
        return 0;
    }

    $openssl_hmac_success_ctr++;
    return 1;
}

sub openssl_enc_verification() {
    my ($encrypted_msg, $encoded_msg, $access_msg, $tmp_key,
        $b64_decode_key, $rv_flag) = @_;

    my $rv = 1;

    my $rv_str = 'REQUIRE_SUCCESS';
    $rv_str = 'REQUIRE_FAILURE' if $rv_flag == $REQUIRE_FAILURE;

    my $key = '';

    if ($b64_decode_key) {
        $key = decode_base64($tmp_key);
    } else {
        $key = $tmp_key;
    }

    &write_test_file("[+] OpenSSL verification, (encoded msg: " .
        "$encoded_msg) (access: $access_msg), key: $tmp_key, " .
        "b64_decode_key: $b64_decode_key, " .
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

    open D4, "> $data_tmp" or die $!;
    print D4 $encrypted_msg, "\n";
    close D4;

    open D5, "> $key_tmp" or die $!;
    print D5 $key;
    close D5;

    $rv = &run_cmd("$openssl_path enc -d -a -aes-256-cbc " .
        "-pass file:$key_tmp -in $data_tmp",
        $openssl_cmd_tmp, $curr_test_file);

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
            open D6, "< $openssl_cmd_tmp" or die $!;
            while (<D6>) {
                if (/^(?:\S+?\:){5}(\S+?)\:/) {
                    $decrypted_access_msg = $1;
                    $decrypted_msg = $_;
                }
            }
            close D6;

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
            open D7, "< $openssl_cmd_tmp" or die $!;
            while (<D7>) {
                if (/^(?:\S+?\:){5}(\S+?)\:/) {
                    $decrypted_access_msg = $1;
                    $decrypted_msg = $_;
                }
            }
            close D7;

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
                        $openssl_cmd_tmp, $curr_test_file)) {

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

     &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd " .
            "$default_server_conf_args --fw-list-all",
            $cmd_out_tmp, $curr_test_file);

     &run_cmd("$lib_view_str $valgrind_str $fwknopdCmd " .
            "$default_server_conf_args --ipv6 --fw-list-all",
            $cmd_out_tmp, $curr_test_file);

    my $have_gpgme = 0;
    my $net_cmd = '';
    if ($ip_path) {
        $net_cmd = "$ip_path addr";
    } else {
        $net_cmd = "$ifconfig_path -a";
    }

    for my $cmd (
        'uname -a',
        'uptime',
        "$net_cmd",
        'ls -l /etc', 'if [ -e /etc/issue ]; then cat /etc/issue; fi',
        'if [ `which iptables` ]; then iptables -V; fi',
        'if [ -e /proc/cpuinfo ]; then cat /proc/cpuinfo; fi',
        'if [ -e /proc/config.gz ]; then zcat /proc/config.gz; fi',
        'if [ `which gpg` ]; then gpg --version; fi',
        "if [ `which tcpdump` ]; then $lib_view_cmd `which tcpdump`; fi",
        "$lib_view_cmd $fwknopCmd",
        "$lib_view_cmd $fwknopdCmd",
        "$lib_view_cmd $libfko_bin",
        'ls -l /usr/lib/*pcap*',
        'ls -l /usr/local/lib/*pcap*',
        'ls -l /usr/lib/*fko*',
        'ls -l /usr/local/lib/*fko*',
    ) {
        &run_cmd($cmd, $cmd_out_tmp, $curr_test_file);

        if ($cmd =~ /^$lib_view_cmd/) {
            $have_gpgme++ if &file_find_regex([qr/gpgme/],
                $MATCH_ALL, $APPEND_RESULTS, $cmd_out_tmp);
        }
    }

    ### all three of fwknop/fwknopd/libfko must link against gpgme in order
    ### to enable gpg tests
    unless ($have_gpgme == 3) {
        push @tests_to_exclude, qr/gpg/i;
        push @tests_to_exclude, qr/gnupg/i;
    }

    return 1;
}

sub is_valgrind_running() {
    return &run_cmd("ps axuww | grep valgrind " .
        "| grep -v perl | grep -v grep",
        $cmd_out_tmp, $curr_test_file);
}

sub anonymize_results() {
    my $rv = 0;
    die "[*] $output_dir does not exist" unless -d $output_dir;
    die "[*] $logfile does not exist, has $0 been executed?"
        unless -e $logfile;
    if (-e $tarfile) {
        unlink $tarfile or die "[*] Could not unlink $tarfile: $!";
    }

    print "\n[+] Anonymizing all IP addresses and hostnames ",
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

    print "\n[+] Anonymized test results file: '$tarfile', you can send\n",
        "    this to mbr\@cipherdyne.org for diagnosis.\n\n";

    if (-e $tarfile) {
        $rv = 1;
    }
    return $rv;
}


sub write_pid() {
    my $test_hr = shift;

    open PID, "> $default_pid_file" or die $!;
    print PID "1\n";
    close PID;

    &server_start($test_hr);

    open RPID, "< $default_pid_file" or die $!;
    my $pid = <RPID>;
    chomp $pid;
    close RPID;

    if ($pid != 1) {
        return 1;
    }

    return 0;
}

sub do_fwknopd_cmd() {
    my $cmdline = shift;

    my $pid = fork();
    die "[*] Could not fork: $!" unless defined $pid;

    if ($pid == 0) {

        ### we are the child, so start fwknopd
        exit &run_cmd($cmdline, $server_cmd_tmp, $server_test_file);
    }

    ### look for 'fwknopd main event loop' as the indicator that fwknopd
    ### is ready to receive packets
    my $tries = 0;

    while (not -e $server_cmd_tmp) {
        $tries++;
        sleep 1;
        last if $tries == 5;
    }

    if (&file_find_regex([qr/fwknopd\smain\sevent\sloop/],
            $MATCH_ALL, $NO_APPEND_RESULTS, $server_cmd_tmp)) {
        &write_test_file("[.] start_fwknopd() found 'main event loop' string\n",
            $curr_test_file);
        sleep 1;
    } else {
        $tries = 0;
        while (not &file_find_regex([qr/fwknopd\smain\sevent\sloop/],
                $MATCH_ALL, $NO_APPEND_RESULTS, $server_cmd_tmp) and
                not &file_find_regex([qr/Kicking\soff.*server/],
                $MATCH_ALL, $NO_APPEND_RESULTS, $server_cmd_tmp)) {
            &write_test_file("[.] start_fwknopd() looking " .
                "for 'main event loop' or 'Kicking off.*server', try: $tries\n",
                $curr_test_file);
            $tries++;
            if ($detect_server_loop_once) {
                last if $tries == $default_server_tries;
            } else {
                last if $tries == $default_server_tries * 10;
            }
            sleep 1;
        }
    }

    $default_server_tries = $tries+5 if $tries > $default_server_tries;
    $detect_server_loop_once = 1;

    return $pid;
}

sub start_fwknopd() {
    my $test_hr = shift;

    &write_test_file("[+] TEST: $test_hr->{'msg'}\n", $server_test_file);

    return &do_fwknopd_cmd($test_hr->{'fwknopd_cmdline'});
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

sub popen_cmd() {
    my ($test_hr, $cmd_out, $file) = @_;

    unlink $cmd_out if -e $cmd_out;

    my $cmd = $test_hr->{'cmdline'};

    if (-e $file) {
        open AC, ">> $file"
            or die "[*] Could not open $file: $!";
        print AC localtime() . " CMD (popen): | $cmd > $cmd_out 2>&1\n";
        close AC;
    } else {
        open W, "> $file"
            or die "[*] Could not open $file: $!";
        print W localtime() . " CMD (popen): | $cmd > $cmd_out 2>&1\n";
        close W;
    }

    open CMD, "| $cmd > $cmd_out 2>&1" or die $!;
    print CMD $test_hr->{'client_popen'}, "\n";
    close CMD;

    open C, "< $cmd_out" or die "[*] Could not open $cmd_out: $!";
    my @cmd_lines = <C>;
    close C;

    open AC2, ">> $file" or die "[*] Could not open $file: $!";
    for (@cmd_lines) {
        if (/\n/) {
            print AC2 $_;
        } else {
            print AC2 $_, "\n";
        }
    }
    close AC2;

    return 1;
}

sub cache_fw_policy() {
    my $file = shift;
    open FWP, "< $file" or die "[*] Could not open $file: $!";
    while (<FWP>) {
        ### 3   ACCEPT   tcp  --  127.0.0.2...
        ### Since we use the policy cache to detect duplicate rules,
        ### don't allow the rule number itself to make each rule
        ### unique by default
        if (/^\d+\s+(.*)/) {
            $cached_fw_policy{$1} = '';
        }
    }
    close FWP;
}

sub run_cmd() {
    my ($cmd, $cmd_out, $file) = @_;

    unlink $cmd_out if -e $cmd_out;

    if (-e $file) {
        open RC, ">> $file"
            or die "[*] Could not open $file: $!";
        print RC localtime() . " CMD: $cmd\n";
        close RC;
    } else {
        open RCA, "> $file"
            or die "[*] Could not open $file: $!";
        print RCA localtime() . " CMD: $cmd\n";
        close RCA;
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

    open L, ">> $file" or die "[*] Could not open $file: $!";
    for (@cmd_lines) {
        if (/\n/) {
            print L $_;
        } else {
            print L $_, "\n";
        }
    }
    close L;

    if ($rv == 0) {
        return 1;
    }
    return 0;
}

sub dots_print() {
    my $msg = shift;
    &logr($msg . '.');
    my $dots = '';
    for (my $i=length($msg); $i < $PRINT_LEN; $i++) {
        $dots .= '.';
    }
    &logr($dots);
    return;
}

sub validate_test_hash() {
    my $test_hr = shift;
    my $msg = &get_msg($test_hr);
    for my $key (keys %test_keys) {
        if ($test_keys{$key} == $REQUIRED) {
            die "[*] Missing '$key' element in test hash: '$msg'"
                unless defined $test_hr->{$key};
        } elsif ($test_keys{$key} == $OPTIONAL_NUMERIC) {
            $test_hr->{$key} = 0 unless defined $test_hr->{$key};
        } else {
            $test_hr->{$key} = '' unless defined $test_hr->{$key};
        }
    }
    for my $key (keys %$test_hr) {
        die "[*] Unrecognized key '$key' in test hash: '$msg'"
            unless defined $test_keys{$key};
    }
    return;
}

sub validate_test_hashes() {

    ### validate test hashes
    for my $test_hr (@tests) {
        &validate_test_hash($test_hr);
    }

    ### make sure test message strings are unique across all tests
    my %uniq_test_msgs = ();
    for my $test_hr (@tests) {
        my $msg = &get_msg($test_hr);
        if (defined $uniq_test_msgs{$msg}) {
            die "[*] Duplicate test message: $msg";
        } else {
            $uniq_test_msgs{$msg} = '';
        }
    }

    ### validate the 'key_file' and 'server_conf' hash keys
    for my $test_hr (@tests) {
        my $msg = &get_msg($test_hr);
        if ($test_hr->{'key_file'}) {
            if ($test_hr->{'multi_cmds'}) {
                my $found = 0;
                for my $cmd (@{$test_hr->{'multi_cmds'}}) {
                    if ($cmd =~ /\s$test_hr->{'key_file'}\b/) {
                        $found = 1;
                        last;
                    }
                }
            } else {
                unless ($test_hr->{'cmdline'} =~ /\s$test_hr->{'key_file'}\b/) {
                    die "[*] 'key_file' value: '$test_hr->{'key_file'}' not matched in " .
                        "client command line '$test_hr->{'cmdline'}' for: $msg";
                }
            }
        }

        if ($test_hr->{'server_conf'}) {
            unless ($test_hr->{'fwknopd_cmdline'} =~ /\s$test_hr->{'server_conf'}\b/) {
                die "[*] 'server_conf' value: '$test_hr->{'server_conf'}' not matched in " .
                    "server command line '$test_hr->{'fwknopd_cmdline'}' for: $msg";
            }
        }
    }

    ### for fwknop/fwknopd commands, prepend LD_LIBRARY_PATH and valgrind args
    for my $test_hr (@tests) {
        next if $test_hr->{'disable_valgrind'} eq $YES;

        ### don't add LD_LIBRARY_PATH for tests run underneath fiu-run
        next if $test_hr->{'subcategory'} =~ /fiu\-run/;

        if ($test_hr->{'cmdline'} =~ /^$fwknopCmd/
                or $test_hr->{'cmdline'} =~ /^$fwknopdCmd/) {
            my $str = $lib_view_str;
            unless ($test_hr->{'disable_valgrind'} eq $YES) {
                $str .= " $valgrind_str";
            }
            $test_hr->{'cmdline'} = "$str $test_hr->{'cmdline'}";
        } elsif ($test_hr->{'cmdline'} =~ /LD_LIBRARY_PATH/) {
            if ($lib_view_cmd =~ /otool/) {
                if ($test_hr->{'cmdline'} !~ /DYLD_LIBRARY_PATH/) {
                    $test_hr->{'cmdline'}
                        =~ s/(LD_LIBRARY_PATH=\S+)/$1 DYLD_LIBRARY_PATH=$lib_dir/;
                }
            }
        }
        if ($test_hr->{'fwknopd_cmdline'} =~ /^$fwknopdCmd/) {
            my $str = $lib_view_str;
            unless ($test_hr->{'disable_valgrind'} eq $YES) {
                $str .= " $valgrind_str";
            }
            $test_hr->{'fwknopd_cmdline'} = "$str $test_hr->{'fwknopd_cmdline'}";
        }
    }

    return;
}

sub init() {

    $|++; ### turn off buffering

    unless ($client_only_mode or $list_mode) {
        $< == 0 && $> == 0 or
            die "[*] $0: You must be root (or equivalent ",
                "UID 0 account) to effectively test fwknop";
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

    unlink $init_file if -e $init_file;
    unlink $logfile   if -e $logfile;

    $do_profile_init = 1 unless $test_include or $rerun_failed_mode;

    ### always restore the gpg and access %include directories before
    ### tests are executed
    &restore_dir($gpg_dirs_tar);
    &restore_dir($access_include_dirs_tar);

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

    ### cache the configure args that were used before running the
    ### test suite
    if (-e $config_log) {
        open F, "< $config_log" or die $!;
        while (<F>) {
            ###   $ ./configure --prefix=/usr --sysconfdir=/etc ...
            if (m/^\s+[\$#]\s+(\.\/configure.*)/) {
                $orig_config_args = $1;
                last;
            }
        }
        close F;
    }

    if ($enable_openssl_compatibility_tests) {
        $openssl_path = &find_command('openssl') unless $openssl_path;
        if ($openssl_path) {
            require MIME::Base64;
            MIME::Base64->import(qw(encode_base64 decode_base64));
            $base64_path = &find_command('base64') unless $base64_path;

            ### check for hmac openssl support
            &openssl_hmac_style_check();

        } else {
            print "[-] openssl checks requested, but openssl ",
                " command not found, disabling.\n";
            $enable_openssl_compatibility_tests = 0;
        }
    }

    if ($enable_valgrind) {
        $valgrind_path = &find_command('valgrind') unless $valgrind_path;
        unless ($valgrind_path) {
            print "[-] --enable-valgrind mode requested ",
                "but valgrind not found, disabling.\n";
            push @tests_to_exclude, qr/$cpan_valgrind_mod/;
            $enable_valgrind = 0;
        }
    }

    if ($enable_fault_injection) {
        $fiu_run_path = &find_command('fiu-run') unless $fiu_run_path;
        $enable_fault_injection = 0 unless $fiu_run_path;
    }

    $enable_perl_module_checks = 1
        if $enable_perl_module_fuzzing_spa_pkt_generation;

    if ($fuzzing_test_tag) {
        $fuzzing_test_tag .= '_' unless $fuzzing_test_tag =~ /_$/;
    }

    unless ($enable_cunit_tests) {
        push @tests_to_exclude, qr/cunit tests/;
    }
    unless ($enable_valgrind) {
        push @tests_to_exclude, qr/with valgrind/;
    }

    unless ($enable_fault_injection) {
        push @tests_to_exclude, qr/fault injection/;
    }

    unless ($enable_recompilation_warnings_check
            or $enable_profile_coverage_check) {
        ### don't recompile if we're in looking at code
        ### coverage - that is what --profile-coverage-init
        ### is for
        push @tests_to_exclude, qr/recompilation/;
    }

    unless ($enable_configure_args_checks) {
        push @tests_to_exclude, qr/configure args/;
    }

    unless ($enable_make_distcheck) {
        push @tests_to_exclude, qr/distcheck/;
    }

    unless ($enable_client_ip_resolve_test) {
        push @tests_to_exclude, qr/IP resolve/;
    }

    $perl_path = &find_command('perl') unless $perl_path;

    if ($enable_perl_module_checks) {
        open F, "< $fuzzing_pkts_file" or die $!;
        while (<F>) {
            next if /^#/;
            if (/(?:Bogus|Invalid_encoding)\s(\S+)\:\s+(.*)\,\sSPA\spacket\:\s(\S+)/) {
                push @{$fuzzing_spa_packets{$1}{$2}}, $3;
                $total_fuzzing_pkts++;
            }
        }
        close F;

        ### check to see if the Test::Valgrind module is installed
        if ($enable_valgrind and $valgrind_path) {
            unless (&run_cmd("$perl_path -e 'use $cpan_valgrind_mod'",
                    $cmd_out_tmp, $curr_test_file) and &find_command('prove')) {
                push @tests_to_exclude, qr/$cpan_valgrind_mod/;
            }
        } else {
            push @tests_to_exclude, qr/$cpan_valgrind_mod/;
        }
    } else {
        push @tests_to_exclude, qr/perl FKO module/;
    }

    if ($enable_python_module_checks) {
        die "[*] The python test script: $python_script doesn't exist ",
            "or is not executable."
            unless -e $python_script and -x $python_script;
        $python_path = &find_command('python') unless $python_path;
        unless ($python_path) {
            push @tests_to_exclude, qr/python fko extension/
        }
    } else {
        push @tests_to_exclude, qr/python fko extension/;
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

    $sudo_path    = &find_command('sudo') unless $sudo_path;
    $killall_path = &find_command('killall') unless $killall_path;
    $pgrep_path   = &find_command('pgrep') unless $pgrep_path;
    $pkill_path   = &find_command('pkill') unless $pkill_path;
    $lib_view_cmd = &find_command('ldd') unless $lib_view_cmd;
    $git_path     = &find_command('git') unless $git_path;
    $prove_path   = &find_command('prove') unless $prove_path;
    $touch_path   = &find_command('touch') unless $touch_path;
    $readelf_path = &find_command('readelf') unless $readelf_path;

    if ($sudo_path) {
        $username = (getpwuid((stat($test_suite_path))[4]))[0];
        die "[*] Could not determine $test_suite_path owner"
            unless $username;

        ### see if sudo is configured to accept custom configs
        SCONF: for my $sudo_conf ('/etc/sudoers', '/usr/local/etc/sudoers') {
            next SCONF unless -e $sudo_conf;
            open SR, "< $sudo_conf" or die $!;
            LINES: while (<SR>) {
                if (/^#includedir\s+(\/\S+)/) {
                    my $dir = $1;
                    next LINES unless -d $dir;
                    $sudo_conf_testing = "$dir/fwknop_testing";
                    last LINES;
                }
            }
            close SR;
            last SCONF;
        }
    }

    push @tests_to_exclude, qr/sudo/ unless $sudo_conf_testing;
    push @tests_to_exclude, qr/user.*\sparity/
        unless $username and $username ne 'root';

    ### see if the 'nobody' user is on the system
    unless (getpwnam('nobody')) {
        push @tests_to_exclude, qr/setuid nobody/;
    }

    ### On Mac OS X look for otool instead of ldd
    unless ($lib_view_cmd) {
        $lib_view_cmd = &find_command('otool');
        if ($lib_view_cmd) {
            $lib_view_str .= " DYLD_LIBRARY_PATH=$lib_dir";
            $lib_view_cmd .= ' -L';
        } else {
            $lib_view_cmd = '#';  ### comment out subsequent shell commands
        }
    }

    unless ((&find_command('cc') or &find_command('gcc')) and &find_command('make')) {
        ### disable compilation checks
        push @tests_to_exclude, qr/recompilation/;
    }

    $gcov_path = &find_command('gcov') unless $gcov_path;
    $lcov_path = &find_command('lcov') unless $lcov_path;
    $genhtml_path = &find_command('genhtml') unless $genhtml_path;

    unless ($ip_path or $ifconfig_path) {
        push @tests_to_exclude, qr/down interface/;
    }

    ### see if we're compiled with AddressSanitizer support
    if (&asan_compiled_binary()) {
        $asan_mode = 1;
        $asan_instrumentation_check = 1;
    } else {
        push @tests_to_exclude, qr/ASAN/;
    }

    ### see if we're compiled with UndefinedBehaviorSanitizer support
    if (&file_find_regex([qr/enable\-ubsan\-support/],
            $MATCH_ALL, $NO_APPEND_RESULTS, $config_log)) {
        $asan_mode = 1;
    } else {
        &write_test_file("[-] Can't find --enable-ubsan-support in $config_log\n",
            $curr_test_file);
        push @tests_to_exclude, qr/UBSAN/;
    }

    if ($gcov_path) {
        if ($enable_profile_coverage_check
                and not $list_mode) {
            if ($enable_profile_coverage_init or $do_profile_init) {
                if (&file_find_regex([qr/\-enable\-profile\-coverage/],
                        $MATCH_ALL, $NO_APPEND_RESULTS, $config_log)) {
                    print "[+] Found --enable-profile-coverage\n";
                } else {
                    print "[-] Warning: --enable-profile-coverage not ",
                        "found, use ./configure --enable-profile-coverage?\n";
                }
                &run_cmd($profile_rm_files_sh, $cmd_out_tmp, $curr_test_file);
                &run_cmd($profile_init_sh, $cmd_out_tmp, $curr_test_file);
            }
            push @tests_to_exclude, qr/distcheck/;
        }
    } else {
        push @tests_to_exclude, qr/profile coverage/;
    }

    ### unless we are in client only mode, see if the target firewall
    ### is PF (since FreeBSD can be either ipfw or PF for example)
    if (-e $fwknopdCmd) {
        my $fw = '';
        my $cmd = "$fwknopdCmd -c $cf{'def'} -a $cf{'def_access'} -D";
        open F, "$cmd 2>&1 |" or die "[*] Could not execute $cmd $!";
        while (<F>) {
            if (m|FIREWALL_EXE.*/(\S+)'|) {
                $fw = $1;
                last;
            }
        }
        close F;

        if ($fw eq 'pfctl') {
            push @tests_to_exclude, qr|active/expire sets|;
            push @tests_to_exclude, qr|ipfw|;
        }
    }

    for my $file ($default_digest_file, "${default_digest_file}-old") {
        if (-e $file) {
            unlink $file;
        }
    }

    ### write out the latest git commit hash as a way to help track
    ### what code is actually being tested
    if ($git_path) {
        &run_cmd("$git_path branch", $cmd_out_tmp, $curr_test_file);
        &run_cmd("$git_path log | grep commit | head -n 1",
            $cmd_out_tmp, $curr_test_file);
    }

    system $cores_pattern_sh if $enable_cores_pattern_mode;

    return;
}

sub os_fw_detect() {
    open UNAME, "uname |" or die "[*] Could not execute uname: $!";
    while (<UNAME>) {
        if (/linux/i) {
            $platform = $LINUX;
            last;
        } elsif (/freebsd/i) {
            $platform = $FREEBSD;
            last;
        } elsif (/darwin/i) {
            $platform = $MACOSX;
            last;
        }
    }
    close UNAME;

    if ($platform eq $LINUX) {
        if ($prefer_iptables) {
            $fw_bin = $fw_bin_and_prefix = &find_command('iptables');
        } else {
            $fw_bin = &find_command('firewall-cmd');
            if ($fw_bin) {
                $FW_TYPE   = 'firewalld';
                $FW_PREFIX = 'FIREWD';
                $fw_conf_prefix = 'firewd';
                $fw_bin_and_prefix = "$fw_bin --direct --passthrough ipv4";
            } else {
                $fw_bin = $fw_bin_and_prefix = &find_command('iptables');
            }
        }
    } else {
        push @tests_to_exclude, qr/NAT\b/;
        push @tests_to_exclude, qr/MASQ/;
        push @tests_to_exclude, qr/INPUT/;
        push @tests_to_exclude, qr/FORWARD/;
        push @tests_to_exclude, qr/IPT_/;
        push @tests_to_exclude, qr/\bchain\b/;
        push @tests_to_exclude, qr/\bjump\b/;
        push @tests_to_exclude, qr/iptables/;
        push @tests_to_exclude, qr/firewalld/;
        push @tests_to_exclude, qr|dupe rule|; ### not handled yet on non-iptables firewalls
        push @tests_to_exclude, qr|ipt\-no|;
        $fw_bin = &find_command('pfctl');
        if ($fw_bin) {
            $FW_TYPE = 'pf';
        } else {
            $fw_bin = &find_command('ipfw');
            if ($fw_bin) {
                $FW_TYPE = 'ipfw';
            }
        }
    }
    unless ($platform eq $FREEBSD or $platform eq $MACOSX) {
        push @tests_to_exclude, qr|active/expire sets|;
        push @tests_to_exclude, qr|ipfw|;
    }
    return;
}

sub preserve_previous_test_run_results() {

    return if $list_mode;

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

    for my $dir ($run_dir, $run_tmp_dir_top) {
        if (-d $dir) {
            rmtree $dir or die $!;
        }
    }

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
    return;
}

sub restore_dir() {
    my $tarfile = shift;

    my $curr_pwd = cwd() or die $!;

    chdir $conf_dir or die $!;

    if (-e $gpg_dirs_tar) {
        system "tar xfz $tarfile > /dev/null";
    }

    chdir $curr_pwd or die $!;

    return;
}

sub openssl_hmac_style_check() {
    if (&run_cmd("$openssl_path dgst -hex -sha256 -mac HMAC " .
            "-macopt hexkey:61616161 $0", $cmd_out_tmp, $curr_test_file)) {
        &write_test_file("[+] OpenSSL supports HMAC hexkey option.\n",
            $curr_test_file);
        $openssl_hmac_hexkey_supported = 1;
    } elsif (&run_cmd("$openssl_path dgst -hex -sha256 -hmac dummykey $0",
            $cmd_out_tmp, $curr_test_file)) {
        &write_test_file("[+] OpenSSL does not support the HMAC hexkey option.\n",
            $curr_test_file);
        $openssl_hmac_hexkey_supported = 0;
    } else {
        print "[-] openssl hmac syntax unknown, disabling.\n";
        $enable_openssl_compatibility_tests = 0;
    }

    return;
}

sub identify_loopback_intf() {
    return if $loopback_intf;

    die "[*] ip and ifconfig commands not found, use --loopback <name>"
        unless $ip_path or $ifconfig_path;

    ### Linux 'ip addr'
    ### 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    ###     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    ###     inet 127.0.0.1/8 scope host lo
    ###         valid_lft forever preferred_lft forever
    ###     inet6 ::1/128 scope host
    ###         valid_lft forever preferred_lft forever

    ### Linux 'ifconfig -a':

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

    if ($ip_path) {
        my $cmd = "$ip_path addr";
        open C, "$cmd |" or die "[*] (use --loopback <name>) $cmd: $!";
        while (<C>) {
            if (/^\s*\d+\:\s+(\S+?)\:\s+.*loopback/i) {
                $intf = $1;
                next;
            }
            if (/^\S/ and $intf and not $found_loopback_intf) {
                ### should not happen
                last;
            }
            if ($intf and /\b127\.0\.0\.1/) {
                $found_loopback_intf = 1;
                last;
            }
        }
        close C;
    } else {
        my $cmd = "$ifconfig_path -a";
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
    }

    die "[*] could not determine loopback interface, use --loopback <name>"
        unless $found_loopback_intf;

    $loopback_intf = $intf;

    return;
}

sub import_previous_valgrind_coverage_info() {

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
                $prev_valgrind_file_titles{$type}{$test_title} = $file;
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

sub compile_wrapper() {
    my $make_arg = shift;

    unless (-d $fko_wrapper_dir) {
        &write_test_file("[-] fko wrapper directory " .
            "$fko_wrapper_dir does not exist.\n", $curr_test_file);
        return 0;
    }

    chdir $fko_wrapper_dir or die $!;

    ### 'make clean' as root
    unless (&run_cmd('make clean', $cmd_out_tmp, $curr_test_file)) {
        chdir '..' or die $!;
        return 0;
    }

    my $make_str = 'make';
    $make_str .= " $make_arg" if $make_arg;

    if ($sudo_path) {
        unless (&run_cmd("$sudo_path -u $username $make_str",
                "../$cmd_out_tmp", $curr_test_file)) {
            unless (&run_cmd($make_str, "../$cmd_out_tmp",
                    $curr_test_file)) {
                chdir '..' or die $!;
                return 0;
            }
        }

    } else {

        unless (&run_cmd($make_str, "../$cmd_out_tmp",
                $curr_test_file)) {
            chdir '..' or die $!;
            return 0;
        }
    }

    chdir '..' or die $!;
    return 1;
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
        my $is_prove_output = 0;

        open F, "< $file" or die $!;
        while (<F>) {
            ### ==30969==    by 0x4E3983A: fko_set_username (fko_user.c:65)
            if (/^==.*\sby\s\S+\:\s(\S+)\s(.*)/) {
                $valgrind_flagged_fcns{$type}{"$1 $2"}++;
                $valgrind_flagged_fcns_unique{$type}{$1}++;
                $file_scope_flagged_fcns{"$1 $2"}++;
                $file_scope_flagged_fcns_unique{$1}++;
            } elsif ($is_prove_output) {
                ###     fko_decrypt_spa_data (/home/mbr/git/fwknop.git/lib/.libs/libfko.so.2.0.0) [fko_encryption.c:264]
                if (/\s(\S+)\s\(.*\/libfko\.so\..*?\)\s(.*)/) {
                    $valgrind_flagged_fcns{$type}{"$1 $2"}++;
                    $valgrind_flagged_fcns_unique{$type}{$1}++;
                    $file_scope_flagged_fcns{"$1 $2"}++;
                    $file_scope_flagged_fcns_unique{$1}++;
                }
            } elsif (/TEST\:\s/) {
                $test_title = $_;
                chomp $test_title;
                $is_prove_output = 1 if $test_title =~ /Test\:\:Valgrind/;
                last if $test_title =~ /valgrind\soutput/;

                ### exclude the start/stop test since it involves signals
                ### that force leaks
                last if $test_title =~ /start restart stop/;
            }
        }
        close F;

        next FILE if $test_title =~ /valgrind\soutput/;
        next FILE unless $filename;

        ### write out flagged fcns for this file
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
                        $new_flagged_fcns  = 1;
                    }
                } else {
                    open F, ">> $curr_test_file" or die $!;
                    print F "[-] $filename ($type) '$test_title' --> NEW valgrind flagged function: $fcn\n";
                    close F;
                    $new_flagged_fcns  = 1;
                }
            }
        }

        if ($new_flagged_fcns) {
            open F, ">> $curr_test_file" or die $!;
            print F "[-] $filename ($test_title) New and/or greater number of valgrind flagged function calls\n";
            close F;
            $rv = 0;
        } else {
            unless (defined $prev_valgrind_file_titles{$type}
                    and $prev_valgrind_file_titles{$type}{$test_title}) {
                open F, ">> $curr_test_file" or die $!;
                print F "[.] Skipping $filename ($test_title), no matching previous valgrind output.\n";
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

    my $rv = 1;

    my $conf_args = $default_server_conf_args;

    my $ipv6_arg = '';
    if (&get_msg($test_hr) =~ /IPv6/) {
        $ipv6_arg = '--ipv6';
    }

    if ($test_hr->{'server_conf'}) {
        $conf_args = "-c $test_hr->{'server_conf'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file";
    }

    if ($test_hr->{'no_ip_check'}) {
        &run_cmd("$lib_view_str $fwknopdCmd $ipv6_arg " .
                qq{$conf_args --fw-list | grep -v "# DISABLED" },
                $cmd_out_tmp, $curr_test_file);
        unless (&file_find_regex([qr/_exp_/],
                $MATCH_ALL, $NO_APPEND_RESULTS, $cmd_out_tmp)) {
            $rv = 0;
        }
    } else {
        &run_cmd("$lib_view_str $fwknopdCmd $ipv6_arg " .
                qq{$conf_args --fw-list | grep -v "# DISABLED" },
                $cmd_out_tmp, $curr_test_file);
        if ($test_hr->{'insert_duplicate_rule_while_running'}) {
            ### see if there is a new rule that wasn't in the
            ### policy before the SPA packet was sent
            my $new_fw_rule = 0;
            open FWPOL, "< $cmd_out_tmp" or die $!;
            while (<FWPOL>) {
                my $line = $_;
                if ($line =~ /^\d+\s+(.*)/) {
                    if (not defined $cached_fw_policy{$1}) {
                        &write_test_file(
                            "[.] Found new rule not found in previously cached policy: $line\n",
                            $curr_test_file);
                        $new_fw_rule = 1;
                        last;
                    }
                }
            }
            close FWPOL;
            $rv = 0 unless $new_fw_rule;
        } else {
            if ($ipv6_arg) {
                unless (&file_find_regex([qr/\s$fake_ip6\s.*_exp_/],
                        $MATCH_ALL, $NO_APPEND_RESULTS, $cmd_out_tmp)) {
                    $rv = 0;
                }
            } else {
                unless (&file_find_regex([qr/\s$fake_ip\s.*_exp_/],
                        $MATCH_ALL, $NO_APPEND_RESULTS, $cmd_out_tmp)) {
                    $rv = 0;
                }
            }
        }
    }

    if ($fw_bin and $FW_TYPE eq 'firewalld' or $FW_TYPE eq 'iptables') {
        ### make sure there is at least one jump rule
        ###    79  5304 FWKNOP_INPUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0
        unless (&run_cmd("$fw_bin_and_prefix -t filter " .
                "-nL -v | grep -v Chain | grep FWKNOP_ ", $cmd_out_tmp, $curr_test_file)) {
            &write_test_file("[-] No jump rule found.\n", $curr_test_file);
            $rv = 0;
        }
    }

    return $rv;
}

sub asan_compiled_binary() {

    my $lib_bin = '../lib/.libs/libfko.so';
    if (&run_cmd("$readelf_path -a $lib_bin | grep __asan",
                $cmd_out_tmp, $curr_test_file)) {
        &write_test_file("[+] $lib_bin is compiled with ASAN support\n",
            $curr_test_file);
        return 1;
    }
    &write_test_file("[-] $lib_bin is NOT compiled with ASAN support\n",
        $curr_test_file);
    return 0;
}

sub global_fwknopd_pgrep_check() {
    my $rv = 0;
    if ($pgrep_path) {
        open PGREP, "$pgrep_path fwknopd |" or die $!;
        while (<PGREP>) {
            if (/(\d+)/) {
                print "[*] Found existing fwknopd pid: $1\n";
                $rv = 1;
            }
        }
        close PGREP;
    } else {
        $rv = &is_fwknopd_running();
    }
    return $rv;
}

sub is_fwknopd_running() {

    &run_cmd("$lib_view_str $fwknopdCmd $default_server_conf_args " .
        "--status", $cmd_out_tmp, $curr_test_file);

    return 1 if &file_find_regex([qr/Detected\sfwknopd\sis\srunning/i],
            $MATCH_ALL, $APPEND_RESULTS, $cmd_out_tmp);

    return 0;
}

sub stop_fwknopd() {

    my $pid = &is_pid_running($default_pid_file);

    if ($pid) {
        &write_test_file("[+] stop_fwknopd() fwknopd is running, pid: $pid\n",
            $curr_test_file);
    } else {
        &write_test_file("[-] stop_fwknopd() fwknopd is not running.\n",
            $curr_test_file);
        ### make certain there is no running fwknopd process
        system "$killall_path fwknopd 2> /dev/null" if $killall_path;
        return;
    }

    &run_cmd("$lib_view_str $fwknopdCmd " .
        "$default_server_conf_args -K", $cmd_out_tmp, $curr_test_file);

    ### look for fwknopd to be stopped
    my $tries = 1;
    if (not &is_pid_running($default_pid_file)
            and &file_find_regex(
            [qr/Got\sSIGTERM/],
            $MATCH_ALL, $NO_APPEND_RESULTS, $server_cmd_tmp)) {
        &write_test_file("[+] stop_fwknopd() fwknopd received SIGTERM\n",
            $curr_test_file);
    } else {
        if (&is_pid_running($default_pid_file)) {
            while (&is_pid_running($default_pid_file)) {
                &write_test_file("[-] stop_fwknopd() " .
                    "fwknopd still running, try: $tries\n", $curr_test_file);
                &run_cmd("$lib_view_str $fwknopdCmd $default_server_conf_args -K",
                    $cmd_out_tmp, $curr_test_file);
                $tries++;
                last if $tries == 10;   ### should be plenty of tries
                sleep 1;
            }
        } else {
            &write_test_file("[-] stop_fwknopd() fwknopd stopped with SIGKILL\n",
                $curr_test_file);
        }
    }

    if ($tries == 10) {
        &write_test_file("[-] stop_fwknopd() fwknopd not stopped with -K\n",
            $curr_test_file);
    }

    ### open the pid file and send signal manually if -K didn't work
    if (-e $default_pid_file) {
        ### don't manually send signal immediately after
        ### fwknopd wrote 'Got SIGTERM'
        sleep 1 if $tries == 1;
        my $sig_tries = 0;
        while (&is_pid_running($default_pid_file)) {
            &write_test_file("[.] Manually sending pid: $pid SIGTERM.\n",
                $curr_test_file);
            unless (kill 15, $pid) {
                &write_test_file("[.] Manually sending pid: $pid SIGKILL.\n",
                    $curr_test_file);
                kill 9, $pid;
            }
            $sig_tries++;
            last if $sig_tries == 3;
            sleep 1;
        }
    }

    ### make certain fwknopd is stopped. Test suite interactions with fwknop
    ### are complex, and having a running fwknopd process that may be been
    ### "lost" can interfere with test results
    system "$killall_path fwknopd 2> /dev/null" if $killall_path;

    return;
}

sub is_pid_running() {
    my $pid_file = shift;
    return 0 unless -e $pid_file;
    open F, "< $pid_file" or die "[*] Could not open pid file: $!";
    my $pid = <F>;
    close F;
    chomp $pid;
    if (kill 0, $pid) {
        return $pid;
    }
    return 0;
}

sub file_find_num_matches() {
    my ($re, $append_results_flag, $file) = @_;

    my $num_matches = 0;

    my $tries = 0;
    while (not -e $file) {
        $tries++;
        sleep 1;
        return 0 if $tries == 5;
    }

    open F, "< $file" or
        (&write_test_file("[-] Could not open $file: $!\n", $curr_test_file) and return 0);
    while (<F>) {
        next if /file_find_num_matches\(\)/;
        if (/$re/) {
            $num_matches++;
        }
    }
    close F;

    if ($append_results_flag == $APPEND_RESULTS) {
        &write_test_file("[.] file_find_num_matches() Matched '$re' $num_matches times.",
            $file);
    }

    return $num_matches;
}

sub file_find_regex() {
    my ($re_ar, $match_style, $append_results_flag, $file) = @_;

    my $found_all_regexs = 1;
    my $found_single_match = 0;
    my @write_lines = ();
    my @file_lines = ();

    my $tries = 0;
    while (not -e $file) {
        $tries++;
        sleep 1;
        return 0 if $tries == 5;
    }

    if (open (RE, "<", $file)) {
        while (<RE>) {
            push @file_lines, $_;
        }
        close RE;
    } else {
         &write_test_file("[-] Could not open $file: $!\n", $curr_test_file) and return 0;
    }

    for my $re (@$re_ar) {
        my $matched = 0;
        my $line_ctr = 0;
        for my $line (@file_lines) {
            $line_ctr++;
            next if $line =~ /file_find_regex\(\)/;
            if ($line =~ $re) {
                push @write_lines, "[.] file_find_regex() " .
                    "Matched '$re' with line $line_ctr: $line";
                $matched = 1;
                $found_single_match = 1;
                last if $append_results_flag == $NO_APPEND_RESULTS;
            }
        }
        unless ($matched) {
            push @write_lines, "[.] file_find_regex() " .
                "Did not match regex '$re' from regexs: '@$re_ar' " .
                "within file: $file\n";
            $found_all_regexs = 0;
        }
    }

    if ($append_results_flag == $APPEND_RESULTS) {
        for my $line (@write_lines) {
            &write_test_file($line, $file);
        }
    }

    if ($match_style == $MATCH_ANY) {
        return $found_single_match;
    }

    return $found_all_regexs;
}

sub remove_permissions_warnings() {
    return unless -e "$output_dir/1.test";
    system qq|perl -p -i -e 's/.*not owned by current effective.*\n//' $output_dir/*.test|;
    system qq|perl -p -i -e 's/.*permissions should only be user.*\n//' $output_dir/*.test|;
    return;
}

sub rm_tmp_files() {
    for my $file ($cmd_out_tmp, $server_cmd_tmp, $openssl_cmd_tmp) {
        unlink $file if -e $file;
    }
    return;
}

sub find_command() {
    my $cmd = shift;

    my $path = '';
    open C, "which $cmd 2>&1 |" or die "[*] Could not execute: which $cmd: $!";
    while (<C>) {
        if (m|^(/.*$cmd)$|) {
            $path = $1;
            last;
        }
    }
    close C;
    return $path;
}

sub import_test_files() {
    for my $file (@test_files) {
        die "[*] tests file: $file does not exist"
            unless -e $file;
        require $file or die "[*] Could not 'require $file': $!";
    }
    return;
}

sub write_test_file() {
    my ($msg, $file) = @_;

    if (-e $file) {
        open WT, ">> $file"
            or die "[*] Could not open $file: $!";
        print WT $msg;
        close WT;
    } else {
        open WT, "> $file"
            or die "[*] Could not open $file: $!";
        print WT $msg;
        close WT;
    }
    return;
}

sub logr() {
    my $msg = shift;
    print STDOUT $msg;
    open F, ">> $logfile"
        or die "[*] Could not append msg '$msg' to $logfile: $!";
    print F $msg;
    close F;
    return;
}

sub usage() {
    print <<_HELP_;

[+] $0 <options>

    -A   --Anonymize-results           - Prepare anonymized results at:
                                         $tarfile
    --enable-all                       - Enable tests that aren't enabled by
                                         default.  This also enables running all
                                         tests under valgrind, so if you need
                                         fast results this can be disabled by also
                                         specifying --disable-valgrind.
    --enable-complete                  - Enable even more tests --enable-all such
                                         fuzzing interfaces, fault injection, and
                                         code coverage.
    --enable-dist-check                - Test 'make dist' run.
    --enable-profile-coverage          - Generate profile coverage stats with an
                                         emphasis on finding functions that the
                                         test suite does not call.
    --enable-profile-coverage-init     - Reset .gcov coverage counters to zero.
    --enable-recompile                 - Recompile fwknop sources and look for
                                         compilation warnings.
    --enable-configure-args-checks     - Run the autoconf configure script with
                                         various args to check compilation
                                         results.
    --enable-cunit-tests               - Check output of Cunit tests - requires
                                         './configure --enable-c-unit-tests'.
    --enable-valgrind                  - Run every test underneath valgrind.
    --disable-valgrind                 - Disable valgrind mode (useful sometimes
                                         when --enable-all is used to have
                                         everything except for valgrind enabled).
    --enable-ip-resolve                - Enable client IP resolution (-R) test -
                                         this requires internet access.
    --enable-distcheck                 - Enable 'make dist' check.
    --enable-perl-module-checks        - Run a series of tests against libfko via
                                         the perl FKO module.
    --enable-perl-module-pkt-gen       - Generate a series of fuzzing packets via
                                         the perl FKO module (assumes a patched
                                         libfko code to accept fuzzing values).
                                         The generated packets are placed in:
                                         $fuzzing_pkts_file
    --enable-openssl-checks            - Enable tests to verify that Rijndael
                                         cipher usage is compatible with openssl.
    --disable-openssl-checks           - Disable OpenSSL verification tests.
    --gdb-test <test file>             - Run the same command a previous test suite
                                         execution through gdb by specifying the
                                         output/ test file.
    --test-limit <number>              - Limit the number of executed tests.
    --diff                             - Compare the results of one test run to
                                         another.  By default this compares output
                                         in ${output_dir}.last to $output_dir
    --diff-dir1=<path>                 - Left hand side of diff directory path,
                                         default is: ${output_dir}.last
    --diff-dir2=<path>                 - Right hand side of diff directory path,
                                         default is: $output_dir
    --include=<regex>                  - Specify a regex to be used over test
                                         names that must match.
    --exclude=<regex>                  - Specify a regex to be used over test
                                         names that must not match.
    --fuzzing-pkts-file <file>         - Specify path to fuzzing packet file.
    --fuzzing-pkts-append              - When generating new fuzzing packets,
                                         append them to the fuzzing packets file.
    --List                             - List test names.
    --test-limit=<num>                 - Limit the number of tests that will run.
    --loopback-intf=<intf>             - Specify loopback interface name (default
                                         depends on the OS where the test suite
                                         is executed).
    --output-dir=<path>                - Path to output directory, default is:
                                         $output_dir
    --fwknop-path=<path>               - Path to fwknop binary, default is:
                                         $fwknopCmd
    --fwknopd-path=<path>              - Path to fwknopd binary, default is:
                                         $fwknopdCmd
    --lib-dir=<path>                   - For LD_LIBRARY_PATH, default is:
                                         $lib_dir
    --client-only-mode                 - Run client-only tests.
    --server-only-mode                 - Run server-only tests.
    --valgrind-path=<path>             - Specify path to valgrind
    --valgrind-prev-cov-dir=<path>     - Path to previous valgrind-coverage
                                         directory (defaults to:
                                         "output.last/valgrind-coverage").
    --valgrind-suppressions-file       - Path to the valgrind suppressions file,
                                         default is: $valgrind_suppressions_file
    --valgrind-disable-suppressions    - Disable valgrind suppressions (current
                                         suppressions are for gpgme).
    --valgrind-disable-child-silent    - Disable valgrind --child-silent-after-fork
                                         option (enabled because of gpgme).
    --enable-valgrind-gen-suppressions - Generate valgrind suppressions for any
                                         valgrind error discoveries.
    --rerun-failed                     - Repeats the last test run, but only runs
                                         the failed tests.  This command does not
                                         reset the coverage statistics.  A useful
                                         tactic is to couple this flag with
                                         the faketime command in order to allow
                                         tests with timing problems to pass on
                                         slower systems.  Suggested command would be
                                         \"sudo faketime -f \'+0 x0.25\'
                                         ./test-fwknop.pl --rerun-failed\"
    --cmd-verbose=<str>                - Set the verbosity level of executed fwknop
                                         commands, default is:
                                         $verbose_str
    -h   --help                        - Display usage on STDOUT and exit.

_HELP_
    exit 0;
}
