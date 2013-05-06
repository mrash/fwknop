#!/usr/bin/perl -w
#
# This is the main driver program for the fwknop test suite.  Test definitions
# are imported from the tests/ directory.
#

use Cwd;
use File::Copy;
use File::Path;
use IO::Socket;
use Data::Dumper;
use Cwd;
use Getopt::Long 'GetOptions';
use strict;

#==================== config =====================
my $logfile         = 'test.log';
our $local_key_file = 'local_spa.key';
our $local_hmac_key_file = 'local_hmac_spa.key';
my $output_dir      = 'output';
our $conf_dir       = 'conf';
my $run_dir         = 'run';
my $cmd_out_tmp     = 'cmd.out';
my $server_cmd_tmp  = 'server_cmd.out';
my $openssl_cmd_tmp = 'openssl_cmd.out';
my $data_tmp        = 'data.tmp';
my $key_tmp         = 'key.tmp';
my $enc_save_tmp    = 'openssl_save.enc';
my $test_suite_path = 'test-fwknop.pl';
my $gpg_dir_orig_tar = 'gpg_dirs_orig.tar.gz';
our $gpg_client_home_dir = "$conf_dir/client-gpg";
our $gpg_client_home_dir_no_pw = "$conf_dir/client-gpg-no-pw";
our $replay_pcap_file = "$conf_dir/spa_replay.pcap";

our $lib_dir = '../lib/.libs';

our %cf = (
    'nat'                          => "$conf_dir/nat_fwknopd.conf",
    'def'                          => "$conf_dir/default_fwknopd.conf",
    'def_access'                   => "$conf_dir/default_access.conf",
    'hmac_access'                  => "$conf_dir/hmac_access.conf",
    'hmac_get_key_access'          => "$conf_dir/hmac_get_key_access.conf",
    'hmac_no_b64_access'           => "$conf_dir/hmac_no_b64_access.conf",
    'hmac_md5_access'              => "$conf_dir/hmac_md5_access.conf",
    'hmac_md5_short_key_access'    => "$conf_dir/hmac_md5_short_key_access.conf",
    'hmac_md5_long_key_access'     => "$conf_dir/hmac_md5_long_key_access.conf",
    'hmac_sha1_access'             => "$conf_dir/hmac_sha1_access.conf",
    'hmac_sha1_short_key_access'   => "$conf_dir/hmac_sha1_short_key_access.conf",
    'hmac_sha1_long_key_access'    => "$conf_dir/hmac_sha1_long_key_access.conf",
    'hmac_sha256_access'           => "$conf_dir/hmac_sha256_access.conf",
    'hmac_sha256_short_key_access' => "$conf_dir/hmac_sha256_short_key_access.conf",
    'hmac_sha256_long_key_access'  => "$conf_dir/hmac_sha256_long_key_access.conf",
    'hmac_sha384_access'           => "$conf_dir/hmac_sha384_access.conf",
    'hmac_sha384_short_key_access' => "$conf_dir/hmac_sha384_short_key_access.conf",
    'hmac_sha384_long_key_access'  => "$conf_dir/hmac_sha384_long_key_access.conf",
    'hmac_sha512_access'           => "$conf_dir/hmac_sha512_access.conf",
    'hmac_sha512_short_key_access' => "$conf_dir/hmac_sha512_short_key_access.conf",
    'hmac_sha512_short_key2_access' => "$conf_dir/hmac_sha512_short_key2_access.conf",
    'hmac_sha512_long_key_access'  => "$conf_dir/hmac_sha512_long_key_access.conf",
    'hmac_simple_keys_access'      => "$conf_dir/hmac_simple_keys_access.conf",
    'hmac_invalid_type_access'     => "$conf_dir/hmac_invalid_type_access.conf",
    'hmac_cygwin_access'           => "$conf_dir/hmac_no_b64_cygwin_access.conf",
    'exp_access'                   => "$conf_dir/expired_stanza_access.conf",
    'future_exp_access'            => "$conf_dir/future_expired_stanza_access.conf",
    'exp_epoch_access'             => "$conf_dir/expired_epoch_stanza_access.conf",
    'invalid_exp_access'           => "$conf_dir/invalid_expire_access.conf",
    'force_nat_access'             => "$conf_dir/force_nat_access.conf",
    'hmac_force_nat_access'        => "$conf_dir/hmac_force_nat_access.conf",
    'cmd_access'                   => "$conf_dir/cmd_access.conf",
    'local_nat'                    => "$conf_dir/local_nat_fwknopd.conf",
    'no_flush_init'                => "$conf_dir/no_flush_init_fwknopd.conf",
    'no_flush_exit'                => "$conf_dir/no_flush_exit_fwknopd.conf",
    'no_flush_init_or_exit'        => "$conf_dir/no_flush_init_or_exit_fwknopd.conf",
    'ipfw_active_expire'           => "$conf_dir/ipfw_active_expire_equal_fwknopd.conf",
    'android_access'               => "$conf_dir/android_access.conf",
    'android_legacy_iv_access'     => "$conf_dir/android_legacy_iv_access.conf",
    'dual_key_access'              => "$conf_dir/dual_key_usage_access.conf",
    'hmac_dual_key_access'         => "$conf_dir/hmac_dual_key_usage_access.conf",
    'gpg_access'                   => "$conf_dir/gpg_access.conf",
    'gpg_hmac_access'              => "$conf_dir/gpg_hmac_access.conf",
    'legacy_iv_access'             => "$conf_dir/legacy_iv_access.conf",
    'gpg_no_pw_access'             => "$conf_dir/gpg_no_pw_access.conf",
    'gpg_no_pw_hmac_access'        => "$conf_dir/gpg_no_pw_hmac_access.conf",
    'tcp_server'                   => "$conf_dir/tcp_server_fwknopd.conf",
    'tcp_pcap_filter'              => "$conf_dir/tcp_pcap_filter_fwknopd.conf",
    'icmp_pcap_filter'             => "$conf_dir/icmp_pcap_filter_fwknopd.conf",
    'open_ports_access'            => "$conf_dir/open_ports_access.conf",
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
    'rc_invalid_b64_key'           => "$conf_dir/fwknoprc_invalid_base64_key",
    'rc_hmac_b64_key'              => "$conf_dir/fwknoprc_default_hmac_base64_key",
    'rc_hmac_b64_key2'             => "$conf_dir/fwknoprc_hmac_key2",
    'rc_gpg_hmac_b64_key'          => "$conf_dir/fwknoprc_gpg_hmac_key",
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
    'rc_hmac_sha256_short_key'     => "$conf_dir/fwknoprc_hmac_sha256_short_key",
    'rc_hmac_sha256_long_key'      => "$conf_dir/fwknoprc_hmac_sha256_long_key",
    'rc_hmac_sha384_key'           => "$conf_dir/fwknoprc_hmac_sha384_key",
    'rc_hmac_sha384_short_key'     => "$conf_dir/fwknoprc_hmac_sha384_short_key",
    'rc_hmac_sha384_long_key'      => "$conf_dir/fwknoprc_hmac_sha384_long_key",
    'rc_hmac_sha512_key'           => "$conf_dir/fwknoprc_hmac_sha512_key",
    'rc_hmac_sha512_short_key'     => "$conf_dir/fwknoprc_hmac_sha512_short_key",
    'rc_hmac_sha512_long_key'      => "$conf_dir/fwknoprc_hmac_sha512_long_key",
    'base64_key_access'            => "$conf_dir/base64_key_access.conf",
    'disable_aging'                => "$conf_dir/disable_aging_fwknopd.conf",
    'disable_aging_nat'            => "$conf_dir/disable_aging_nat_fwknopd.conf",
    'fuzz_source'                  => "$conf_dir/fuzzing_source_access.conf",
    'fuzz_open_ports'              => "$conf_dir/fuzzing_open_ports_access.conf",
    'fuzz_restrict_ports'          => "$conf_dir/fuzzing_restrict_ports_access.conf",
);

our $default_digest_file = "$run_dir/digest.cache";
our $default_pid_file    = "$run_dir/fwknopd.pid";
our $tmp_rc_file         = "$run_dir/fwknoprc";
our $rewrite_rc_file     = "$run_dir/rewrite_fwknoprc";
our $save_rc_file        = "$run_dir/save_fwknoprc";
our $tmp_pkt_file        = "$run_dir/tmp_spa.pkt";
our $tmp_args_file       = "$run_dir/args.save";

our $fwknopCmd  = '../client/.libs/fwknop';
our $fwknopdCmd = '../server/.libs/fwknopd';
our $libfko_bin = "$lib_dir/libfko.so";  ### this is usually a link

our $gpg_server_key = '361BBAD4';
our $gpg_client_key = '6A3FAD56';

our $loopback_ip       = '127.0.0.1';
our $fake_ip           = '127.0.0.2';
our $fake_spoof_ip     = '1.2.3.4';
our $internal_nat_host = '192.168.1.2';
our $force_nat_host    = '192.168.1.123';
our $default_spa_port  = 62201;
our $non_std_spa_port  = 12345;

our $spoof_user = 'testuser';

my $valgrind_cov_dir = 'valgrind-coverage';

our $spoof_ip   = '1.2.3.4';
my $perl_mod_fko_dir = 'FKO';
my $python_fko_dir   = 'python_fko';
my $python_script    = 'fko-python.py';
my $python_path      = '';
our $cmd_exec_test_file = '/tmp/fwknoptest';
my $default_key = 'fwknoptest';

my $tests_dir = 'tests';

my @test_files = (
    "$tests_dir/build_security.pl",
    "$tests_dir/preliminaries.pl",
    "$tests_dir/basic_operations.pl",
    "$tests_dir/rijndael.pl",
    "$tests_dir/rijndael_cmd_exec.pl",
    "$tests_dir/rijndael_replay_attacks.pl",
    "$tests_dir/rijndael_fuzzing.pl",
    "$tests_dir/rijndael_backwards_compatibility.pl",
    "$tests_dir/rijndael_hmac.pl",
    "$tests_dir/perl_FKO_module.pl",
    "$tests_dir/python_fko.pl",
    "$tests_dir/gpg_no_pw.pl",
    "$tests_dir/gpg_no_pw_hmac.pl",
    "$tests_dir/gpg.pl",
    "$tests_dir/gpg_hmac.pl",
);
#================== end config ===================

our @build_security_client   = ();  ### imported from tests/build_security.pl
our @build_security_server   = ();
our @build_security_libfko   = ();
our @preliminaries           = ();  ### from tests/preliminaries.pl
our @basic_operations        = ();  ### from tests/basic_operations.pl
our @rijndael                = ();  ### from tests/rijndael.pl
our @rijndael_cmd_exec       = ();  ### from tests/rijndael_cmd_exec.pl
our @rijndael_replay_attacks = ();  ### from tests/rijndael_replay_attacks.pl
our @rijndael_hmac           = ();  ### from tests/rijndael_hmac.pl
our @rijndael_fuzzing        = ();  ### from tests/rijndael_fuzzing.pl
our @gpg_no_pw               = ();  ### from tests/gpg_now_pw.pl
our @gpg_no_pw_hmac          = ();  ### from tests/gpg_now_pw_hmac.pl
our @gpg                     = ();  ### from tests/gpg.pl
our @gpg_hmac                = ();  ### from tests/gpg_hmac.pl
our @perl_FKO_module         = ();  ### from tests/perl_FKO_module.pl
our @python_fko              = ();  ### from tests/python_fko.pl
our @rijndael_backwards_compatibility = ();  ### from tests/rijndael_backwards_compatibility.pl

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
our $uniq_keys = 100;
my $test_limit = 0;
my $list_mode = 0;
my $diff_dir1 = '';
my $diff_dir2 = '';
my $loopback_intf = '';
my $anonymize_results = 0;
my $curr_test_file = "$output_dir/init";
my $tarfile = 'test_fwknop.tar.gz';
our $key_gen_file = "$output_dir/key_gen";
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
my $disable_valgrind = 0;
our $valgrind_str = '';
my %prev_valgrind_cov = ();
my %prev_valgrind_file_titles = ();
my $fko_wrapper_dir = 'fko-wrapper';
my $python_spa_packet = '';
my $enable_client_ip_resolve_test = 0;
my $enable_all = 0;
my $saved_last_results = 0;
my $diff_mode = 0;
my $enc_dummy_key = 'A'x8;
my $fko_obj = ();
my $enable_recompilation_warnings_check = 0;
my $enable_profile_coverage_check = 0;
my $enable_make_distcheck = 0;
my $enable_perl_module_checks = 0;
my $enable_perl_module_fuzzing_spa_pkt_generation = 0;
my $enable_python_module_checks = 0;
my $enable_openssl_compatibility_tests = 0;
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
our $valgrind_path = '';
our $sudo_path = '';
our $gcov_path = '';
our $killall_path = '';
our $pgrep_path   = '';
our $openssl_path = '';
our $base64_path  = '';
our $pinentry_fail = 0;
our $platform = '';
our $help = 0;
our $YES = 1;
our $NO  = 0;
our $IGNORE = 2;
our $PRINT_LEN = 68;
our $USE_PREDEF_PKTS = 1;
our $USE_CLIENT = 2;
our $USE_PCAP_FILE = 3;
our $REQUIRED = 1;
our $OPTIONAL = 0;
our $NEW_RULE_REQUIRED = 1;
our $REQUIRE_NO_NEW_RULE = 2;
our $NEW_RULE_REMOVED = 1;
our $REQUIRE_NO_NEW_REMOVED = 2;
our $MATCH_ANY = 1;
our $MATCH_ALL = 2;
our $REQUIRE_SUCCESS = 0;
our $REQUIRE_FAILURE = 1;
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
    'enable-python-module-checks' => \$enable_python_module_checks,
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
    'disable-valgrind'  => \$disable_valgrind,
    'enable-all'        => \$enable_all,
    'valgrind-path=s'   => \$valgrind_path,
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
    $enable_python_module_checks = 1;
    $enable_openssl_compatibility_tests = 1;
}

unless (-d $output_dir) {
    mkdir $output_dir or die "[*] Could not mkdir $output_dir: $!";
}
$enable_valgrind = 0 if $disable_valgrind;

### create an anonymized tar file of test suite results that can be
### emailed around to assist in debugging fwknop communications
exit &anonymize_results() if $anonymize_results;

exit &diff_test_results() if $diff_mode;

&identify_loopback_intf();

### make sure everything looks as expected before continuing
&init();

$valgrind_str = "$valgrind_path --leak-check=full " .
    "--show-reachable=yes --track-origins=yes" if $enable_valgrind;

our $intf_str = "-i $loopback_intf --foreground --verbose --verbose";

our $default_client_args = "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
    "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --get-key " .
    "$local_key_file --no-save-args --verbose --verbose";

our $default_client_args_no_get_key = "LD_LIBRARY_PATH=$lib_dir " .
    "$valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip " .
    "--no-save-args --verbose --verbose";

our $client_rewrite_rc_args = "$default_client_args_no_get_key " .
    "--rc-file $rewrite_rc_file --test";

our $client_save_rc_args = "$default_client_args_no_get_key " .
    "--rc-file $save_rc_file --save-rc-stanza --test";

our $default_client_hmac_args = "$default_client_args_no_get_key " .
    "--rc-file $cf{'rc_hmac_b64_key'}";

our $client_ip_resolve_args = "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
    "$fwknopCmd -A tcp/22 -R -D $loopback_ip --get-key " .
    "$local_key_file --verbose --verbose";

our $client_ip_resolve_hmac_args = "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
    "$fwknopCmd -A tcp/22 -R -D $loopback_ip --rc-file " .
    "$cf{'rc_hmac_b64_key'} --verbose --verbose";

our $default_client_gpg_args = "$default_client_args " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key " .
    "--gpg-home-dir $gpg_client_home_dir";

our $default_client_gpg_args_no_homedir = "$default_client_args " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key ";

our $default_client_gpg_args_no_get_key = "$default_client_args_no_get_key " .
    "--gpg-recipient-key $gpg_server_key " .
    "--gpg-signer-key $gpg_client_key " .
    "--gpg-home-dir $gpg_client_home_dir";

our $default_server_conf_args = "-c $cf{'def'} -a $cf{'def_access'} " .
    "-d $default_digest_file -p $default_pid_file";

our $default_server_hmac_conf_args = "-c $cf{'def'} -a $cf{'hmac_access'} " .
    "-d $default_digest_file -p $default_pid_file";

our $default_server_gpg_args = "LD_LIBRARY_PATH=$lib_dir " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_access'} $intf_str " .
    "-d $default_digest_file -p $default_pid_file";

our $default_server_gpg_args_no_pw = "LD_LIBRARY_PATH=$lib_dir " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_no_pw_access'} $intf_str " .
    "-d $default_digest_file -p $default_pid_file";

our $default_server_gpg_args_hmac = "LD_LIBRARY_PATH=$lib_dir " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_hmac_access'} $intf_str " .
    "-d $default_digest_file -p $default_pid_file";

our $default_server_gpg_args_no_pw_hmac = "LD_LIBRARY_PATH=$lib_dir " .
    "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
    "-a $cf{'gpg_no_pw_hmac_access'} $intf_str " .
    "-d $default_digest_file -p $default_pid_file";

### point the compiled binaries at the local libary path
### instead of any installed libfko instance
$ENV{'LD_LIBRARY_PATH'} = $lib_dir;

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
        'fatal'    => $NO
    },
    {
        'category' => 'make distcheck',
        'detail'   => 'ensure proper distribution creation',
        'function' => \&make_distcheck,
        'fatal'    => $NO
    },
    {
        'category' => 'Makefile.am',
        'detail'   => 'test suite conf/ files included',
        'function' => \&test_suite_conf_files,
        'fatal'    => $NO
    },

    @build_security_client,
    @build_security_server,
    @build_security_libfko,
    @preliminaries,
    @basic_operations,
    @rijndael,
    @rijndael_cmd_exec,
    @rijndael_replay_attacks,
    @rijndael_backwards_compatibility,
    @rijndael_fuzzing,
    @rijndael_hmac,
    @perl_FKO_module,
    @python_fko,
    @gpg_no_pw,
    @gpg_no_pw_hmac,
    @gpg,
    @gpg_hmac,
);

&validate_test_hashes();

### make sure no fwknopd instance is currently running
die "[*] Please stop the running fwknopd instance."
    if &is_fwknopd_running();

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

if ($enable_profile_coverage_check) {
    push @tests,
        {
            'category' => 'profile coverage',
            'detail'   => 'gcov profile coverage',
            'function' => \&profile_coverage,
            'fatal'    => $NO
        };
}

if ($enable_valgrind) {
    push @tests,
        {
            'category' => 'valgrind',
            'subcategory' => 'fko-wrapper',
            'detail'   => 'multiple libfko calls',
            'function' => \&compile_execute_fko_wrapper,
            'fatal'    => $NO
        };

    push @tests,
        {
            'category' => 'valgrind output',
            'subcategory' => 'flagged functions',
            'detail'   => '',
            'function' => \&parse_valgrind_flagged_functions,
            'fatal'    => $NO
        };
}

### print a summary of how many test buckets will be run
my $test_buckets = 0;
for my $test_hr (@tests) {
    next unless &process_include_exclude(&get_msg($test_hr));
    $test_buckets++;
    if ($test_limit > 0) {
        last if $executed >= $test_limit;
    }
}
&logr("[+] Total test buckets to execute: $test_buckets\n\n");

### main loop through all of the tests
for my $test_hr (@tests) {
    &run_test($test_hr);
    if ($test_limit > 0) {
        last if $executed >= $test_limit;
    }
}

&logr("\n");

&remove_permissions_warnings() unless $include_permissions_warnings;
&restore_gpg_dirs();

my $total_elapsed_seconds = time() - $start_time;
my $total_elapsed_minutes = sprintf "%.2f", ($total_elapsed_seconds / 60);

if ($total_elapsed_seconds > 60) {
    &logr("    Run time: $total_elapsed_minutes minutes\n");
} else {
    &logr("    Run time: $total_elapsed_seconds seconds\n");
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

    ### prepare for test run
    &rm_tmp_files();

    my $msg = &get_msg($test_hr);

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

    if ($enable_valgrind and &is_valgrind_running()) {
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

    ### clean up tmp files now that the test is complete
    &rm_tmp_files();

    return;
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

    open F, "< $dir/$logfile" or die "[*] Could not open $dir/$logfile: $!";
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
            $MATCH_ANY, $APPEND_RESULTS, "test/$curr_test_file")) {
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
        if (m|test/$conf_dir/(\S+)|) {
            $makefile_conf_files{$1} = '';
        } elsif (m|test/$tests_dir/(\S+)|) {
            $makefile_test_scripts{$1} = '';
        }
    }
    close F;

    for my $f (glob("$conf_dir/*")) {
        next if -d $f;
        next unless $f =~ /\.conf/ or $f =~ /fwknop/;
        if ($f =~ m|$conf_dir/(\S+)|) {
            if (defined $makefile_conf_files{$1}) {
                &write_test_file("[+] test suite conf file $1 is in $make_file.\n",
                    $curr_test_file);
            } else {
                &write_test_file("[-] test suite conf file $1 not in $make_file.\n",
                    $curr_test_file);
                $rv = 0;
            }
        }
    }

    for my $f (glob("$tests_dir/*.pl")) {
        if ($f =~ m|$tests_dir/(\S+)|) {
            if (defined $makefile_test_scripts{$1}) {
                &write_test_file("[+] test suite script file $1 is in $make_file.\n",
                    $curr_test_file);
            } else {
                &write_test_file("[-] test suite script file $1 not in $make_file.\n",
                    $curr_test_file);
                $rv = 0;
            }
        }
    }

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

sub client_rc_file() {
    my $test_hr = shift;

    my $rv = 1;

    if ($test_hr->{'write_rc_file'}) {
        open RC, "> $rewrite_rc_file"
            or die "[*] Could not open $rewrite_rc_file: $!";
        for my $hr (@{$test_hr->{'write_rc_file'}}) {
            print RC "[$hr->{'name'}]\n";
            for my $var (keys %{$hr->{'vars'}}) {
                print RC "$var      $hr->{'vars'}->{$var}\n";
            }
        }
        close RC;
    } elsif ($test_hr->{'save_rc_stanza'}) {
        open RC, "> $save_rc_file"
            or die "[*] Could not open $save_rc_file: $!";
        for my $hr (@{$test_hr->{'save_rc_stanza'}}) {
            print RC "[$hr->{'name'}]\n";
            for my $var (keys %{$hr->{'vars'}}) {
                print RC "$var      $hr->{'vars'}->{$var}\n";
            }
        }
        close RC;
    } else {
        &write_test_file(
            "[-] test hash does not include 'write_rc_file' or 'save_rc_stanza'\n",
            $curr_test_file);
        return 0;
    }

    $rv = 0 unless &run_cmd($test_hr->{'cmdline'},
            $cmd_out_tmp, $curr_test_file);
    $rv = 0 unless &file_find_regex([qr/final\spacked/i],
        $MATCH_ALL, $NO_APPEND_RESULTS, $curr_test_file);

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
        if (/Final\sPacked/) {
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

sub client_send_spa_packet() {
    my ($test_hr, $server_receive_check) = @_;

    $server_receive_check = $NO_SERVER_RECEIVE_CHECK
        unless defined $server_receive_check;

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
        while (not &file_find_regex(
                [qr/stanza\s.*\sSPA Packet from IP/],
                $MATCH_ALL, $NO_APPEND_RESULTS, $server_cmd_tmp)) {

            &write_test_file("[.] client_send_spa_packet() " .
                "executing client and looking for fwknopd receiving " .
                "packet, try: $tries\n",
                $curr_test_file);

            $rv = 0 unless &run_cmd($test_hr->{'cmdline'},
                    $cmd_out_tmp, $curr_test_file);
            $rv = 0 unless &file_find_regex([qr/final\spacked/i],
                $MATCH_ALL, $NO_APPEND_RESULTS, $curr_test_file);

            last if $server_receive_check == $NO_SERVER_RECEIVE_CHECK;
            $tries++;
            last if $tries == 10;   ### should be plenty of time
            sleep 1;
        }
    } else {
        $rv = 0 unless &run_cmd($test_hr->{'cmdline'},
                $cmd_out_tmp, $curr_test_file);
        $rv = 0 unless &file_find_regex([qr/final\spacked/i],
            $MATCH_ALL, $NO_APPEND_RESULTS, $curr_test_file);
    }

    &write_test_file("[+] fwknopd received SPA packet.\n", $curr_test_file)
        unless $server_receive_check == $NO_SERVER_RECEIVE_CHECK;

    if ($enable_openssl_compatibility_tests) {

        ### extract the SPA packet from the cmd tmp file
        my $encoded_msg = '';
        my $digest = '';
        my $enc_mode = 0;
        my $is_hmac_type = 1;
        my $hmac_digest = '';
        my $hmac_mode = 'sha256';
        open F, "< $cmd_out_tmp" or die $!;
        while (<F>) {
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
        close F;

        $encoded_msg .= ":$digest";

        my $ssl_test_flag = $REQUIRE_SUCCESS;
        $ssl_test_flag = $REQUIRE_FAILURE if $enc_mode != 2;  ### CBC mode
        $ssl_test_flag = $REQUIRE_FAILURE if $is_hmac_type;

        my $encrypted_msg = &get_spa_packet_from_file($cmd_out_tmp);

        my $key = '';
        my $hmac_key = '';
        my $b64_decode_key = 0;
        if ($test_hr->{'key_file'}) {
            open F, "< $test_hr->{'key_file'}" or die $!;
            while (<F>) {
                if (/^KEY_BASE64\:?\s+(\S+)/) {
                    $key = $1;
                    $b64_decode_key = 1;
                } elsif (/^KEY\:?\s+(\S+)/) {
                    $key = $1;
                } elsif (/^HMAC_KEY_BASE64\:?\s+(\S+)/) {
                    $hmac_key = $1;
                    $b64_decode_key = 1;
                } elsif (/^HMAC_KEY\:?\s+(\S+)/) {
                    $hmac_key = $1;
                }
            }
            close F;
        }
        $key = $default_key unless $key;

        unless (&openssl_enc_verification($encrypted_msg,
                $encoded_msg, '', $key, $b64_decode_key,
                $ssl_test_flag)) {
            $rv = 0;
        }

        if ($is_hmac_type and $hmac_key) {
            my $enc_mode = $ENC_RIJNDAEL;
            $enc_mode = $ENC_GPG if $test_hr->{'msg'} =~ /GPG/;
            unless (&openssl_hmac_verification($encrypted_msg,
                    $encoded_msg, '', $hmac_key, $b64_decode_key,
                    $hmac_digest, $hmac_mode, $enc_mode)) {
                $rv = 0;
            }
        }
    }

    &write_test_file("[.] client_send_spa_packet() rv: $rv\n",
        $curr_test_file);

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
            $MATCH_ALL, $APPEND_RESULTS, $server_test_file);
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

    return $rv;
}

sub iptables_no_flush_init_exit() {
    my $test_hr = shift;

    my $rv = 1;

    &run_cmd("LD_LIBRARY_PATH=$lib_dir $valgrind_str $fwknopdCmd " .
        "--fw-flush --verbose --verbose", $cmd_out_tmp, $curr_test_file);

    if ($test_hr->{'insert_rule_before_exec'}) {
        ### first create the fwknop chains and add a rule, then check for
        ### this rule to either not be deleted at init or exit
        &run_cmd("iptables -N FWKNOP_INPUT", $cmd_out_tmp, $curr_test_file);
        &run_cmd("iptables -A FWKNOP_INPUT -p tcp -s $fake_ip --dport 1234 -j ACCEPT",
            $cmd_out_tmp, $curr_test_file);
    }

    $rv = &spa_cycle($test_hr);

    if ($test_hr->{'search_for_rule_after_exit'}) {
        &run_cmd("LD_LIBRARY_PATH=$lib_dir $valgrind_str $fwknopdCmd " .
            "--fw-list --verbose --verbose", $cmd_out_tmp, $curr_test_file);
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
            push @tests_to_exclude, qr/GPG/;
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

    chdir $curr_pwd or die $!;

    return $rv;
}

sub python_fko_basic_exec() {
    my $test_hr = shift;

    my $rv = 1;

    my $site_dir = "$python_fko_dir/lib";

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

    $rv = &run_cmd("LD_LIBRARY_PATH=$lib_dir " .
        "PYTHONPATH=$site_dir $python_path ./$python_script",
        $cmd_out_tmp, $curr_test_file);

    if ($rv) {

        $python_spa_packet = '';

        ### get the SPA packet data
        open F, "< $curr_test_file" or die $!;
        while (<F>) {
            if (/SPA\spacket\sdata\:\s(\S+)/) {
                $python_spa_packet = $1;
                last;
            }
        }
        close F;

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

    &run_cmd("perl Makefile.PL PREFIX=../../test/$perl_mod_fko_dir " .
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

            $status = $fko_obj->spa_data_final($key, length($key), '', 0);

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

                $status = $fko_obj->spa_data_final($enc_dummy_key,
                        length($enc_dummy_key), $hmac_key, length($hmac_key));

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

sub fuzzing_encryption_keys() {
    my @keys = (
        'A'x33,
        'A'x34,
        'A'x128,
        'A'x1000,
        'A'x2000,
        'asdfasdfsafsdafasdfasdfsafsdaffdjskalfjdsklafjsldkafjdsajdkajsklfdafsklfjjdkljdsafjdjd' .
        'sklfjsfdsafjdslfdkjdljsajdskjdskafjdldsljdkafdsljdslafdslaldldajdskajlddslajsl',
    );
    return \@keys;
}

sub fuzzing_hmac_keys() {
    my @keys = (
        'A'x129,
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
    $fko_obj->spa_data_final($key_with_null, length($key_with_null), '', 0);

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
        if ($fko_obj->decrypt_spa_data($truncated_key,
                length($truncated_key)) == FKO->FKO_SUCCESS) {
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
            $fko_obj->spa_data_final($key, length($key), '', 0);

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

                            $fko_obj->spa_data_final($key, length($key), $hmac_key, length($hmac_key));

                            my $encrypted_msg = $fko_obj->spa_data();

                            $fko_obj->destroy();

                            ### now get new object for decryption
                            $fko_obj = FKO->new($encrypted_msg, $key, length($key),
                                    $enc_mode, $hmac_key, length($hmac_key), $hmac_type);
                            unless ($fko_obj) {
                                &write_test_file("[-] error FKO->new(): " . FKO::error_str() . "\n",
                                    $curr_test_file);
                                return 0;
                            }
                            $fko_obj->spa_data($encrypted_msg);
                            $fko_obj->hmac_type($hmac_type);
                            $fko_obj->encryption_mode($enc_mode);
                            my $hmac_digest = $fko_obj->spa_hmac();

                            $fko_obj->decrypt_spa_data($key, length($key), $hmac_key, length($hmac_key));

                            if ($msg ne $fko_obj->spa_message()) {
                                &write_test_file("[-] $msg encrypt/decrypt mismatch\n",
                                    $curr_test_file);
                                $rv = 0;
                            }

                            $fko_obj->destroy();

                            if ($enable_openssl_compatibility_tests) {
                                unless (&openssl_hmac_verification($encrypted_msg,
                                        '', $msg, $hmac_key, 0, $hmac_digest,
                                        &hmac_type_to_str($hmac_type), $ENC_RIJNDAEL)) {
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
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    my @packets = ();

    for (my $i=0; $i < 3; $i++) {
        unless (&client_send_spa_packet($test_hr, $NO_SERVER_RECEIVE_CHECK)) {
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

    unless (&client_send_spa_packet($test_hr, $NO_SERVER_RECEIVE_CHECK)) {
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

    unless (&client_send_spa_packet($test_hr, $SERVER_RECEIVE_CHECK)) {
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

sub altered_base64_spa_data() {
    my $test_hr = shift;

    my $rv = 1;
    my $server_was_stopped = 0;
    my $fw_rule_created = 0;
    my $fw_rule_removed = 0;

    unless (&client_send_spa_packet($test_hr, $NO_SERVER_RECEIVE_CHECK)) {
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

    unless (&client_send_spa_packet($test_hr, $NO_SERVER_RECEIVE_CHECK)) {
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

    unless (&client_send_spa_packet($test_hr, $NO_SERVER_RECEIVE_CHECK)) {
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

    unless (&client_send_spa_packet($test_hr, $NO_SERVER_RECEIVE_CHECK)) {
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

    unless (&client_send_spa_packet($test_hr, $NO_SERVER_RECEIVE_CHECK)) {
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

sub client_server_interaction() {
    my ($test_hr, $pkts_hr, $spa_client_flag) = @_;

    my $rv = 1;
    my $server_was_stopped = 1;
    my $fw_rule_created = 1;
    my $fw_rule_removed = 0;

    ### start fwknopd to monitor for the SPA packet over the loopback interface
    my $fwknopd_parent_pid = &start_fwknopd($test_hr);

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
        &run_cmd("iptables -A FWKNOP_INPUT -p tcp -s $fake_ip --dport 1234 -j ACCEPT",
            $cmd_out_tmp, $curr_test_file);
    }

    ### send the SPA packet(s) to the server either manually using IO::Socket or
    ### with the fwknopd client
    if ($spa_client_flag == $USE_CLIENT) {
        unless (&client_send_spa_packet($test_hr, $SERVER_RECEIVE_CHECK)) {
            if ($enable_openssl_compatibility_tests) {
                &write_test_file(
                    "[-] fwknop client execution and/or OpenSSL error.\n",
                    $curr_test_file);
            } else {
                &write_test_file("[-] fwknop client execution error.\n",
                    $curr_test_file);
            }
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
        &write_test_file("[.] new fw rule does not exist.\n",
            $curr_test_file);
        $ctr++;
        last if $ctr == 3;
        sleep 1;
    }
    if ($ctr == 3) {
        $fw_rule_created = 0;
        $fw_rule_removed = 0;
    }

    if ($fw_rule_created) {
        sleep 3;  ### allow time for rule time out.
        if (&is_fw_rule_active($test_hr)) {
            &write_test_file("[-] new fw rule not timed out, setting rv=0.\n",
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
                $MATCH_ALL, $APPEND_RESULTS, $server_test_file)) {
            $server_was_stopped = 0;
        }
    } else {
        &write_test_file("[-] server is not running.\n",
            $curr_test_file);
        $server_was_stopped = 0;
    }

    unless ($server_was_stopped) {
        &write_test_file("[-] server_was_stopped=0, so setting rv=0.\n",
            $curr_test_file);
        $rv = 0;
    }

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
                "[-] fw_rule_removed=0 but new rule removal requied, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    } elsif ($test_hr->{'fw_rule_removed'} eq $REQUIRE_NO_NEW_REMOVED) {
        if ($fw_rule_removed) {
            &write_test_file(
                "[-] fw_rule_removed=1 but new rule removal NOT requied, setting rv=0\n",
                $curr_test_file);
            $rv = 0;
        }
    }

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

    &write_test_file("[.] client_server_interaction() rv: $rv, " .
        "server_was_stopped: $server_was_stopped, " .
        "fw_rule_created: $fw_rule_created, fw_rule_removed: $fw_rule_removed\n",
        $curr_test_file);

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

    my $received_first_packet = 0;

    if (-e $server_cmd_tmp) {
        for my $pkt_hr (@$pkts_ar) {
            my $tries = 0;
            while (not &file_find_regex(
                    [qr/stanza\s.*\sSPA Packet from IP/],
                    $MATCH_ALL, $NO_APPEND_RESULTS, $server_cmd_tmp)) {

                &write_test_file("[.] send_packets() looking for " .
                    "fwknopd to receive packet, try: $tries\n",
                    $curr_test_file);

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
                last if $received_first_packet;
                $tries++;
                last if $tries == 10;   ### should be plenty of time
                sleep 1;
            }
            $received_first_packet = 1;
            sleep $pkt_hr->{'delay'} if defined $pkt_hr->{'delay'};
        }
    } else {
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
        $b64_decode_key, $hmac_digest, $hmac_mode, $enc_mode) = @_;

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

    open F, "> $data_tmp" or die $!;
    print F $enc_msg_without_hmac;
    close F;

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
    open F, "< $openssl_cmd_tmp" or die $!;
    while (<F>) {
        $openssl_hmac_line .= $_;
        chomp $openssl_hmac_line;
    }
    close F;

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
        $openssl_hmac_failure_ctr++;
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

    open F, "> $data_tmp" or die $!;
    print F $encrypted_msg, "\n";
    close F;

    open F, "> $key_tmp" or die $!;
    print F $key;
    close F;

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
            open F, "< $openssl_cmd_tmp" or die $!;
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
            open F, "< $openssl_cmd_tmp" or die $!;
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
                $MATCH_ALL, $APPEND_RESULTS, $cmd_out_tmp);
        }
    }

    ### all three of fwknop/fwknopd/libfko must link against gpgme in order
    ### to enable gpg tests
    unless ($have_gpgme == 3) {
        push @tests_to_exclude, qr/GPG/;
    }

    return 1;
}

sub is_valgrind_running() {
    return &run_cmd("ps axuww | grep LD_LIBRARY_PATH | " .
        "grep valgrind |grep -v perl | grep -v grep",
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
                $MATCH_ALL, $NO_APPEND_RESULTS, $server_cmd_tmp)) {
            &write_test_file("[.] start_fwknopd() looking " .
                "for 'main event loop' string, try: $tries\n",
                $curr_test_file);
            $tries++;
            last if $tries == 10;  ### shouldn't reasonably get here
            sleep 1;
        }
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

    unlink $cmd_out if -e $cmd_out;

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

sub validate_test_hashes() {

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
        'server_exec_err' => $OPTIONAL,
        'fw_rule_created' => $OPTIONAL,
        'fw_rule_removed' => $OPTIONAL,
        'server_conf'     => $OPTIONAL,
        'pkt'             => $OPTIONAL,
        'fuzzing_pkt'     => $OPTIONAL,
        'pkt_prefix'      => $OPTIONAL,
        'no_ip_check'     => $OPTIONAL,
        'get_key'         => $OPTIONAL,
        'get_hmac_key'    => $OPTIONAL,
        'set_legacy_iv'   => $OPTIONAL,
        'write_rc_file'   => $OPTIONAL,
        'save_rc_stanza'  => $OPTIONAL,
        'positive_output_matches' => $OPTIONAL,
        'negative_output_matches' => $OPTIONAL,
        'insert_rule_before_exec'    => $OPTIONAL,
        'insert_rule_while_running'  => $OPTIONAL,
        'search_for_rule_after_exit' => $OPTIONAL,
        'server_positive_output_matches' => $OPTIONAL,
        'server_negative_output_matches' => $OPTIONAL,
        'replay_positive_output_matches' => $OPTIONAL,
        'replay_negative_output_matches' => $OPTIONAL,
    );

    ### validate test hashes
    for my $test_hr (@tests) {
        my $msg = &get_msg($test_hr);
        for my $key (keys %test_keys) {
            if ($test_keys{$key} == $REQUIRED) {
                die "[*] Missing '$key' element in test hash: '$msg'"
                    unless defined $test_hr->{$key};
            } else {
                $test_hr->{$key} = '' unless defined $test_hr->{$key};
            }
        }
        for my $key (keys %$test_hr) {
            die "[*] Unrecognized key '$key' in test hash: '$msg'"
                unless defined $test_keys{$key};
        }
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
            unless ($test_hr->{'cmdline'} =~ /\s$test_hr->{'key_file'}\b/) {
                die "[*] 'key_file' value: '$test_hr->{'key_file'}' not matched in " .
                    "client command line '$test_hr->{'cmdline'}' for: $msg";
            }
        }
        if ($test_hr->{'server_conf'}) {
            unless ($test_hr->{'fwknopd_cmdline'} =~ /\s$test_hr->{'server_conf'}\b/) {
                die "[*] 'server_conf' value: '$test_hr->{'server_conf'}' not matched in " .
                    "server command line '$test_hr->{'fwknopd_cmdline'}' for: $msg";
            }
        }
    }

    return;
}

sub init() {

    $|++; ### turn off buffering

    $< == 0 && $> == 0 or
        die "[*] $0: You must be root (or equivalent ",
            "UID 0 account) to effectively test fwknop";

    die "[*] $conf_dir directory does not exist." unless -d $conf_dir;

    unless ($enable_recompilation_warnings_check) {
        die "[*] $lib_dir directory does not exist." unless -d $lib_dir;
    }

    unlink $cmd_exec_test_file if -e $cmd_exec_test_file;
    for my $name (keys %cf) {
        die "[*] $cf{$name} does not exist" unless -e $cf{$name};
        chmod 0600, $cf{$name} or die "[*] Could not chmod 0600 $cf{$name}";
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

    if ($enable_openssl_compatibility_tests) {
        $openssl_path = &find_command('openssl');
        if ($openssl_path) {
            require MIME::Base64;
            MIME::Base64->import(qw(encode_base64 decode_base64));
            $base64_path = &find_command('base64');

            ### check for hmac openssl support
            &openssl_hmac_style_check();

        } else {
            print "[-] openssl checks requested, but openssl ",
                " command not found, disabling.\n";
            $enable_openssl_compatibility_tests = 0;
        }
    }

    if ($enable_valgrind) {
        $valgrind_path = &find_command('valgrind');
        unless ($valgrind_path) {
            print "[-] --enable-valgrind mode requested ",
                "but valgrind not found, disabling.\n";
            $enable_valgrind = 0;
        }
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

    if ($enable_python_module_checks) {
        die "[*] The python test script: $python_script doesn't exist ",
            "or is not executable."
            unless -e $python_script and -x $python_script;
        $python_path = &find_command('python');
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

sub preserve_previous_test_run_results() {
    unless ($list_mode) {
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
    }
    return;
}

sub restore_gpg_dirs() {

    my $curr_pwd = cwd() or die $!;

    chdir $conf_dir or die $!;

    if (-e $gpg_dir_orig_tar) {
        system "tar xfz $gpg_dir_orig_tar > /dev/null";
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
        $MATCH_ALL, $APPEND_RESULTS, "../$curr_test_file");

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
            if (defined $prev_valgrind_file_titles{$type}
                    and $prev_valgrind_file_titles{$type}{$test_title}) {
                open F, ">> $curr_test_file" or die $!;
                print F "[+] $filename ($test_title) No new or greater number of valgrind flagged function calls\n";
                close F;
            } else {
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

    &run_cmd("LD_LIBRARY_PATH=$lib_dir $fwknopdCmd $default_server_conf_args " .
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
        return;
    }

    &run_cmd("LD_LIBRARY_PATH=$lib_dir $fwknopdCmd " .
        "$default_server_conf_args -K", $cmd_out_tmp, $curr_test_file);

    ### look for SIGTERM receipt
    my $tries = 0;
    if (&file_find_regex(
            [qr/Got\sSIGTERM/],
            $MATCH_ALL, $NO_APPEND_RESULTS, $server_cmd_tmp)) {
        &write_test_file("[+] stop_fwknopd() fwknopd received SIGTERM\n",
            $curr_test_file);
    } else {
        while (not &file_find_regex(
                [qr/Got\sSIGTERM/],
                $MATCH_ALL, $NO_APPEND_RESULTS, $server_cmd_tmp)) {

            &run_cmd("LD_LIBRARY_PATH=$lib_dir $fwknopdCmd " .
                "$default_server_conf_args -K", $cmd_out_tmp, $curr_test_file);

            &write_test_file("[.] stop_fwknopd() looking for fwknopd receiving " .
                "SIGTERM, try: $tries\n",
                $curr_test_file);
            last unless &is_pid_running($default_pid_file);
            $tries++;
            last if $tries == 10;   ### should be plenty of time
            sleep 1;
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
        sleep 1 if $tries == 0;
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

    open F, "< $file" or (print Dumper $re_ar and die "[*] Could not open $file: $!");
    while (<F>) {
        push @file_lines, $_;
    }
    close F;

    for my $re (@$re_ar) {
        my $matched = 0;
        for my $line (@file_lines) {
            next if $line =~ /file_find_regex\(\)/;
            if ($line =~ $re) {
                push @write_lines, "[.] file_find_regex() " .
                    "Matched '$re' with line: $line";
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
    --disable-valgrind             - Disable valgrind mode (useful sometimes
                                     when --enable-all is used to have
                                     everything except for valgrind enabled).
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
    --valgrind-path=<path>         - Specify path to valgrind
    --valgrind-prev-cov-dir=<path> - Path to previous valgrind-coverage
                                     directory (defaults to:
                                     "output.last/valgrind-coverage").
    -h   --help                    - Display usage on STDOUT and exit.

_HELP_
    exit 0;
}
