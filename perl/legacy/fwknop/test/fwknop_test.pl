#!/usr/bin/perl -w
#
#############################################################################
#
# File: fwknop_test.pl
#
# Purpose: This program provides a test suite for the fwknop Single Packet
#          Authorization client and server.
#
# Author: Michael Rash (mbr@cipherdyne.org)
#
# Version: 1.9.12
#
# Copyright (C) 2007-2009 Michael Rash (mbr@cipherdyne.org)
#
# License (GNU Public License):
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
#    USA
#
#############################################################################
#
# $Id: fwknop_test.pl 1532 2009-09-08 02:42:18Z mbr $
#

use IO::Socket;
use Getopt::Long;
use strict;

#=================== config defaults ==============
my $lib_dir = '/usr/lib/fwknop';

my $fwknopCmd  = '../fwknop';
my $fwknopdCmd = '../fwknopd';
my $knoptmCmd  = '../knoptm';
my $fwknop_servCmd = '../fwknop_serv';
my $tcpdumpCmd = '/usr/sbin/tcpdump';
my $gpgCmd     = '/usr/bin/gpg';
my $gpg2Cmd    = '/usr/bin/gpg2';
my $fileCmd    = '/usr/bin/file';

my $conf_dir   = 'conf';
my $output_dir = 'output';
my $logfile    = 'test.log';
my $tarfile    = 'fwknop_test.tar.gz';

my $dump_packets_file  = "$output_dir/dump_packets";  # for digest calculation

my $default_access_conf   = "$conf_dir/default_access.conf";
my $tcp_serv_fwknop_conf  = "$conf_dir/tcp_serv_fwknop.conf";
my $http_fwknop_conf      = "$conf_dir/http_fwknop.conf";
my $icmp_fwknop_conf      = "$conf_dir/icmp_fwknop.conf";
my $default_fwknop_conf   = "$conf_dir/default_fwknop.conf";
my $ipt_sleep_fwknop_conf = "$conf_dir/ipt_sleep_fwknop.conf";
my $system_fwknop_conf    = "$conf_dir/system_fwknop.conf";
my $popen_fwknop_conf     = "$conf_dir/popen_fwknop.conf";
my $gpg2_fwknop_conf      = "$conf_dir/gpg2_fwknop.conf";
my $gpg2_http_fwknop_conf = "$conf_dir/gpg2_http_fwknop.conf";
my $fwknop_62203_conf     = "$conf_dir/filter_62203_fwknop.conf";
my $sha256_fwknop_conf    = "$conf_dir/sha256_fwknop.conf";
my $sha1_fwknop_conf      = "$conf_dir/sha1_fwknop.conf";
my $md5_fwknop_conf       = "$conf_dir/md5_fwknop.conf";
my $forward_access_conf   = "$conf_dir/forward_access.conf";
my $forward_fwknop_conf   = "$conf_dir/forward_chain_fwknop.conf";
my $output_access_conf    = "$conf_dir/output_access.conf";
my $output_fwknop_conf    = "$conf_dir/output_chain_fwknop.conf";
my $blacklist_fwknop_conf = "$conf_dir/blacklist_fwknop.conf";
my $spa_aging_fwknop_conf = "$conf_dir/spa_aging_fwknop.conf";
my $pcap_file_fwknop_conf = "$conf_dir/pcap_file_fwknop.conf";
my $rand_port_fwknop_conf = "$conf_dir/rand_port_fwknop.conf";
my $gpg_access_conf       = "$conf_dir/gpg_access.conf";
my $gpg2_access_conf      = "$conf_dir/gpg2_access.conf";
my $no_promisc_fwknop_conf   = "$conf_dir/no_promisc_fwknop.conf";
my $ext_command_access_conf  = "$conf_dir/external_cmd_access.conf";
my $excluded_net_access_conf = "$conf_dir/excluded_net_access.conf";
my $multi_source_access_conf = "$conf_dir/multi_source_access.conf";
my $multi_port_access_conf   = "$conf_dir/multi_port_access.conf";
my $no_local_nat_fwknop_conf = "$conf_dir/no_local_nat_fwknop.conf";
my $gpg_access_no_prefix_conf = "$conf_dir/gpg_access_no_prefix.conf";
my $any_interface_fwknop_conf = "$conf_dir/any_interface_fwknop.conf";
my $override_sleep_fwknop_conf = "$conf_dir/override_sleep_fwknop.conf";
my $client_timeout_access_conf = "$conf_dir/client_timeout_access.conf";
my $socket_com_tcp_fwknop_conf = "$conf_dir/socket_com_tcp_serv_fwknop.conf";
my $socket_com_udp_fwknop_conf = "$conf_dir/socket_com_udp_serv_fwknop.conf";
my $restricted_forward_access_conf = "$conf_dir/forward_internal_ip_access.conf";
my $blacklist_dashA_IP_fwknop_conf = "$conf_dir/blacklist_dashA_IP_fwknop.conf";
my $no_loopback_ip_match_access_conf = "$conf_dir/no_loopback_ip_match_access.conf";
my $pk_fwknop_conf = "$conf_dir/pk_fwknop.conf";
my $pk_encrypted_sequence_conf = "$conf_dir/pk_encrypted_sequence_access.conf";
my $pk_multi_port_shared_sequence_conf  = "$conf_dir/pk_multi_port_shared_sequence_access.conf";
my $pk_single_port_shared_sequence_conf = "$conf_dir/pk_single_port_shared_sequence_access.conf";
my $pk_multi_protocol_shared_sequence_conf = "$conf_dir/pk_multi_protocol_shared_sequence_access.conf";
my $ext_command_no_open_ports_access_conf  = "$conf_dir/external_cmd_no_open_ports_access.conf";
my $ext_command_no_dash_A_access_conf      = "$conf_dir/external_cmd_no_dash_A_access.conf";

my $local_key_file = 'local_spa.key';

my $loopback_intf = 'lo'; ### default on linux

my $spa_port = 0;
my $localhost = '127.0.0.1';
my $allow_src = '127.0.0.2';

my $gpg_server_key = '361BBAD4';
my $gpg_client_key = '6A3FAD56';

my $sniff_alarm = 20;

my $test_cmd_file = '/tmp/fwknop_test.txt';
my $test_cmd = "echo fwknoptest > $test_cmd_file";

my $ip_forward_file = '/proc/sys/net/ipv4/ip_forward';
#==================== end config ==================

my $QUIET     = 1;
my $NO_QUIET  = 0;
my $APPEND    = 1;
my $NO_APPEND = 0;

my $fw_access_timeout = 3;  ### default
my $require_user = '';
my $gpg_mode_str = '';
my $require_source_addr = 0;
my $permit_client_ports = 0;
my $fwknop_conf_file    = '/etc/fwknop/fwknop.conf';
my $cache_encrypted_spa_packet = '';
my $spa_http_request = '';
my $test_system_installed_fwknop = 0;
my $spa_packet_digest  = '';
my $successful_tests   = 0;
my $failed_tests       = 0;
my $no_client_fko_module = 0;
my $no_server_fko_module = 0;
my $fwknopd_using_fko_module = 0;
my $fwknop_using_fko_module  = 0;
my $ipt_chainmgr_version = 0;
my $skip_language_check  = 0;
my $client_language = 'perl';
my $server_language = 'perl';
my $cache_key = '';
my $test_num  = 0;
my $test_include = '';
my @tests_to_include = ();
my $test_exclude = '';
my @tests_to_exclude = ();
my $unauth_port = 0;
my $sniff_file = '';
my $open_ports = '';
my $PRINT_LEN = 68;
my $NUM_RAND  = 100;
my $cmd_regex = '';
my $prepare_results = 0;
my $help   = 0;
my %config = ();
my %cmds   = ();
my $ip_re  = qr|(?:[0-2]?\d{1,2}\.){3}[0-2]?\d{1,2}|;
my $current_test_file  = "$output_dir/$test_num.test";
my $previous_test_file = '';
my $pk_shared_sequence = '';
my $pk_encrypted_sequence = '';
my $http_test_file = '';
my $SHARED_SEQ = 1;
my $ENCRYPTED_SEQ = 2;
my $SEND_UDP = 1;
my $SEND_TCP = 2;
my $SEND_ICMP = 3;
my $SEND_HTTP = 4;

### ACCESS message:
###     random data :user : client_timestamp : client_version : \
###     type (1) : access_request : digest
my $SPA_ACCESS_MODE  = 1;  ### default

### COMMAND message:
###     random data :user : client_timestamp : client_version : \
###     type (0) : command : digest
my $SPA_COMMAND_MODE = 0;

### FORWARD ACCESS message:
###     random data :user : client_timestamp : client_version : \
###     type (2) : access_request : NAT_info : digest
my $SPA_FORWARD_ACCESS_MODE = 2;

### ACCESS message with client-defined firewall timeout:
###     random data :user : client_timestamp : client_version : \
###     type (3) : access_request : timeout : digest
my $SPA_CLIENT_TIMEOUT_ACCESS_MODE = 3;

### FORWARD ACCESS message with client-defined firewall timeout:
###     random data :user : client_timestamp : client_version : \
###     type (4) : access_request : NAT_info : timeout : digest
my $SPA_CLIENT_TIMEOUT_NAT_ACCESS_MODE = 4;

### local NAT ACCESS message:
###     random data : user : client_timestamp : client_version : \
###     type (5) : access_request : NAT_info : message digest
my $SPA_LOCAL_NAT_ACCESS_MODE = 5;

### local NAT ACCESS message with client-defined firewall timeout:
###     random data : user : client_timestamp : client_version : \
###     type (6) : access_request : NAT_info : timeout : message digest
my $SPA_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MODE = 6;

my @args_cp = @ARGV;

### make Getopts case sensitive
Getopt::Long::Configure('no_ignore_case');

exit 1 unless GetOptions(
    'Prepare-results'   => \$prepare_results,
    'fwknop-command=s'  => \$fwknopCmd,
    'fwknopd-command=s' => \$fwknopdCmd,
    'knoptm-command=s'  => \$knoptmCmd,
    'access-conf=s'     => \$default_access_conf,
    'loopback-intf=s'   => \$loopback_intf,
    'IPTables-ChainMgr-VERSION=s' => \$ipt_chainmgr_version,
    'test-include=s'    => \$test_include,
    'include=s'         => \$test_include,  ### synonym
    'test-exclude=s'    => \$test_exclude,
    'exclude=s'         => \$test_exclude,  ### synonym
    'test-system-fwknop' => \$test_system_installed_fwknop,
    'skip-lx-check'     => \$skip_language_check,
    'no-client-FKO-module' => \$no_client_fko_module, # fwknop client without using libfko
    'no-server-FKO-module' => \$no_server_fko_module, # fwknop server without using libfko
    'help'              => \$help
);

&usage() if $help;

if ($test_include) {
    @tests_to_include = split /\s*,\s*/, $test_include;
}
if ($test_exclude) {
    @tests_to_exclude = split /\s*,\s*/, $test_exclude;
}

### create an anonymized tar file of test suite results that can be
### emailed around to assist in debugging fwknop communications
exit &prepare_results() if $prepare_results;

### see if the client/server is perl or C
&check_language() unless $skip_language_check;

### import fwknop perl modules
&import_perl_modules();

&setup();
&parse_access_conf($default_access_conf);

&write_key();

my $test_mode_opt   = '--Test';
my $spoof_user_opt  = '--Spoof-user';
my $spoof_proto_opt = '--Spoof-proto';
my $server_port_opt = '--Server-port';
my $server_cmd_opt  = '--Server-cmd';
my $http_opt        = '--HTTP';
my $digest_opt      = '--digest-alg';
my $nat_access_opt  = '--NAT-access';
my $nat_local_opt   = '--NAT-local';
my $nat_rand_opt    = '--NAT-rand-port';
my $show_last_opt   = '--Show-last';
my $http_proxy_opt  = '--HTTP-proxy';
my $server_test_mode_opt = '--Test';

my $http_proxy_host = 'proxy.host.domain.com';
if ($client_language eq 'C') {
    $test_mode_opt   = '--test';
    $spoof_user_opt  = '--spoof-user';
    $spoof_proto_opt = '--server-proto';
    $server_port_opt = '--server-port';
    $nat_access_opt  = '--nat-access';
    $nat_local_opt   = '--nat-local';
    $nat_rand_opt    = '--nat-rand-port';
    $http_opt        = '--server-proto http';
    $digest_opt      = '--digest-type';
    $server_cmd_opt  = '--server-command';
    $show_last_opt   = '--show-last';
}

if ($server_language eq 'C') {
    $server_test_mode_opt = '--test';
}

if ($no_client_fko_module) {
    $fwknopCmd .= " --no-FKO-module";
} else {
    ### see if fwknop is going to use the FKO module
    &fwknop_test_fko_exists();
}

my $default_fwknop_args = "$fwknopCmd -A $open_ports --no-save --get-key " .
        "$local_key_file -D $localhost -a $allow_src $test_mode_opt -v " .
        "$spoof_user_opt $require_user";

my $fwknop_args_no_dash_A = "$fwknopCmd --no-save --get-key " .
        "$local_key_file -D $localhost -a $allow_src $test_mode_opt -v " .
        "$spoof_user_opt $require_user";

if ($no_server_fko_module) {
    $fwknopdCmd .= " --no-FKO-module";
} else {
    ### see if fwknopd is going to use the FKO module
    &fwknopd_test_fko_exists();
}

unless ($client_language eq 'C') {
    $default_fwknop_args   .= ' --debug';
    $fwknop_args_no_dash_A .= ' --debug';
}

&logr("\n[+] ==> Running fwknop test suite; " .
    "firewall: $config{'FIREWALL_TYPE'} <==\n\n" .
    "    args: $0 @args_cp\n\n");

### main tests
&test_driver('(Setup) perl program compilation', \&perl_compilation);
&test_driver('(Setup) C program compilation', \&C_compilation);
&test_driver('(Setup) Command line argument processing', \&getopt_test);
&test_driver('(Setup) Last command line execution', \&show_last);
&test_driver('(Setup) Expected code version', \&expected_code_version);
&test_driver("(Setup) List $config{'FIREWALL_TYPE'} rules", \&fw_list);
&test_driver("(Setup) System information and fwknop installation specifics",
    \&specs);
&test_driver('(Setup) Dump config', \&dump_config);
&test_driver('(Setup) Override config', \&override_config);
&test_driver('(Setup) Caching SPA packets to disk', \&SPA_disk_caching);
&test_driver('(Setup) Caching multiple SPA packets to disk',
    \&SPA_multi_packet_disk_caching);
&test_driver('(Setup) Stopping any running fwknopd processes',
    \&stop_fwknopd);

if ($config{'FIREWALL_TYPE'} eq 'iptables') {
    &test_driver('(Setup) Flushing all fwknopd iptables rules',
        \&flush_iptables);
    &test_driver('(Setup) Deleting all fwknopd iptables chains',
        \&del_ipt_chains);
}

### fundamental SPA access tests
&test_driver('(Basic communications) Generating SPA access packet',
    \&SPA_access_packet);
&test_driver('(Basic communications) Sniffing SPA access packet',
    \&SPA_sniff_decrypt);
&test_driver('(Basic communications) Verifying SPA access packet format',
    \&spa_access_format);
&test_driver('(Basic communications) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(Basic communications)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(Basic communications) Firewall access rules removed',
    \&fw_rules_removed);
&test_driver('(Basic communications) Stopping all running fwknopd processes',
    \&stop_fwknopd);

### digest/replay testing
&test_driver('(Replay attacks, broken data) Rijndael key validity',
    \&short_key);
&test_driver('(Replay attacks, broken data) Replay detection - all digests',
    \&replay_attack);
&test_driver('(Replay attacks, broken data) Replay detection - SHA256',
    \&replay_attack_sha256);
&test_driver('(Replay attacks, broken data) Replay detection - SHA1',
    \&replay_attack_sha1);
&test_driver('(Replay attacks, broken data) Replay detection - MD5',
    \&replay_attack_md5);
&stop_fwknopd_quiet('(Replay attacks, broken data)');

&test_driver("(Replay attacks, broken data) $NUM_RAND random packets",
    \&packet_randomness);

&test_driver('(Replay attacks, broken data) Truncated SPA packet',
    \&truncated_SPA_packet);
&test_driver('(Replay attacks, broken data) Sniffing truncated SPA packet',
    \&truncated_SPA_sniff_decrypt);
&test_driver('(Replay attacks, broken data) Firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(Replay attacks, broken data)');
&test_driver('(Replay attacks, broken data) SPA packet with bogus key',
    \&bogus_key_SPA_packet);
&test_driver('(Replay attacks, broken data) Sniffing broken SPA packet',
    \&bogus_SPA_sniff_decrypt);
&test_driver('(Replay attacks, broken data) Firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(Replay attacks, broken data)');

&test_driver('(Replay attacks, broken data) non-base64 SPA packet',
    \&non_base64_SPA_packet);
&test_driver('(Replay attacks, broken data) Sniffing non-base64 SPA packet',
    \&non_base64_SPA_sniff_decrypt);
&test_driver('(Replay attacks, broken data) Firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(Replay attacks, broken data)');

&test_driver('(Internal digest alg mis-match) Generating SPA packet',
    \&SPA_access_packet_md5);
&test_driver('(Internal digest alg mis-match) Sniffing SPA packet',
    \&SPA_sniff_decrypt_sha256);
&test_driver('(Internal digest alg mis-match) Firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(Internal digest alg mis-match)');

&test_driver("(pcap filter) SPA packet with $server_port_opt 62203",
    \&SPA_access_packet_62203);
&test_driver('(pcap filter) Sniffing SPA access packet',
    \&SPA_sniff_decrypt_62203);
&test_driver('(pcap filter) Verifying SPA access packet format',
    \&spa_access_format);
&test_driver('(pcap filter) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(pcap filter)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule timeout)");
&test_driver('(pcap filter) Firewall access rules removed',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(pcap filter)');

### client timeout with --fw-timeout on fwknop command line
&test_driver('(Client timeout) Generating SPA access packet',
    \&SPA_client_timeout_access_packet);
&test_driver('(Client timeout) Sniffing SPA access packet',
    \&client_timeout_sniff_decrypt);
&test_driver('(Client timeout) Verifying SPA access packet format',
    \&spa_client_timeout_access_format);
&test_driver('(Client timeout) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep(10, '(Client timeout)',
    "(Sleeping for 10 seconds for firewall rule timeout)");
&test_driver('(Client timeout) Firewall access rules removed',
    \&fw_rules_removed);
&test_driver('(Client timeout) Stopping all running fwknopd processes',
    \&stop_fwknopd);

### It is ok to append data in the current code since the Rijndael decrypt
### only returns the actual SPA payload (may need to revist this)
&test_driver('(Append data) Data appended to SPA packet', \&append_SPA_packet);
&test_driver('(Append data) Sniffing appended SPA packet',
    \&append_SPA_sniff_decrypt);
if ($fwknopd_using_fko_module) {
    &test_driver('(Append data) Firewall rules do not exist',
        \&fw_rules_removed);
} else {
    &test_driver('(Append data) Firewall rules exist', \&fw_rules_exist);
}
&stop_fwknopd_quiet('(Append data)');

&test_driver('(Append invalid multiple) Data append',
    \&append_invalid_multiple_SPA_packet);
&test_driver('(Append invalid multiple) Sniffing SPA packet',
    \&append_SPA_sniff_decrypt);
&test_driver('(Append invalid multiple) base64 invalid check',
    \&append_check_invalid_multiple);
&test_driver('(Append invalid multiple) Firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(Append invalid multiple)');

if ($client_language eq 'perl') {
    ### Salted__ prefix compatibility
    &test_driver('(Rijndael Salted__ compatibility) Generating SPA packet',
        \&SPA_access_packet_salted);
    &test_driver('(Rijndael Salted__ compatibility) Sniffing SPA packet',
        \&SPA_sniff_decrypt);
    &test_driver('(Rijndael Salted__ compatibility) Verifying SPA format',
        \&spa_access_format);
    &test_driver('(Rijndael Salted__ compatibility) Rules exist',
        \&fw_rules_exist);
    &test_sleep($fw_access_timeout+3, '(Rijndael Salted__ compatibility)',
        "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
        "timeout)");
    &test_driver('(Rijndael Salted__ compatibility) Rules removed',
        \&fw_rules_removed);
    &test_driver('(Rijndael Salted__ compatibility) Stopping fwknopd',
        \&stop_fwknopd);
}

### SPA over established TCP connections
&test_driver('(TCP socket established) Generating SPA access packet',
    \&SPA_access_packet_established_tcp);
&test_driver('(TCP socket established) Sniffing SPA access packet',
    \&SPA_sniff_decrypt_established_tcp);
&test_driver('(TCP socket established) Verifying SPA access packet format',
    \&spa_access_format);
&test_driver('(TCP socket established) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(TCP socket established)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(TCP socket established) Firewall access rules removed',
    \&fw_rules_removed);
&test_driver('(TCP socket established) Stopping all running fwknopd processes',
    \&stop_fwknopd);

### SPA over HTTP
&test_driver('(SPA over HTTP) Generating SPA access packet',
    \&SPA_access_packet_http);
&test_driver('(SPA over HTTP) Verifying beginning slash',
    \&http_verify_beginning_slash);
&test_driver('(SPA over HTTP) Sniffing SPA access packet',
    \&SPA_sniff_decrypt_http);
&test_driver('(SPA over HTTP) Verifying SPA access packet format',
    \&spa_access_format);
&test_driver('(SPA over HTTP) Verifying HTTP header structure',
    \&http_verify_request_header_ordering);
&test_driver('(SPA over HTTP) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(SPA over HTTP)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(SPA over HTTP) Firewall access rules removed',
    \&fw_rules_removed);
&test_driver('(SPA over HTTP) Stopping all running fwknopd processes',
    \&stop_fwknopd);

### include hostname in GET request
&test_driver('(SPA/HTTP localhost) Generating SPA access packet',
    \&SPA_access_packet_http_localhost);
&test_driver('(SPA/HTTP localhost) Verifying beginning slash',
    \&http_verify_beginning_slash);
&test_driver('(SPA/HTTP localhost) Sniffing SPA access packet',
    \&SPA_sniff_decrypt_http);
&test_driver('(SPA/HTTP localhost) Verifying SPA access packet format',
    \&spa_access_format);
&test_driver('(SPA/HTTP localhost) Verifying HTTP header structure',
    \&http_verify_request_header_ordering);
&test_driver('(SPA/HTTP localhost) Verifying localhost hostname',
    \&http_verify_pre_resolv_hostname_in_get_request);
&test_driver('(SPA/HTTP localhost) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(SPA/HTTP localhost)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(SPA/HTTP localhost) Firewall rules removed',
    \&fw_rules_removed);
&test_driver('(SPA/HTTP localhost) Stopping fwknopd processes',
    \&stop_fwknopd);

### send SPA HTTP request through a proxy
&test_driver('(SPA/HTTP proxy support) Generating SPA packet',
    \&SPA_access_packet_http_include_host);
&test_driver('(SPA/HTTP proxy support) Verifying http://',
    \&http_verify_beginning_http);
&test_driver('(SPA/HTTP proxy support) Sniffing SPA packet',
    \&SPA_sniff_decrypt_http);
&test_driver('(SPA/HTTP proxy support) Verifying SPA packet format',
    \&spa_access_format);
&test_driver('(SPA/HTTP proxy support) Verifying HTTP header',
    \&http_verify_request_header_ordering);
&test_driver('(SPA/HTTP proxy support) Verifying include hostname',
    \&http_verify_include_hostname_in_request);
&test_driver('(SPA/HTTP proxy support) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(SPA/HTTP proxy support)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(SPA/HTTP proxy support) Firewall rules removed',
    \&fw_rules_removed);
&test_driver('(SPA/HTTP proxy support) Stopping fwknopd processes',
    \&stop_fwknopd);

### SPA over ICMP
&test_driver('(SPA over ICMP) Generating SPA access packet',
    \&SPA_access_packet_icmp);
&test_driver('(SPA over ICMP) Sniffing SPA access packet',
    \&SPA_sniff_decrypt_icmp);
&test_driver('(SPA over ICMP) Verifying SPA access packet format',
    \&spa_access_format);
&test_driver('(SPA over ICMP) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(SPA over ICMP)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(SPA over ICMP) Firewall access rules removed',
    \&fw_rules_removed);
&test_driver('(SPA over ICMP) Stopping all running fwknopd processes',
    \&stop_fwknopd);

### SPA over established TCP connections + domain socket to fwknopd
&test_driver('(UNIX domain + TCP sockets) Generating SPA access packet',
    \&SPA_access_packet_established_tcp);
&test_driver('(UNIX domain + TCP sockets) Sniffing SPA access packet',
    \&SPA_sniff_decrypt_established_tcp_domain_sock);
&test_driver('(UNIX domain + TCP sockets) Verifying access packet format',
    \&spa_access_format);
&test_driver('(UNIX domain + TCP sockets) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(UNIX domain + TCP sockets)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(UNIX domain + TCP sockets) Firewall rules removed',
    \&fw_rules_removed);
&test_driver('(UNIX domain + TCP sockets) Stopping fwknopd processes',
    \&stop_fwknopd);

### SPA over UDP + domain socket to fwknopd
&test_driver('(UNIX domain + UDP sockets) Generating SPA access packet',
    \&SPA_access_packet);
&test_driver('(UNIX domain + UDP sockets) Sniffing SPA access packet',
    \&SPA_sniff_decrypt_udp_domain_sock);
&test_driver('(UNIX domain + UDP sockets) Verifying access packet format',
    \&spa_access_format);
&test_driver('(UNIX domain + UDP sockets) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(UNIX domain + UDP sockets)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(UNIX domain + UDP sockets) Firewall rules removed',
    \&fw_rules_removed);
&test_driver('(UNIX domain + UDP sockets) Stopping fwknopd processes',
    \&stop_fwknopd);

if ($config{'FIREWALL_TYPE'} eq 'iptables' and $ipt_chainmgr_version > 5) {
    ### IPTables::ChainMgr tests
    &test_driver('(IPTables::ChainMgr) waitpid() SPA access packet',
        \&SPA_access_packet);
    &test_driver('(IPTables::ChainMgr) waitpid() execution model',
        \&SPA_sniff_decrypt_waitpid);
    &test_driver('(IPTables::ChainMgr) Verifying SPA access packet format',
        \&spa_access_format);
    &test_driver('(IPTables::ChainMgr) Firewall access rules exist',
        \&fw_rules_exist);
    &test_sleep($fw_access_timeout+3, '(IPTables::ChainMgr)',
        "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
        "timeout)");
    &test_driver('(IPTables::ChainMgr) Firewall access rules removed',
        \&fw_rules_removed);
    &test_driver('(IPTables::ChainMgr) Stopping all running fwknopd processes',
        \&stop_fwknopd);

    &test_driver('(IPTables::ChainMgr) Additional sleep between ipt cmds',
        \&SPA_access_packet);
    &test_driver('(IPTables::ChainMgr) sniffing SPA access packet',
        \&SPA_sniff_decrypt_waitpid_sleep);
    &test_driver('(IPTables::ChainMgr) Verifying SPA access packet format',
        \&spa_access_format);
    &test_driver('(IPTables::ChainMgr) Firewall access rules exist',
        \&fw_rules_exist);
    &test_sleep($fw_access_timeout+3, '(IPTables::ChainMgr)',
        "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
        "timeout)");
    &test_driver('(IPTables::ChainMgr) Firewall access rules removed',
        \&fw_rules_removed);
    &test_driver('(IPTables::ChainMgr) Stopping all running fwknopd processes',
        \&stop_fwknopd);

    &test_driver('(IPTables::ChainMgr) system() SPA access packet',
        \&SPA_access_packet);
    &test_driver('(IPTables::ChainMgr) system() execution model',
        \&SPA_sniff_decrypt_system);
    &test_driver('(IPTables::ChainMgr) Verifying SPA access packet format',
        \&spa_access_format);
    &test_driver('(IPTables::ChainMgr) Firewall access rules exist',
        \&fw_rules_exist);
    &test_sleep($fw_access_timeout+3, '(IPTables::ChainMgr)',
        "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
        "timeout)");
    &test_driver('(IPTables::ChainMgr) Firewall access rules removed',
        \&fw_rules_removed);
    &test_driver('(IPTables::ChainMgr) Stopping all running fwknopd processes',
        \&stop_fwknopd);

    &test_driver('(IPTables::ChainMgr) popen() SPA access packet',
        \&SPA_access_packet);
    &test_driver('(IPTables::ChainMgr) popen() execution model',
        \&SPA_sniff_decrypt_popen);
    &test_driver('(IPTables::ChainMgr) Verifying SPA access packet format',
        \&spa_access_format);
    &test_driver('(IPTables::ChainMgr) Firewall access rules exist',
        \&fw_rules_exist);
    &test_sleep($fw_access_timeout+3, '(IPTables::ChainMgr)',
        "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
        "timeout)");
    &test_driver('(IPTables::ChainMgr) Firewall access rules removed',
        \&fw_rules_removed);
    &test_driver('(IPTables::ChainMgr) Stopping all running fwknopd processes',
        \&stop_fwknopd);
}

### destination port randomness
&test_driver('(Destination port randomness) Generating SPA packet',
    \&SPA_access_packet_rand_dest_port);
&test_driver('(Destination port randomness) Sniffing SPA packet',
    \&sniff_decrypt_rand_port);
&test_driver('(Destination port randomness) Verifying SPA format',
    \&spa_access_format);
&test_driver('(Destination port randomness) Rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(Destination port randomness)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(Destination port randomness) Rules removed',
    \&fw_rules_removed);
&test_driver('(Destination port randomness) Stopping fwknopd',
    \&stop_fwknopd);

### non-promiscuous capture
&test_driver('(Non-promisc capture) Generating SPA access packet',
    \&SPA_access_packet);
&test_driver('(Non-promisc capture) Sniffing SPA access packet',
    \&no_promisc_sniff_decrypt);
&test_driver('(Non-promisc capture) Verifying sniffed SPA access packet',
    \&spa_access_format);
&test_driver('(Non-promisc capture) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(Non-promisc capture)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(Non-promisc capture) Firewall access rules removed',
    \&fw_rules_removed);
&test_driver('(Non-promisc capture) Stopping all fwknopd processes',
    \&stop_fwknopd);

### SPA packet aging
&test_driver('(SPA aging) Generating SPA access packet',
    \&SPA_access_packet);
&test_driver('(SPA aging) Expired SPA packet detection',
    \&sniff_old_packet);
&test_driver('(SPA aging) Making sure firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(SPA aging)');
&test_driver('(SPA aging) SPA packet --time-offset-plus 60min',
    \&SPA_access_packet_plus60min);
&test_driver('(SPA aging) Expired SPA packet detection',
    \&sniff_old_packet);
&test_driver('(SPA aging) Making sure firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(SPA aging)');
&test_driver('(SPA aging) SPA packet --time-offset-minus 60min',
    \&SPA_access_packet_minus60min);
&test_driver('(SPA aging) Expired SPA packet detection',
    \&sniff_old_packet);
&test_driver('(SPA aging) Making sure firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(SPA aging)');

if ($require_source_addr) {
    &test_driver('(Require SRC) Generating SPA packet with 0.0.0.0 src addr',
        \&source_addr);
    &test_driver('(Require SRC) Sniffing packet with 0.0.0.0 src addr',
        \&sniff_source_addr);
    &test_driver('(Require SRC) Making sure firewall rules do not exist',
        \&fw_rules_removed);
    &stop_fwknopd_quiet('(Require SRC)');
}

if ($require_user) {
    &test_driver('(Require user) Generating SPA packet with unauthorized user',
        \&unauthorized_user);
    &test_driver('(Require user) Unauthorized user detection',
        \&sniff_unauthorized_user);
    &test_driver('(Require user) Making sure firewall rules do not exist',
        \&fw_rules_removed);
    &stop_fwknopd_quiet('(Require user)');
}

unless ($permit_client_ports) {
    ### the default access.conf does not allow client-requested ports
    &test_driver('(Permit ports) Generating unauthorized port access request',
        \&unauthorized_port_request);
    &test_driver('(Permit ports) Unauthorized port access detection',
        \&sniff_unauthorized_port_request);
    &test_driver('(Permit ports) Making sure firewall rules do not exist',
        \&fw_rules_removed);
    &stop_fwknopd_quiet('(Permit ports)');
}

### non-matching SOURCE test
&test_driver('(Bogus src) Generating SPA packet from non-matching src',
    \&non_matching_source_generation);
&test_driver('(Bogus src) Non-matching SOURCE block',
    \&non_matching_source_block);
&test_driver('(Bogus src) Making sure firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(Bogus src)');

### excluded SOURCE test (i.e. ! 127.0.0.2 test)
&test_driver('(Excluded src) Generating SPA packet from non-matching src',
    \&non_matching_source_generation);
&test_driver('(Excluded src) Non-matching SOURCE block',
    \&excluded_net_source_block);
&test_driver('(Excluded src) Making sure firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(Excluded src)');

### excluded SOURCE test (i.e. ! 127.0.0.2 test)
&test_driver('(Blacklist src) Generating blacklisted SPA packet',
    \&non_matching_source_generation);
&test_driver('(Blacklist src) Sniffing SPA packet',
    \&blacklist_net_source_block);
&test_driver('(Blacklist src) Making sure firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(Blacklist src)');

### blacklisted -a 127.0.0.2 address
&test_driver('(Blacklist src) Generating blacklisted -a SPA packet',
    \&non_matching_source_generation);
&test_driver('(Blacklist src) Sniffing SPA packet',
    \&blacklist_dashA_net_source_block);
&test_driver('(Blacklist src) Making sure firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(Blacklist src)');

### test multi-SOURCE access.conf configuration
&test_driver('(Multi-SOURCE) Generating SPA access packet',
    \&SPA_access_packet);
&test_driver('(Multi-SOURCE) Sniffing SPA access packet',
    \&sniff_decrypt_multi_source);
&test_driver('(Multi-SOURCE) Verifying SPA access packet format',
    \&spa_access_format);
&test_driver('(Multi-SOURCE) Firewall access rules exist',
    \&fw_rules_exist);
&test_sleep($fw_access_timeout+3, '(Multi-SOURCE)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(Multi-SOURCE) Firewall access rules removed',
    \&fw_rules_removed);
&test_driver('(Multi-SOURCE) Stopping running fwknopd processes',
    \&stop_fwknopd);

### test multi-port access.conf configuration
&test_driver('(Multi-port) Generating SPA access packet',
    \&SPA_access_packet_multi_port);
&test_driver('(Multi-port) Sniffing SPA access packet',
    \&sniff_decrypt_multi_port);
&test_driver('(Multi-port) Verifying SPA access packet format',
    \&spa_access_format);
&test_driver('(Multi-port) Firewall access rules exist',
    \&fw_rules_exist_multi_port);
&test_sleep($fw_access_timeout+3, '(Multi-port)',
    "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
    "timeout)");
&test_driver('(Multi-port) Firewall access rules removed',
    \&fw_rules_removed);
&test_driver('(Multi-port) Stopping running fwknopd processes',
    \&stop_fwknopd);

if (-e $gpgCmd and -x $gpgCmd) {
    &test_driver('(GnuPG) Generating SPA access packet',
        \&SPA_gpg_access_packet);
    &test_driver('(GnuPG) Sniffing SPA access packet to acquire access',
        \&gpg_sniff_decrypt);
    &test_driver('(GnuPG) Verifying sniffed SPA access packet format',
        \&spa_access_format);
    &test_driver('(GnuPG) Firewall access rules exist', \&fw_rules_exist);
    &test_sleep($fw_access_timeout+3, '(GnuPG)',
        "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
        "timeout)");
    &test_driver('(GnuPG) Firewall access rules removed', \&fw_rules_removed);
    &test_driver('(GnuPG) Stopping all running fwknopd processes',
        \&stop_fwknopd);

    &test_driver('(GnuPG) Excluding prefix config',
        \&gpg_sniff_decrypt_no_prefix_add);
    &test_driver('(GnuPG) Making sure firewall rules do not exist',
        \&fw_rules_removed);
    &stop_fwknopd_quiet('(GnuPG)');

    if ($client_language eq 'perl') {
        &test_driver('(GnuPG) Generating SPA packet with 0x8502 prefix',
            \&SPA_gpg_access_packet_with_prefix);
        &test_driver('(GnuPG) Sniffing SPA access packet to acquire access',
            \&gpg_sniff_decrypt);
        &test_driver('(GnuPG) Verifying sniffed SPA access packet format',
            \&spa_access_format);
        &test_driver('(GnuPG) Firewall access rules exist', \&fw_rules_exist);
        &test_sleep($fw_access_timeout+3, '(GnuPG)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(GnuPG) Firewall access rules removed', \&fw_rules_removed);
        &test_driver('(GnuPG) Stopping all running fwknopd processes',
            \&stop_fwknopd);
    }

    ### GnuPG SPA over HTTP
    &test_driver('(GnuPG/SPA over HTTP) Generating SPA access packet',
        \&SPA_gpg_access_packet_http);
    &test_driver('(GnuPG/SPA over HTTP) Verifying beginning slash',
        \&http_verify_beginning_slash);
    &test_driver('(GnuPG/SPA over HTTP) Sniffing SPA access packet',
        \&gpg_sniff_decrypt_http);
    &test_driver('(GnuPG/SPA over HTTP) Verifying SPA access packet format',
        \&spa_access_format);
    &test_driver('(GnuPG/SPA over HTTP) Verifying HTTP header structure',
        \&http_verify_request_header_ordering);
    &test_driver('(GnuPG/SPA over HTTP) Firewall access rules exist',
        \&fw_rules_exist);
    &test_sleep($fw_access_timeout+3, '(GnuPG/SPA over HTTP)',
        "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
        "timeout)");
    &test_driver('(GnuPG/SPA over HTTP) Firewall access rules removed',
        \&fw_rules_removed);
    &test_driver('(GnuPG/SPA over HTTP) Stopping all fwknopd processes',
        \&stop_fwknopd);
}

if ($gpg_mode_str eq '' and -e $gpg2Cmd and -x $gpg2Cmd) {
    &test_driver('(GnuPG v2) Generating SPA access packet',
        \&SPA_gpg2_access_packet);
    &test_driver('(GnuPG v2) Sniffing SPA access packet to acquire access',
        \&gpg2_sniff_decrypt);
    &test_driver('(GnuPG v2) Verifying sniffed SPA access packet format',
        \&spa_access_format);
    &test_driver('(GnuPG v2) Firewall access rules exist', \&fw_rules_exist);
    &test_sleep($fw_access_timeout+3, '(GnuPG v2)',
        "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
        "timeout)");
    &test_driver('(GnuPG v2) Firewall access rules removed',
        \&fw_rules_removed);
    &test_driver('(GnuPG v2) Stopping all running fwknopd processes',
        \&stop_fwknopd);

    ### GnuPGv2 SPA over HTTP
    &test_driver('(GnuPG v2 over HTTP) Generating SPA access packet',
        \&SPA_gpg2_access_packet_http);
    &test_driver('(GnuPG v2 over HTTP) Verifying beginning slash',
        \&http_verify_beginning_slash);
    &test_driver('(GnuPG v2 over HTTP) Sniffing SPA access packet',
        \&gpg2_sniff_decrypt_http);
    &test_driver('(GnuPG v2 over HTTP) Verifying SPA access packet format',
        \&spa_access_format);
    &test_driver('(GnuPG v2 over HTTP) Verifying HTTP header structure',
        \&http_verify_request_header_ordering);
    &test_driver('(GnuPG v2 over HTTP) Firewall access rules exist',
        \&fw_rules_exist);
    &test_sleep($fw_access_timeout+3, '(GnuPG v2 over HTTP)',
        "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
        "timeout)");
    &test_driver('(GnuPG v2 over HTTP) Firewall access rules removed',
        \&fw_rules_removed);
    &test_driver('(GnuPG v2 over HTTP) Stopping all fwknopd processes',
        \&stop_fwknopd);
}

### test SPA command execution instead of access requests
&test_driver('(Command execution) Generating SPA command packet',
    \&SPA_command_packet);
&test_driver('(Command execution) Sniffing SPA command packet and executing',
    \&fwknopd_command);
&test_driver('(Command execution) Verifying SPA command packet format',
    \&spa_command_format);
&test_driver('(Command execution) Making sure firewall rules do not exist',
    \&fw_rules_removed);

if ($cmd_regex) {
    $test_cmd = "touch $test_cmd_file";
    if ($test_cmd !~ /$cmd_regex/) {
        &test_driver('(Command execution) Non-matching regex command packet',
            \&SPA_non_matching_re_command_packet);
        &test_driver('(Command execution) SPA command packet filtered',
            \&fwknopd_no_re_command);
    }
}
&test_driver('(Command execution) Making sure firewall rules do not exist',
    \&fw_rules_removed);
&stop_fwknopd_quiet('(Command execution)');

### test external command execution and variable substitution
&test_driver('(External cmd execution) Generating SPA packet',
    \&SPA_access_packet);
&test_driver('(External cmd execution) Sniffing SPA packet',
    \&fwknopd_ext_command);
&test_driver('(External cmd execution) Verifying SPA command packet format',
    \&spa_access_format);
&test_driver('(External cmd execution) Verifying OPEN command execution',
    \&spa_open_command);
&test_sleep($fw_access_timeout+3, '(External cmd execution)',
    "(Sleeping for $fw_access_timeout (+3) seconds for timeout)");
&test_driver('(External cmd execution) Firewall rules do not exist',
    \&fw_rules_removed);
&test_driver('(External cmd execution) Verifying CLOSE command execution',
    \&spa_close_command);
&stop_fwknopd_quiet('(External cmd execution)');

&test_driver('(External cmd no OPEN_PORTS) Generating SPA packet',
    \&SPA_access_packet);
&test_driver('(External cmd no OPEN_PORTS) Sniffing SPA packet',
    \&fwknopd_ext_no_open_ports_command);
&test_driver('(External cmd no OPEN_PORTS) Verifying SPA packet format',
    \&spa_access_format);
&test_driver('(External cmd no OPEN_PORTS) Verifying OPEN command',
    \&spa_open_no_ports_command);
&test_sleep($fw_access_timeout+3, '(External cmd no OPEN_PORTS)',
    "(Sleeping for $fw_access_timeout (+3) seconds for timeout)");
&test_driver('(External cmd no OPEN_PORTS) Firewall rules do not exist',
    \&fw_rules_removed);
&test_driver('(External cmd no OPEN_PORTS) Verifying CLOSE command',
    \&spa_close_no_open_ports_command);
&stop_fwknopd_quiet('(External cmd no execution)');

&test_driver('(External cmd no -A) Generating SPA packet',
    \&SPA_access_packet_no_dash_A);
&test_driver('(External cmd no -A) Sniffing SPA packet',
    \&fwknopd_ext_no_dash_A_command);
&test_driver('(External cmd no -A) Verifying SPA packet format',
    \&spa_access_format);
&test_driver('(External cmd no -A) Verifying OPEN command',
    \&spa_open_no_dash_A_command);
&test_sleep($fw_access_timeout+3, '(External cmd no -A)',
    "(Sleeping for $fw_access_timeout (+3) seconds for timeout)");
&test_driver('(External cmd no -A) Firewall rules do not exist',
    \&fw_rules_removed);
&test_driver('(External cmd no -A) Verifying CLOSE command',
    \&spa_close_no_dash_A_command);
&stop_fwknopd_quiet('(External cmd no execution)');

if ($config{'FIREWALL_TYPE'} eq 'iptables') {

    if ($client_language eq 'perl' and $server_language eq 'perl') {

        ### legacy port knocking mode tests
        &test_driver('(Legacy Port Knocking Mode) Single port shared sequence',
            \&pk_single_port_shared_sequence);
        &test_driver('(Legacy Port Knocking Mode) Firewall rules exist',
            \&fw_rules_exist);

        &test_sleep($fw_access_timeout+3, '(Legacy Port Knocking Mode)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Legacy Port Knocking Mode) Firewall rules removed',
            \&fw_rules_removed);

        &test_driver('(Legacy Port Knocking Mode) Multi-port shared sequence',
            \&pk_multi_port_shared_sequence);
        &test_driver('(Legacy Port Knocking Mode) Firewall rules exist',
            \&fw_rules_exist);
        &test_sleep($fw_access_timeout+3, '(Legacy Port Knocking Mode)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Legacy Port Knocking Mode) Firewall rules removed',
            \&fw_rules_removed);

        &test_driver('(Legacy Port Knocking Mode) Multi-protocol sequence',
            \&pk_multi_protocol_shared_sequence);
        &test_driver('(Legacy Port Knocking Mode) Firewall rules exist',
            \&fw_rules_exist);
        &test_sleep($fw_access_timeout+3, '(Legacy Port Knocking Mode)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Legacy Port Knocking Mode) Firewall rules removed',
            \&fw_rules_removed);

        &test_driver('(Legacy Port Knocking Mode) Building encrypted sequence',
            \&pk_get_encrypted_sequence);
        &test_driver('(Legacy Port Knocking Mode) Sending encrypted sequence',
            \&pk_encrypted_sequence);
        &test_driver('(Legacy Port Knocking Mode) Firewall rules exist',
            \&fw_rules_exist);
        &test_sleep($fw_access_timeout+3, '(Legacy Port Knocking Mode)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Legacy Port Knocking Mode) Firewall rules removed',
            \&fw_rules_removed);
    }

    if ($server_language eq 'perl') {
        ### cache the ip_forward value and restore it if necessary (i.e. it is
        ### not "1")
        my $ip_forward = &cache_ip_forward_val();

        ### test FORWARD chain support and DNAT connections
        &test_driver('(FORWARD chain) Stopping all running fwknopd processes',
            \&stop_fwknopd);
        &test_driver('(FORWARD chain) Generating FORWARD chain access packet',
            \&SPA_forward_access_packet);
        &test_driver('(FORWARD chain) FORWARD and DNAT access rules',
            \&forward_access);
        &test_driver('(FORWARD chain) Verifying SPA FORWARD access packet format',
            \&spa_forward_access_format);
        &test_sleep($fw_access_timeout+3, '(FORWARD chain)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(FORWARD chain) Making sure firewall rules are removed',
            \&fw_rules_removed);
        &stop_fwknopd_quiet('(FORWARD chain)');

        ### internal IP address restrictions
        &test_driver('(FORWARD chain) Generating FORWARD access SPA packet',
            \&SPA_forward_access_packet_restricted_IP);
        &test_driver('(FORWARD chain) FORWARD access to restricted IP',
            \&restricted_forward_access);
        &test_driver('(FORWARD chain) Firewall rules do not exist',
            \&fw_rules_removed);
        &stop_fwknopd_quiet('(FORWARD chain)');

        ### client timeouts
        &test_driver('(Client timeout FORWARD chain) Creating FORWARD chain packet',
            \&SPA_forward_access_packet_client_timeout);
        &test_driver('(Client timeout FORWARD chain) FORWARD and DNAT rules',
            \&forward_request_client_timeout);
        &test_driver('(Client timeout FORWARD chain) Verifying format',
            \&spa_forward_access_format_client_timeout);
        &test_sleep($fw_access_timeout+3, '(Client timeout FORWARD chain)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Client timeout FORWARD chain) Making rules are removed',
            \&fw_rules_removed);
        &stop_fwknopd_quiet('(Client timeout FORWARD chain)');

        if ($ip_forward != 1) {
            ### restore ip_forward value
            &restore_ip_forward_val($ip_forward);
        }

        ### test NAT'ing local connections
        &test_driver('(Local NAT) Stopping all running fwknopd processes',
            \&stop_fwknopd);
        &test_driver('(Local NAT) Generating local NAT access packet',
            \&SPA_local_nat_access_packet);
        &test_driver('(Local NAT) Local access rules exist',
            \&SPA_local_access);
        &test_driver('(Local NAT) Verifying local NAT access packet format',
            \&spa_local_access_format);
        &test_sleep($fw_access_timeout+3, '(Local NAT)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Local NAT) Making sure firewall rules are removed',
            \&fw_rules_removed);
        &stop_fwknopd_quiet('(Local NAT)');

        ### client timeout with --fw-timeout on fwknop command line
        &test_driver('(Client timeout local NAT) Generating local NAT packet',
            \&SPA_local_nat_access_packet_client_timeout);
        &test_driver('(Client timeout local NAT) Local access rules exist',
            \&SPA_local_access_client_timeout);
        &test_driver('(Client timeout local NAT) Verifying local NAT format',
            \&spa_local_access_format_client_timeout);
        &test_sleep($fw_access_timeout+3, '(Client timeout local NAT)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Client timeout local NAT) Making sure rules removed',
            \&fw_rules_removed);
        &stop_fwknopd_quiet('(Client timeout local NAT)');

        ### test disabled NAT'ing of local connections
        &test_driver('(Disabled local NAT) Generating local NAT access packet',
            \&SPA_local_nat_access_packet);
        &test_driver('(Disabled local NAT) Restricted local NAT access',
            \&forward_local_access_restricted);
        &test_driver('(Disabled local NAT) Making sure rules do not exist',
            \&fw_rules_removed);
        &stop_fwknopd_quiet('(Disabled local NAT)');

        ### test NAT'ing local connections with randomized NAT port
        &test_driver('(Local NAT rand port) Generating local NAT access packet',
            \&SPA_local_nat_access_packet_rand_port);
        &test_driver('(Local NAT rand port) Local access rules exist',
            \&SPA_local_access_rand_port);
        &test_driver('(Local NAT rand port) Verifying local NAT packet format',
            \&spa_local_access_format);
        &test_sleep($fw_access_timeout+3, '(Local NAT rand port)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Local NAT rand port) Making sure firewall rules are removed',
            \&fw_rules_removed);
        &stop_fwknopd_quiet('(Local NAT rand port)');

        ### test NAT'ing local connections with randomized NAT port and
        ### randomized destination port
        &test_driver('(Local NAT rand NAT/dst port) Generating local NAT packet',
            \&SPA_local_nat_access_packet_rand_dst_port);
        &test_driver('(Local NAT rand NAT/dst port) Local access rules exist',
            \&SPA_local_access_rand_port);
        &test_driver('(Local NAT rand NAT/dst port) Verifying packet format',
            \&spa_local_access_format);
        &test_sleep($fw_access_timeout+3, '(Local NAT rand NAT/dst port)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Local NAT rand NAT/dst port) Firewall rules removed',
            \&fw_rules_removed);
        &stop_fwknopd_quiet('(Local NAT rand NAT/dst port)');

        ### test OUTPUT chain support
        &test_driver('(OUTPUT chain) Stopping all running fwknopd processes',
            \&stop_fwknopd);
        &test_driver('(OUTPUT chain) Generating OUTPUT chain access packet',
            \&SPA_output_access_packet);
        &test_driver('(OUTPUT chain) OUTPUT access rules', \&output_access);
        &test_driver('(OUTPUT chain) Verifying OUTPUT access packet format',
            \&spa_output_access_format);
        &test_sleep($fw_access_timeout+3, '(OUTPUT chain)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(OUTPUT chain) Making sure firewall rules are removed',
            \&fw_rules_removed);
        &stop_fwknopd_quiet('(OUTPUT chain)');

        ### test the Linux 'any' interface for SPA packet capture on
        ### all interfaces
        &test_driver('(Any interface capture) Generating SPA access packet',
            \&SPA_access_packet);
        &test_driver('(Any interface capture) Sniffing SPA access packet',
            \&SPA_sniff_decrypt_any_interface);
        &test_driver('(Any interface capture) Verifying SPA access packet format',
            \&spa_access_format);
        &test_driver('(Any interface capture) Firewall access rules exist',
            \&fw_rules_exist);
        &test_sleep($fw_access_timeout+3, '(Any interface capture)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Any interface capture) Firewall access rules removed',
            \&fw_rules_removed);
        &test_driver('(Any interface capture) Stopping all fwknopd processes',
            \&stop_fwknopd);
    }
}

### this test should also work on FreeBSD, but there seem to be issues
### acquiring packet data from /var/log/sniff.pcap with Net::Pcap 0.05
if (-e $tcpdumpCmd and -x $tcpdumpCmd) {

    ### see if tcpdump can sniff over the loopback interface
    &test_driver("(Filesystem tcpdump capture) Sniffing over $loopback_intf",
        \&tcpdump_over_loopback);

    if ($config{'FIREWALL_TYPE'} eq 'iptables') {

        &test_driver('(Filesystem tcpdump capture) Stopping fwknopd processes',
            \&stop_fwknopd);
        &get_sniff_file('(Filesystem tcpdump capture)');
        &start_tcpdump('(Filesystem tcpdump capture)');

        &test_driver('(Filesystem tcpdump capture) Generating SPA packet',
            \&SPA_access_packet);

        ### send the SPA packet once to make sure the $sniff_file is
        ### not zero-size (tcpdump will write it to $sniff_file)
        &send_packet('(Filesystem tcpdump capture)', 'somedatastring', $SEND_UDP);

        ### start fwknopd and acquire packet data from $sniff_file
        &test_driver('(Filesystem tcpdump capture) SPA communications via file',
            \&filesystem_capture);

        &test_driver('(Filesystem tcpdump capture) Firewall access rules exist',
            \&fw_rules_exist);
        &test_sleep($fw_access_timeout+3, '(Filesystem tcpdump capture)',
            "(Sleeping for $fw_access_timeout (+3) seconds for firewall rule " .
            "timeout)");
        &test_driver('(Filesystem tcpdump capture) Rules removed',
            \&fw_rules_removed);
    }
}

&test_driver('Stopping all running fwknopd processes', \&stop_fwknopd);
if ($config{'FIREWALL_TYPE'} eq 'iptables') {
    &test_driver('Deleting all fwknopd iptables chains', \&del_ipt_chains);
}
&test_driver('Verifying SPA digest file format', \&digest_format);
&test_driver('Collecting fwknop syslog messages', \&fwknop_syslog);

&logr("\n");
if ($successful_tests) {
    &logr("[+] ==> Passed $successful_tests/$test_num tests " .
        "against fwknop. <==\n");
}
if ($failed_tests) {
    &logr("[+] ==> Failed $failed_tests/$test_num tests " .
        "against fwknop. <==\n");
}
&logr("[+] This console output has been stored in: $logfile\n\n");

&flush_quiet();
system "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
    "--fw-type $config{'FIREWALL_TYPE'} --Kill > /dev/null 2>\&1";

exit 0;
#======================== end main =========================

sub test_driver() {
    my ($msg, $func_ref) = @_;

    ### inclusions/exclusions
    if ($test_include) {
        my $found = 0;
        for my $test (@tests_to_include) {
            if ($msg =~ /\(.*$test.*\)/) {
                $found = 1;
                last;
            }
        }
        return unless $found;
    }
    if ($test_exclude) {
        my $found = 0;
        for my $test (@tests_to_exclude) {
            if ($msg =~ /\(.*$test.*\)/) {
                $found = 1;
                last;
            }
        }
        return if $found;
    }

    ### remove the *.warn and *.die files before executing
    ### the test
    for my $file (glob("$output_dir/*.warn")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    for my $file (glob("$output_dir/*.die")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    my $test_status = 'pass';
    &dots_print($msg);
    if (&{$func_ref}) {
        &pass();
    } else {
        $test_status = 'fail';
        $failed_tests++;
    }

    ### check for *.warn or *.die files from this test.
    for my $file (glob("$output_dir/*.warn")) {
        &logr("    WARN messages from: $file " .
            "(appending to $current_test_file)\n");
        open W, "< $file" or die "[*] Could not open $file: $!";
        my @warnings = <W>;
        close W;
        open C, ">> $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        print C "\n" . localtime() . " WARN messages from: $file\n";
        print C for @warnings;
        close C;
    }

    for my $file (glob("$output_dir/*.die")) {
        &logr("    DIE messages from: $file " .
            "(appending to $current_test_file)\n");
        open D, "< $file" or die "[*] Could not open $file: $!";
        my @die_messages = <D>;
        close D;
        open C, ">> $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        print C "\n" . localtime() . " DIE messages from: $file\n";
        print C for @die_messages;
        close C;
    }

    open C, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print C "\n" . localtime() . " TEST: $msg, STATUS: $test_status\n";
    close C;

    $previous_test_file = $current_test_file;
    $test_num++;
    $current_test_file = "$output_dir/$test_num.test";

    return;
}

sub run_fwknopd() {
    my ($cached_spa_packet, $fwknop_conf, $access_conf) = @_;

    die "\n[*] Zero-length SPA packet" unless $cached_spa_packet;
    my $rv = 1;

    &parse_access_conf($access_conf);

    ### parse the fwknop conf file and see if we need to send over
    ### TCP, UDP, ICMP, or HTTP
    my $socket_type = $SEND_UDP;
    open F, "< $fwknop_conf" or die "[*] Could not open $fwknop_conf: $!";
    while (<F>) {
        if (/^\s*ENABLE_TCP_SERVER\s+Y;/) {
            $socket_type = $SEND_TCP;
            last;
        } elsif (/^\s*ENABLE_SPA_OVER_HTTP\s+Y;/) {
            $socket_type = $SEND_HTTP;
            last;
        } elsif (/^\s*PCAP_FILTER\s+.*icmp;/) {
            $socket_type = $SEND_ICMP;
            last;
        }
    }
    close F;

    ### start fwknopd to monitor for the Rijndael SPA packet over
    ### the loopback interface
    my $fwknopd_pid = &start_fwknopd($fwknop_conf, $access_conf);

    ### give fwknopd a chance to parse its config and start sniffing
    ### on the loopback interface
    sleep 2;

    ### send the SPA packet over UDP port 62201 to the fwknopd server
    &send_packet('', $cached_spa_packet, $socket_type);

    local $SIG{'ALRM'} = sub {die "[*] Sniff packet alarm.\n"};
    ### on some systems and libpcap combinations, it is possible for fwknopd
    ### to not receive packet data, so setting an alarm allows us to recover
    alarm $sniff_alarm;
    eval {
        ### fwknopd will exit after receiving the cached packet (--Count 1)
        waitpid($fwknopd_pid, 0);
    };
    alarm 0;
    if ($@) {
        &dump_pids();
        kill 9, $fwknopd_pid unless kill 15, $fwknopd_pid;
        $rv = 0;
    }
    return $rv;
}

sub pk_get_encrypted_sequence() {

    &write_key();

    my $cmd = "$fwknopCmd -A $open_ports --no-save --get-key $local_key_file " .
        "-D $localhost -a $allow_src $test_mode_opt -v --debug --Server-mode " .
        "knock $spoof_user_opt $require_user";

    if (&run_cmd($cmd, $NO_APPEND)) {
        my $found_seq = 0;
        open F, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<F>) {
            ### Cipher-text sequence (32 bytes): 83 97 108 116 101 100 95 95 53
            ### 251 64 213 63 90 53 30 94 188 119 247 213 128 55 204 221 76 100
            ### 93 111 102 245 36
            if (/Cipher\-text\s+sequence\s\(.*?\):\s+(.*)/) {
                my $str = $1;
                $str =~ s|(\d+)|tcp/$1,|g;
                $str =~ s|\,\s*$||;
                $pk_encrypted_sequence = $str;
                $found_seq = 1;
                last;
            }
        }
        close F;
        if ($found_seq) {
            return 1;
        } else {
            return &print_errors("[-] Could not extract encrypted " .
                "knock sequence.");
        }
    }
    return &print_errors("[-] Could not execute: $cmd");
}

sub pk_run_fwknopd() {
    my ($seq_type, $fwknop_conf, $access_conf) = @_;

    my $rv = 1;

    my $sequence = '';
    $pk_shared_sequence = '';
    my $port_offset = 0;

    &parse_access_conf($access_conf);

    if ($seq_type == $SHARED_SEQ) {

        die "[*] SHARED_SEQUENCE not defined in $access_conf"
            unless $pk_shared_sequence;

        $sequence = $pk_shared_sequence;

    } elsif ($seq_type == $ENCRYPTED_SEQ) {

        die "[*] ENCRYPTED_SEQUENCE not defined in $access_conf"
            unless $pk_encrypted_sequence;

        $sequence = $pk_encrypted_sequence;
        $port_offset = 61000;

    } else {
        die "[*] Invalid sequence type: $seq_type";
    }

    ### create the fwdata file if necessary
    unless (-e 'output/fwdata') {
        open FW, '> output/fwdata'
            or die '[*] Could not create output/fwdata';
        close FW;
    }

    ### start fwknopd to monitor for iptables port knocking sequences
    my $fwknopd_pid = &pk_start_fwknopd($fwknop_conf, $access_conf);

    ### give fwknopd a chance to parse its config and start parsing
    ### the iptables logfile
    sleep 2;

    ### write iptables log messages to simulate the port knocking
    ### sequence
    &pk_write_iptables_msgs($sequence, $port_offset);

    local $SIG{'ALRM'} = sub {die "[*] iptables message parsing alarm.\n"};
    ### on some systems and libpcap combinations, it is possible for fwknopd
    ### to not receive packet data, so setting an alarm allows us to recover
    alarm $sniff_alarm;
    eval {
        ### fwknopd will exit after receiving the cached packet (--Count 1)
        waitpid($fwknopd_pid, 0);
    };
    alarm 0;
    if ($@) {
        &dump_pids();
        kill 9, $fwknopd_pid unless kill 15, $fwknopd_pid;
        $rv = 0;
    }
    return $rv;
}

sub dump_pids() {
    open C, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print C "\n" . localtime() . " [+] PID dump:\n";
    close C;
    if ($config{'FIREWALL_TYPE'} eq 'iptables') {
        &run_cmd("ps auxww | grep knop |grep -v grep", $APPEND);
        &run_cmd("ps auxww | grep iptables |grep -v knop| grep -v grep", $APPEND);
    } else {
        &run_cmd("ps auxww | grep knop | grep -v grep", $APPEND);
        &run_cmd("ps auxww | grep ipfw | grep -v knop | grep -v grep",
            $APPEND);
    }
    return;
}

sub fw_list() {
    my $cmd = "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
        "--fw-type $config{'FIREWALL_TYPE'} --fw-list -v";
    if (&run_cmd($cmd, $NO_APPEND)) {
        return 1;
    }
    return &print_errors("[-] Could not execute: $cmd");
}

sub specs() {
    my $cmd = '';
    if ($config{'FIREWALL_TYPE'} eq 'iptables') {
        $cmd = "iptables -v -n -L";
    } else {
        $cmd = "ipfw list";
    }
    open F, "> $current_test_file" or die $!;
    print F "# $cmd\n";
    close F;
    system "$cmd >> $current_test_file 2>&1";
    for my $cmd (
        'uname -a',
        'uptime',
        'perl -V',
        'if [ `which gpg` ]; then gpg --version; fi',
        'ifconfig -a',
        'ls -l /etc', 'if [ -e /etc/issue ]; then cat /etc/issue; fi',
        'if [ `which iptables` ]; then iptables -V; fi',
        'if [ -e /proc/cpuinfo ]; then cat /proc/cpuinfo; fi',
        'if [ -e /proc/config.gz ]; then zcat /proc/config.gz; fi',
        "$fwknopdCmd $gpg_mode_str -S -c $default_fwknop_conf",
        "$fwknopdCmd $gpg_mode_str -V",
        "$fwknopCmd -V",
        'if [ -e /usr/bin/fwknop ]; then /usr/bin/fwknop -V; fi',
        'if [ -e /usr/sbin/fwknopd ]; then /usr/sbin/fwknopd -V; fi',
        "ldd $tcpdumpCmd",
        'ls -l /usr/lib/*pcap*',
        'ls -l /usr/local/lib/*pcap*',
        'find /usr/lib/fwknop -type f'
    ) {
        open F, ">> $current_test_file" or die $!;
        print F "# $cmd\n";
        close F;
        system "$cmd >> $current_test_file 2>&1";
    }
    return 1;
}

sub pk_single_port_shared_sequence() {

    if (&pk_run_fwknopd($SHARED_SEQ, $pk_fwknop_conf,
            $pk_single_port_shared_sequence_conf)) {
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### FIXME look for error condition
        }
        close SE;
        return 1;
    }
    return &print_errors("[-] iptables parse alarm " .
            "($sniff_alarm seconds) expired");
}

sub pk_multi_port_shared_sequence() {
    if (&pk_run_fwknopd($SHARED_SEQ, $pk_fwknop_conf,
            $pk_multi_port_shared_sequence_conf)) {
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### FIXME look for error condition
        }
        close SE;
        return 1;
    }
    return &print_errors("[-] iptables parse alarm " .
            "($sniff_alarm seconds) expired");
}

sub pk_multi_protocol_shared_sequence() {
    if (&pk_run_fwknopd($SHARED_SEQ, $pk_fwknop_conf,
            $pk_multi_protocol_shared_sequence_conf)) {
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### look for error condition
        }
        close SE;
        return 1;
    }
    return &print_errors("[-] iptables parse alarm " .
            "($sniff_alarm seconds) expired");
}

sub pk_encrypted_sequence() {
    if (&pk_run_fwknopd($ENCRYPTED_SEQ, $pk_fwknop_conf,
            $pk_encrypted_sequence_conf)) {
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### look for error condition
        }
        close SE;
        return 1;
    }
    return &print_errors("[-] iptables parse alarm " .
            "($sniff_alarm seconds) expired");
}

sub fwknop_syslog() {
    my $cmd = 'grep fwknop /var/log/* |tail -n 5000';
    if (&run_cmd($cmd, $NO_APPEND)) {
        return 1;
    }
    return &print_errors("[-] Could not execute $cmd");
}

sub filesystem_capture() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $pcap_file_fwknop_conf, $default_access_conf)) {
        return 1;
    }
    return &print_errors("[-] Sniff alarm " .
            "($sniff_alarm seconds) expired");
}

sub sniff_old_packet() {

    sleep 5;  ### FIXME, should acquire this from $spa_aging_fwknop_conf

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $spa_aging_fwknop_conf, $default_access_conf)) {

        my $found_old_packet = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/remote\s+time\s+stamp\s+age\s+difference/i) {
                $found_old_packet = 1;
                last;
            }
        }
        close SE;

        if ($found_old_packet) {
            return 1;
        } else {
            return &print_errors("[-] fwknopd " .
                    "accepted old SPA packet");
        }
    }
    return &print_errors("[-] Sniff alarm " .
            "($sniff_alarm seconds) expired");
}

sub replay_attack() {

    &get_access_packet($default_fwknop_args, $default_fwknop_conf, $NO_QUIET);

    ### write out the digest to the digest.cache so that we
    ### can easily simulate a replay attack
    &write_digest();

    ### this replays the previous access packet defined
    ### by $cache_encrypted_spa_packet
    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the replay was detected
        my $found_replay = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+attempted\s+SPA\s+packet\s+replay/i) {
                ### [-] attempted SPA packet replay from: 127.0.0.1 (original \
                ### SPA src: 127.0.0.1, digest: 40qPGOpvRBX54E4CmVsxSA)
                $found_replay = 1;
                last;
            }
        }
        close SE;

        if ($found_replay) {
            return 1;
        } else {
            return &print_errors("[-] Replay attack not detected");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub replay_attack_sha256() {

    ### SHA256 is the default anyway
    &get_access_packet("$default_fwknop_args $digest_opt sha256",
        $sha256_fwknop_conf, $NO_QUIET);

    ### write out the SHA256 digest to the digest.cache file so that we
    ### can easily simulate a replay attack
    &write_digest();

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $sha256_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the replay was detected
        my $found_replay = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+attempted\s+SPA\s+packet\s+replay/i) {
                ### [-] attempted SPA packet replay from: 127.0.0.1 (original \
                ### SPA src: 127.0.0.1, digest: 40qPGOpvRBX54E4CmVsxSA)
                $found_replay = 1;
                last;
            }
        }
        close SE;

        if ($found_replay) {
            return 1;
        } else {
            return &print_errors("[-] Replay attack not detected");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub replay_attack_sha1() {

    &get_access_packet("$default_fwknop_args $digest_opt sha1",
        $sha1_fwknop_conf, $NO_QUIET);

    ### write out the SHA1 digest to the digest.cache so that we
    ### can easily simulate a replay attack
    &write_digest();

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $sha1_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the replay was detected
        my $found_replay = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+attempted\s+SPA\s+packet\s+replay/i) {
                ### [-] attempted SPA packet replay from: 127.0.0.1 (original \
                ### SPA src: 127.0.0.1, digest: 40qPGOpvRBX54E4CmVsxSA)
                $found_replay = 1;
                last;
            }
        }
        close SE;

        if ($found_replay) {
            return 1;
        } else {
            return &print_errors("[-] Replay attack not detected");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub replay_attack_md5() {

    &get_access_packet("$default_fwknop_args $digest_opt md5",
        $md5_fwknop_conf, $NO_QUIET);

    ### write out the MD5 digest to the digest.cache so that we
    ### can easily simulate a replay attack
    &write_digest();

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $md5_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the replay was detected
        my $found_replay = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+attempted\s+SPA\s+packet\s+replay/i) {
                ### [-] attempted SPA packet replay from: 127.0.0.1 (original \
                ### SPA src: 127.0.0.1, digest: 40qPGOpvRBX54E4CmVsxSA)
                $found_replay = 1;
                last;
            }
        }
        close SE;

        if ($found_replay) {
            return 1;
        } else {
            return &print_errors("[-] Replay attack not detected");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub non_matching_source_generation() {
    return &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $NO_QUIET);
}

sub write_digest() {
    open F, ">> $output_dir/digest.cache" or die "[*] Could not open ",
        "$output_dir/digest.cache: $!";
    print F "$allow_src $spa_packet_digest [" . localtime() . "]\n";
    close F;
    return;
}

sub excluded_net_source_block() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $excluded_net_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_no_ip_match = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/excluded\s+by\s+\!\s+/) {
                $found_no_ip_match = 1;
                last;
            }
        }
        close SE;
        unless ($found_no_ip_match) {
            return &print_errors("[-] fwknopd " .
                "accepted SPA packet with no matching SOURCE block");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub restricted_forward_access() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $forward_fwknop_conf, $restricted_forward_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_restricted_match = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/NAT\s+access.*restricted/) {
                $found_restricted_match = 1;
                last;
            }
        }
        close SE;
        unless ($found_restricted_match) {
            return &print_errors("[-] fwknopd " .
                "accepted FORWARD access to restricted internal IP");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub blacklist_net_source_block() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $blacklist_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_blacklist_match = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/in\s+BLACKLIST/) {
                $found_blacklist_match = 1;
                last;
            }
        }
        close SE;
        unless ($found_blacklist_match) {
            return &print_errors("[-] fwknopd " .
                "accepted blacklisted SPA packet");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub blacklist_dashA_net_source_block() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $blacklist_dashA_IP_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_blacklist_match = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/in\s+BLACKLIST/) {
                $found_blacklist_match = 1;
                last;
            }
        }
        close SE;
        unless ($found_blacklist_match) {
            return &print_errors("[-] fwknopd " .
                "accepted blacklisted SPA packet");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub non_matching_source_block() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $no_loopback_ip_match_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_no_ip_match = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/did\s+not\s+match\s+any\s+SOURCE/) {
                $found_no_ip_match = 1;
                last;
            }
        }
        close SE;
        unless ($found_no_ip_match) {
            return &print_errors("[-] fwknopd " .
                "accepted SPA packet with no matching SOURCE block");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub fw_rules_removed() {
    if (&fw_rules()) {
        ### forcibly delete the rules so that the next test
        ### will not also fail if the rules are not supposed to
        ### be there.
        &flush_quiet();
        return &print_errors("[-] Access " .
                "rules for $allow_src not removed.");
    }
    return 1;
}

sub flush_quiet() {
    if ($config{'FIREWALL_TYPE'} eq 'iptables') {
        system "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
            "--fw-type $config{'FIREWALL_TYPE'} --fw-flush " .
            "> /dev/null 2>\&1";
    } else {
        system "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
            "--fw-type $config{'FIREWALL_TYPE'} " .
            "--fw-del-ip $allow_src > /dev/null 2>\&1";
    }
    return;
}

sub tcpdump_over_loopback() {
    &get_sniff_file('(Filesystem tcpdump capture)');
    &start_tcpdump('(Filesystem tcpdump capture)');
    sleep 1;
    &send_packet('', 'somedatastring', $SEND_UDP);
    sleep 1;
    &send_packet('', 'somedatastring', $SEND_UDP);
    sleep 1;

    if (not -e $sniff_file or -s $sniff_file == 0) {
        return &print_errors("[-] tcpdump " .
            "could not acquire packet data over $loopback_intf interface");
    }
    return 1;
}

sub fw_rules_exist() {
    unless (&fw_rules()) {
        return &print_errors("[-] Access rules for $allow_src do not exist.");
    }
    return 1;
}

sub fw_rules_exist_multi_port() {
    unless (&fw_rules_multi_port()) {
        return &print_errors("[-] Access rules for $allow_src do not exist.");
    }
    return 1;
}

sub flush_iptables() {
    my $cmd = "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf --fw-flush";
    unless (&run_cmd($cmd, $NO_APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }
    return 1;
}

sub stop_fwknopd() {
    my $cmd = "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
        "--fw-type $config{'FIREWALL_TYPE'} --Kill";
    unless (&run_cmd($cmd, $NO_APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }
    $cmd = "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
        "--fw-type $config{'FIREWALL_TYPE'} --Status";
    unless (&run_cmd($cmd, $APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }

    my $pid_file_msg_ctr = 0;
    open F, "< $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    while (<F>) {
        ### [+] knopwatchd pidfile does not exist.
        if (/^\s*\[\+\].*pidfile\s+does\s+not\s+exist/) {
            $pid_file_msg_ctr++;
        }
    }
    close F;

    unless ($pid_file_msg_ctr == 3) {
        return &print_errors("[-] All three fwknopd processes are not stopped");
    }
    return 1;
}

sub stop_fwknopd_quiet() {
    my $msg = shift;  ### for --test-include and --test-exclude matches

    ### inclusions/exclusions
    if ($test_include) {
        my $found = 0;
        for my $test (@tests_to_include) {
            if ($msg =~ /\(.*$test.*\)/) {
                $found = 1;
                last;
            }
        }
        return unless $found;
    }
    if ($test_exclude) {
        my $found = 0;
        for my $test (@tests_to_exclude) {
            if ($msg =~ /\(.*$test.*\)/) {
                $found = 1;
                last;
            }
        }
        return if $found;
    }

    &flush_quiet();
    system "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
        "--fw-type $config{'FIREWALL_TYPE'} --Kill > /dev/null 2>\&1";

    return;
}

sub test_sleep() {
    my ($timeout, $msg_tag, $msg_log) = @_;

    ### inclusions/exclusions
    if ($test_include) {
        my $found = 0;
        for my $test (@tests_to_include) {
            if ($msg_tag =~ /\(.*$test.*\)/) {
                $found = 1;
                last;
            }
        }
        return unless $found;
    }
    if ($test_exclude) {
        my $found = 0;
        for my $test (@tests_to_exclude) {
            if ($msg_tag =~ /\(.*$test.*\)/) {
                $found = 1;
                last;
            }
        }
        return if $found;
    }

    &logr("    $msg_log\n    ");

    for (my $i=$timeout; $i > 0; $i--) {
        &logr("$i ");
        sleep 1;
    }

    &logr("0\n");

    return;
}

sub fw_rules() {
    my $cmd = "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
        "--fw-type $config{'FIREWALL_TYPE'} --fw-list";
    unless (&run_cmd($cmd, $NO_APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }

    my $found_access_rules = 0;
    open F, "< $current_test_file" or
        die "[*] Could not open $current_test_file: $!";
    while (<F>) {
        next if /DISABLED/;  ### exclude ipfw DISABLED rules
        if (/\b$allow_src\b/) {
            $found_access_rules = 1;
            last;
        }
    }
    close F;
    if ($found_access_rules) {
        return 1;
    }
    return 0;
}

sub fw_rules_multi_port() {
    my $cmd = "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
        "--fw-type $config{'FIREWALL_TYPE'} --fw-list";
    unless (&run_cmd($cmd, $NO_APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }

    my $found_access_rules = 0;
    open F, "< $current_test_file" or
        die "[*] Could not open $current_test_file: $!";
    while (<F>) {
        if (/\b$allow_src\b/) {
            $found_access_rules++;
        }
    }
    close F;
    if ($found_access_rules == 2) {
        return 1;
    }
    return 0;
}

sub gpg_sniff_decrypt_no_prefix_add() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $gpg_access_no_prefix_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\s+is\s+not\s+prefixed/i) {
                close SE;
                return 1;
            }
        }
        close SE;
        return &print_errors("[-] fwknopd accepted SPA packet without prefix");
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub gpg_sniff_decrypt_http() {
    return &sniff_decrypt($http_fwknop_conf, $gpg_access_conf);
}

sub gpg_sniff_decrypt() {
    return &sniff_decrypt($default_fwknop_conf, $gpg_access_conf);
}

sub gpg2_sniff_decrypt() {
    return &sniff_decrypt($gpg2_fwknop_conf, $gpg2_access_conf);
}

sub gpg2_sniff_decrypt_http() {
    return &sniff_decrypt($gpg2_http_fwknop_conf, $gpg2_access_conf);
}

sub SPA_sniff_decrypt() {
    return &sniff_decrypt($default_fwknop_conf, $default_access_conf);
}

sub SPA_sniff_decrypt_any_interface() {
    return &sniff_decrypt($any_interface_fwknop_conf, $default_access_conf);
}

sub SPA_sniff_decrypt_icmp() {
    return &sniff_decrypt($icmp_fwknop_conf, $default_access_conf);
}

sub SPA_sniff_decrypt_http() {
    $http_test_file = $current_test_file;
    return &sniff_decrypt($http_fwknop_conf, $default_access_conf);
}

sub http_verify_beginning_slash() {
    return 1 if $cache_encrypted_spa_packet =~ m|^/|;
    return &print_errors('[-] SPA packet does not contain beginning slash');
}

sub http_verify_beginning_http() {
    return 1 if $cache_encrypted_spa_packet =~ m|^http://|;
    return &print_errors('[-] SPA packet does not contain beginning http://');
}

sub http_verify_request_header_ordering() {
    open F, "< $http_test_file" or
            die "[*] Could not open $http_test_file: $!";
    while (<F>) {
        if (m|Raw\s+packet\s+data\s.*\sGET\s\S+\s+HTTP/1\.0NANA
                User\-Agent:\s+Fwknop/\d+\.\d+\S{0,3}NANAAccept:\s\*/\*NANA
                Host:\s\S+NANAConnection:\sKeep-Alive|x) {
            close F;
            return 1;
        }
    }
    close F;
    return &print_errors('[-] Invalid SPA GET request');
}

sub http_verify_pre_resolv_hostname_in_get_request() {
    open F, "< $http_test_file" or
            die "[*] Could not open $http_test_file: $!";
    while (<F>) {
        if (m|Raw\s+packet\s+data\s.*\sGET\s/\S+\s+HTTP/1\.0NANA
                User\-Agent:\s+Fwknop/\d+\.\d+\S{0,3}NANAAccept:\s\*/\*NANA
                Host:\slocalhostNANAConnection:\sKeep-Alive|x) {
            close F;
            return 1;
        }
    }
    close F;
    return &print_errors('[-] GET request does not contain ' .
        'localhost hostname');
}

sub http_verify_include_hostname_in_request() {
    open F, "< $http_test_file" or
            die "[*] Could not open $http_test_file: $!";
    while (<F>) {
        if (m|Raw\s+packet\s+data\s.*\sGET\shttp://$http_proxy_host/\S+\s+HTTP/1\.0NANA
                User\-Agent:\s+Fwknop/\d+\.\d+\S{0,3}NANAAccept:\s\*/\*NANA
                Host:\s${http_proxy_host}NANAConnection:\sKeep-Alive|x) {
            close F;
            return 1;
        }
    }
    close F;
    return &print_errors('[-] GET request does not contain ' .
        "http://$http_proxy_host hostname");
}

sub SPA_sniff_decrypt_established_tcp() {
    return &sniff_decrypt($tcp_serv_fwknop_conf, $default_access_conf);
}

sub SPA_sniff_decrypt_established_tcp_domain_sock() {
    if (&run_fwknopd($cache_encrypted_spa_packet,
            $socket_com_tcp_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, make sure we see the
        ### "socket_loop()" debugging statement for getting SPA
        ### packets via a UNIX domain socket
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/socket_loop\(\)\s+acquiring\s+SPA.*domain/i) {
                close SE;
                return 1;
            }
        }
        close SE;
        return &print_errors("[-] Could not find 'socket_loop()' " .
            "domain sock handling");
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub SPA_sniff_decrypt_udp_domain_sock() {
    if (&run_fwknopd($cache_encrypted_spa_packet,
            $socket_com_udp_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, make sure we see the
        ### "socket_loop()" debugging statement for getting SPA
        ### packets via a UNIX domain socket
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/socket_loop\(\)\s+acquiring\s+SPA.*domain/i) {
                close SE;
                return 1;
            }
        }
        close SE;
        return &print_errors("[-] Could not find 'socket_loop()' " .
            "domain sock handling");
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub SPA_sniff_decrypt_waitpid() {
    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        my $found_waitpid_model_msgs = 0;
        ### now that fwknopd has exited, see if the SPA packet was valid
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+Key\s+mis\-?match/i) {
                ### [-] Key mis-match or broken message checksum for SOURCE \
                ### ANY (# 1 in access.conf)
                close SE;
                return &print_errors("[-] Key mis-match");
            } elsif (/\[\-\]\s+Decrypted.*not\s+conform/i) {
                ### [-] Decrypted message does not conform to a valid SPA packet
                close SE;
                return &print_errors("[-] Invalid SPA packet");
            } elsif (/run_ipt_cmd.*waitpid/) {
                $found_waitpid_model_msgs = 1;
                last;
            }
        }
        close SE;
        if ($found_waitpid_model_msgs) {
            return 1;
        } else {
            return &print_errors("[-] Could not find waitpid() model messages");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub SPA_sniff_decrypt_waitpid_sleep() {
    if (&run_fwknopd($cache_encrypted_spa_packet,
            $ipt_sleep_fwknop_conf, $default_access_conf)) {

        my $found_iptchainmgr_sleep = 0;
        ### now that fwknopd has exited, see if the SPA packet was valid
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+Key\s+mis\-?match/i) {
                ### [-] Key mis-match or broken message checksum for SOURCE \
                ### ANY (# 1 in access.conf)
                close SE;
                return &print_errors("[-] Key mis-match");
            } elsif (/\[\-\]\s+Decrypted.*not\s+conform/i) {
                ### [-] Decrypted message does not conform to a valid SPA packet
                close SE;
                return &print_errors("[-] Invalid SPA packet");
            } elsif (/IPTables::ChainMgr.*sleep\s+seconds/) {
                $found_iptchainmgr_sleep = 1;
                last;
            }
        }
        close SE;
        if ($found_iptchainmgr_sleep) {
            sleep 4;  ### give more time since knoptm will be slightly slower
                      ### because of additional sleeps before iptables cmds.
            return 1;
        } else {
            return &print_errors("[-] Could not find IPTables::ChainMgr " .
                "sleep message");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub SPA_sniff_decrypt_system() {
    if (&run_fwknopd($cache_encrypted_spa_packet,
            $system_fwknop_conf, $default_access_conf)) {

        my $found_system_model_msgs = 0;
        ### now that fwknopd has exited, see if the SPA packet was valid
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+Key\s+mis\-?match/i) {
                ### [-] Key mis-match or broken message checksum for SOURCE \
                ### ANY (# 1 in access.conf)
                close SE;
                return &print_errors("[-] Key mis-match");
            } elsif (/\[\-\]\s+Decrypted.*not\s+conform/i) {
                ### [-] Decrypted message does not conform to a valid SPA packet
                close SE;
                return &print_errors("[-] Invalid SPA packet");
            } elsif (/run_ipt_cmd.*system/) {
                $found_system_model_msgs = 1;
                last;
            }
        }
        close SE;
        if ($found_system_model_msgs) {
            return 1;
        } else {
            return &print_errors("[-] Could not find system() model messages");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub SPA_sniff_decrypt_popen() {
    if (&run_fwknopd($cache_encrypted_spa_packet,
            $popen_fwknop_conf, $default_access_conf)) {

        my $found_popen_model_msgs = 0;
        ### now that fwknopd has exited, see if the SPA packet was valid
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+Key\s+mis\-?match/i) {
                ### [-] Key mis-match or broken message checksum for SOURCE \
                ### ANY (# 1 in access.conf)
                close SE;
                return &print_errors("[-] Key mis-match");
            } elsif (/\[\-\]\s+Decrypted.*not\s+conform/i) {
                ### [-] Decrypted message does not conform to a valid SPA packet
                close SE;
                return &print_errors("[-] Invalid SPA packet");
            } elsif (/run_ipt_cmd.*popen/) {
                $found_popen_model_msgs = 1;
                last;
            }
        }
        close SE;
        if ($found_popen_model_msgs) {
            return 1;
        } else {
            return &print_errors("[-] Could not find popen() model messages");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub SPA_sniff_decrypt_62203() {
    return &sniff_decrypt($fwknop_62203_conf, $default_access_conf);
}

sub append_check_invalid_multiple() {
    open F, "< $previous_test_file" or die $!;
    while (<F>) {
        if (/would\s+require\s+three\s+\'=\'\s+chars/) {
            close F;
            return 1;
        }
    }
    close F;
    return &print_errors("[-] Could not find base64 three '=' chars error");
}

sub SPA_sniff_decrypt_sha256() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $sha256_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_err = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/Digest\s+alg\s+mis\-match/) {
                $found_err = 1;
                last;
            }
        }
        close SE;
        if ($found_err) {
            return 1;
        } else {
            return &print_errors("[*] fwknopd accepted excluded digest algorithm type");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub sniff_decrypt() {
    my ($fwknop_conf, $access_conf) = @_;

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $fwknop_conf, $access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (not $ipt_chainmgr_version
                    and /IPTables::ChainMgr::VERSION\s+(\S+)/) {
                $ipt_chainmgr_version = $1;
                $ipt_chainmgr_version =~ s/^0\.//;
            }
            if (/\[\-\]\s+Key\s+mis\-?match/i) {
                ### [-] Key mis-match or broken message checksum for SOURCE \
                ### ANY (# 1 in access.conf)
                close SE;
                return &print_errors("[-] Key mis-match");
            } elsif (/\[\-\]\s+Decrypted.*not\s+conform/i) {
                ### [-] Decrypted message does not conform to a valid SPA packet
                close SE;
                return &print_errors("[-] Invalid SPA packet");
            }
        }
        close SE;
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub sniff_decrypt_rand_port() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $rand_port_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+Key\s+mis\-?match/i) {
                ### [-] Key mis-match or broken message checksum for SOURCE \
                ### ANY (# 1 in access.conf)
                close SE;
                return &print_errors("[-] Key mis-match");
            } elsif (/\[\-\]\s+Decrypted.*not\s+conform/i) {
                ### [-] Decrypted message does not conform to a valid SPA packet
                close SE;
                return &print_errors("[-] Invalid SPA packet");
            } elsif (/Unable\s+to\s+compile\s+packet\s+capture/) {
                close SE;
                return &print_errors("[-] Could not compile pcap filter, " .
                    "upgrade libpcap?");
            }
        }
        close SE;
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub no_promisc_sniff_decrypt() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $no_promisc_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_no_promisc = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+Key\s+mis\-?match/i) {
                ### [-] Key mis-match or broken message checksum for SOURCE \
                ### ANY (# 1 in access.conf)
                close SE;
                return &print_errors("[-] Key mis-match");
            } elsif (/\[\-\]\s+Decrypted.*not\s+conform/i) {
                ### [-] Decrypted message does not conform to a valid SPA packet
                close SE;
                return &print_errors("[-] Invalid SPA packet");
            }
            if (/Sniffing\s+\(non\-promisc\)/) {
                $found_no_promisc = 1;
                last;
            }
        }
        close SE;

        if ($found_no_promisc) {
            return 1;
        } else {
            return &print_errors("[-] Could not sniff in non-promisc mode");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub sniff_decrypt_multi_source() {
    return &sniff_decrypt($default_fwknop_conf, $multi_source_access_conf);
}

sub sniff_decrypt_multi_port() {
    return &sniff_decrypt($default_fwknop_conf, $multi_port_access_conf);
}

sub spa_output_access_format() {

    open T, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print T "[+] Verifying SPA packet data from: $previous_test_file\n";

    ### Random data:   1946117908964953
    ### Username:      root
    ### Remote time:   1197922462
    ### Remote ver:    1.9.0
    ### Action type:   1 (SPA_ACCESS_MODE)
    ### Action:        127.0.0.2,none,0
    ### SHA256 digest: nJODs6VU9Q5WxklPmapV4S7cZFAp+rFmMANLFrCuS6w
    my $valid_lines = 0;
    open F, "< $previous_test_file" or die "[*] Could not open ",
        "$previous_test_file: $!";
    while (<F>) {
        if (/^\s+Random\s+data:\s+\d+/i) {
            $valid_lines++;
        } elsif (/^\s+Username:\s+\w+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+time:\s+\d+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+ver:\s+(\S+)$/i) {
            $valid_lines++;
        } elsif (/^\s+Action\s+type:\s+$SPA_ACCESS_MODE\s+/i) {
            $valid_lines++;
        } elsif (/^\s+Action:\s+$ip_re/i) {
            $valid_lines++;
        } elsif (/^\s+\S+\s+digest:\s+\S+$/i) {
            $valid_lines++;
        }
    }
    close F;
    unless ($valid_lines == 7) {
        print T "[*] Dubious sniffed packet format.\n";
        close T;
        return &print_errors("[-] Dubious sniffed packet format");
    }
    print T "    Success.\n";
    close T;
    return 1;
}

sub spa_client_timeout_access_format() {

    open T, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print T "[+] Verifying SPA packet data from: $previous_test_file\n";

    ### Random data:    1946117908964953
    ### Username:       root
    ### Remote time:    1197922462
    ### Remote ver:     1.9.0
    ### Action type:    1 (SPA_ACCESS_MODE)
    ### Action:         127.0.0.2,none,0
    ### Client timeout: 5
    ### SHA256 digest:  nJODs6VU9Q5WxklPmapV4S7cZFAp+rFmMANLFrCuS6w
    my $valid_lines = 0;
    open F, "< $previous_test_file" or die "[*] Could not open ",
        "$previous_test_file: $!";
    while (<F>) {
        if (/^\s+Random\s+data:\s+\d+/i) {
            $valid_lines++;
        } elsif (/^\s+Username:\s+\w+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+time:\s+\d+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+ver:\s+(\S+)$/i) {
            $valid_lines++;
        } elsif (/^\s+Action\s+type:\s+$SPA_CLIENT_TIMEOUT_ACCESS_MODE\s+/i) {
            $valid_lines++;
        } elsif (/^\s+Action:\s+$ip_re/i) {
            $valid_lines++;
        } elsif (/^\s+Client\s+timeout:\s+\d+/i) {
            $valid_lines++;
        } elsif (/^\s+\S+\s+digest:\s+\S+$/i) {
            $valid_lines++;
        }
    }
    close F;
    unless ($valid_lines == 8) {
        print T "[*] Dubious sniffed packet format.\n";
        close T;
        return &print_errors("[-] Dubious sniffed packet format");
    }
    print T "    Success.\n";
    close T;
    return 1;
}

sub spa_local_access_format_client_timeout() {

    open T, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print T "[+] Verifying SPA packet data from: $previous_test_file\n";

    ### Random data:     6647838939252388
    ### Username:        root
    ### Remote time:     1231088030
    ### Remote ver:      1.9.10-pre2
    ### Action type:     6 (SPA_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MODE)
    ### Action:          127.0.0.2,tcp/22
    ### Client timeout:  5
    ### NAT info:        127.0.0.1,55000
    ### SHA256 digest:   kStqQ36R3K+Weau0vDLkh3Pnshu2mlwJBdRzOF2Xeao

    my $valid_lines = 0;
    open F, "< $previous_test_file" or die "[*] Could not open ",
        "$previous_test_file: $!";
    while (<F>) {
        if (/^\s+Random\s+data:\s+\d+/i) {
            $valid_lines++;
        } elsif (/^\s+Username:\s+\w+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+time:\s+\d+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+ver:\s+(\S+)$/i) {
            $valid_lines++;
        } elsif (/^\s+Action\s+type:\s+$SPA_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MODE\s+/i) {
            $valid_lines++;
        } elsif (/^\s+Action:\s+$ip_re,/i) {
            $valid_lines++;
        } elsif (/^\s+NAT\s+info:\s+$ip_re,/i) {
            $valid_lines++;
        } elsif (/^\s+\S+\s+digest:\s+\S+$/i) {
            $valid_lines++;
        }
    }
    close F;
    unless ($valid_lines == 8) {
        print T "[*] Dubious sniffed packet format.\n";
        close T;
        return &print_errors("[-] Dubious sniffed packet format");
    }
    print T "    Success.\n";
    close T;
    return 1;
}

sub spa_local_access_format() {

    open T, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print T "[+] Verifying SPA packet data from: $previous_test_file\n";

    ### Random data:   1946117908964953
    ### Username:      root
    ### Remote time:   1197922462
    ### Remote ver:    1.9.4
    ### Action type:   5 (SPA_LOCAL_ACCESS_MODE)
    ### Access:        127.0.0.2,tcp/22
    ### NAT access:    127.0.0.1,12345
    ### SHA256 digest: nJODs6VU9Q5WxklPmapV4S7cZFAp+rFmMANLFrCuS6w

    my $valid_lines = 0;
    open F, "< $previous_test_file" or die "[*] Could not open ",
        "$previous_test_file: $!";
    while (<F>) {
        if (/^\s+Random\s+data:\s+\d+/i) {
            $valid_lines++;
        } elsif (/^\s+Username:\s+\w+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+time:\s+\d+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+ver:\s+(\S+)$/i) {
            $valid_lines++;
        } elsif (/^\s+Action\s+type:\s+$SPA_LOCAL_NAT_ACCESS_MODE\s+/i) {
            $valid_lines++;
        } elsif (/^\s+Action:\s+$ip_re,/i) {
            $valid_lines++;
        } elsif (/^\s+NAT\s+info:\s+$ip_re,/i) {
            $valid_lines++;
        } elsif (/^\s+\S+\s+digest:\s+\S+$/i) {
            $valid_lines++;
        }
    }
    close F;
    unless ($valid_lines == 8) {
        print T "[*] Dubious sniffed packet format.\n";
        close T;
        return &print_errors("[-] Dubious sniffed packet format");
    }
    print T "    Success.\n";
    close T;
    return 1;
}

sub spa_access_format() {

    open T, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print T "[+] Verifying SPA packet data from: $previous_test_file\n";

    ### Random data:   1946117908964953
    ### Username:      root
    ### Remote time:   1197922462
    ### Remote ver:    1.9.0
    ### Action type:   1 (SPA_ACCESS_MODE)
    ### Action:        127.0.0.2,none,0
    ### SHA256 digest: nJODs6VU9Q5WxklPmapV4S7cZFAp+rFmMANLFrCuS6w

    my $valid_lines = 0;
    open F, "< $previous_test_file" or die "[*] Could not open ",
        "$previous_test_file: $!";
    while (<F>) {
        if (/^\s+Random\s+data:\s+\d+/i) {
            $valid_lines++;
        } elsif (/^\s+Username:\s+\w+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+time:\s+\d+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+ver:\s+(\S+)$/i) {
            $valid_lines++;
        } elsif (/^\s+Action\s+type:\s+$SPA_ACCESS_MODE\s+/i) {
            $valid_lines++;
        } elsif (/^\s+Action:\s+$ip_re/i) {
            $valid_lines++;
        } elsif (/^\s+\S+\s+digest:\s+\S+$/i) {
            $valid_lines++;
        }
    }
    close F;
    unless ($valid_lines == 7) {
        print T "[*] Dubious sniffed packet format.\n";
        close T;
        return &print_errors("[-] Dubious sniffed packet format");
    }
    print T "    Success.\n";
    close T;
    return 1;
}

sub spa_command_format() {

    open T, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print T "[+] Verifying SPA packet data from: $previous_test_file\n";

    ### Random data:   6248973224583174
    ### Username:      root
    ### Remote time:   1197928728
    ### Remote ver:    1.9.0
    ### Action type:   0 (SPA_COMMAND_MODE)
    ### Action:        127.0.0.2,echo fwknoptest > /tmp/fwknop_test.txt
    ### SHA256 digest: nJODs6VU9Q5WxklPmapV4S7cZFAp+rFmMANLFrCuS6w
    my $valid_lines = 0;
    open F, "< $previous_test_file" or die "[*] Could not open ",
        "$previous_test_file: $!";
    while (<F>) {
        if (/^\s+Random\s+data:\s+\d+/i) {
            $valid_lines++;
        } elsif (/^\s+Username:\s+\w+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+time:\s+\d+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+ver:\s+(\S+)$/i) {
            $valid_lines++;
        } elsif (/^\s+Action\s+type:\s+$SPA_COMMAND_MODE\s+/i) {
            $valid_lines++;
        } elsif (/^\s+Action:\s+$ip_re/i) {
            $valid_lines++;
        } elsif (/^\s+\S+\s+digest:\s+\S+$/i) {
            $valid_lines++;
        }
    }
    close F;
    unless ($valid_lines == 7) {
        print T "[*] Dubious sniffed packet format.\n";
        close T;
        return &print_errors("[-] Dubious sniffed packet format");
    }
    print T "    Success.\n";
    close T;
    return 1;
}

sub spa_forward_access_format_client_timeout() {

    open T, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print T "[+] Verifying SPA packet data from: $previous_test_file\n";

    ### Random data:     3341202149904379
    ### Username:        root
    ### Remote time:     1231092253
    ### Remote ver:      1.9.10-pre2
    ### Action type:     4 (SPA_CLIENT_TIMEOUT_NAT_ACCESS_MODE)
    ### Action:          127.0.0.2,tcp/22
    ### Client timeout:  5
    ### NAT info:        192.168.10.3,55000
    ### SHA256 digest:   vEGCKTDyEykGZ/m/7I1Xq74LGwrXH46zd+8Bt7BasDs

    my $valid_lines = 0;
    open F, "< $previous_test_file" or die "[*] Could not open ",
        "$previous_test_file: $!";
    while (<F>) {
        if (/^\s+Random\s+data:\s+\d+/i) {
            $valid_lines++;
        } elsif (/^\s+Username:\s+\w+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+time:\s+\d+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+ver:\s+(\S+)$/i) {
            $valid_lines++;
        } elsif (/^\s+Action\s+type:\s+$SPA_CLIENT_TIMEOUT_NAT_ACCESS_MODE\s+/i) {
            $valid_lines++;
        } elsif (/^\s+Action:\s+$ip_re/i) {
            $valid_lines++;
        } elsif (/^\s+NAT\s+info:\s+$ip_re,\d+$/i) {
            $valid_lines++;
        } elsif (/^\s+\S+\s+digest:\s+\S+$/i) {
            $valid_lines++;
        }
    }
    close F;
    unless ($valid_lines == 8) {
        print T "[*] Dubious sniffed packet format.\n";
        close T;
        return &print_errors("[-] Dubious sniffed packet format");
    }
    print T "    Success.\n";
    close T;
    return 1;
}

sub spa_forward_access_format() {

    open T, ">> $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    print T "[+] Verifying SPA packet data from: $previous_test_file\n";

    ### Random data:   1005424690238209
    ### Username:      root
    ### Remote time:   1197927488
    ### Remote ver:    1.9.0
    ### Action type:   2 (SPA_FORWARD_ACCESS_MODE)
    ### Action:        127.0.0.2,none,0
    ### NAT info:      192.168.10.3,55000
    ### SHA256 digest: nJODs6VU9Q5WxklPmapV4S7cZFAp+rFmMANLFrCuS6w
    my $valid_lines = 0;
    open F, "< $previous_test_file" or die "[*] Could not open ",
        "$previous_test_file: $!";
    while (<F>) {
        if (/^\s+Random\s+data:\s+\d+/i) {
            $valid_lines++;
        } elsif (/^\s+Username:\s+\w+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+time:\s+\d+$/i) {
            $valid_lines++;
        } elsif (/^\s+Remote\s+ver:\s+(\S+)$/i) {
            $valid_lines++;
        } elsif (/^\s+Action\s+type:\s+$SPA_FORWARD_ACCESS_MODE\s+/i) {
            $valid_lines++;
        } elsif (/^\s+Action:\s+$ip_re/i) {
            $valid_lines++;
        } elsif (/^\s+NAT\s+info:\s+$ip_re,\d+$/i) {
            $valid_lines++;
        } elsif (/^\s+\S+\s+digest:\s+\S+$/i) {
            $valid_lines++;
        }
    }
    close F;
    unless ($valid_lines == 8) {
        print T "[*] Dubious sniffed packet format.\n";
        close T;
        return &print_errors("[-] Dubious sniffed packet format");
    }
    print T "    Success.\n";
    close T;
    return 1;
}

sub cache_ip_forward_val() {
    my $val = 0;
    return $val unless -e $ip_forward_file;
    open F, "< $ip_forward_file" or die $!;
    while (<F>) {
        if (/(\d)/) {
            $val = $1;
            last;
        }
    }
    close F;
    return $val;
}

sub restore_ip_forward_val() {
    my $val = shift;
    return unless -e $ip_forward_file;
    open F, "> $ip_forward_file" or die $!;
    print F $val, "\n";
    close F;
    return;
}

sub forward_request_client_timeout() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $client_timeout_access_conf)) {

        ### now that fwknopd has exited, make sure the FORWARD access request
        ### packet was detected and did not allow access
        my $forward_access_detected = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### [-] FORWARD access requested through non-forward access
            ### SOURCE block (SOURCE line num: 152)
            if (/\[\-\]\s+FORWARD\s+access\s+requested\s+through\s+non-forward/i) {
                $forward_access_detected = 1;
                last;
            }
        }
        close SE;
        unless ($forward_access_detected) {
            return &print_errors("[-] FORWARD access " .
                "request packet should have been detected and not allowed");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub forward_request() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, make sure the FORWARD access request
        ### packet was detected and did not allow access
        my $forward_access_detected = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### [-] FORWARD access requested through non-forward access
            ### SOURCE block (SOURCE line num: 152)
            if (/\[\-\]\s+FORWARD\s+access\s+requested\s+through\s+non-forward/i) {
                $forward_access_detected = 1;
                last;
            }
        }
        close SE;
        unless ($forward_access_detected) {
            return &print_errors("[-] FORWARD access " .
                "request packet should have been detected and not allowed");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub output_access() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $output_fwknop_conf, $output_access_conf)) {

        ### now that fwknopd has exited, make sure the FORWARD access request
        ### packet was detected and did not allow access
        my $output_access = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### [+] add FWKNOP_OUTPUT 127.0.0.2 -> 0.0.0.0/0(tcp/22) ACCEPT rule 10 sec
            if (/\[\+\]\s+add\s+FWKNOP_OUTPUT\s+/i) {
                $output_access = 1;
                last;
            }
        }
        close SE;
        unless ($output_access) {
            return &print_errors("[-] OUTPUT access not granted");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub forward_access() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $forward_fwknop_conf, $forward_access_conf)) {

        ### now that fwknopd has exited, make sure the FORWARD access request
        ### packet was detected and did not allow access
        my $forward_access_stage1 = 0;
        my $forward_access_stage2 = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### [+] add FWKNOP_FORWARD 127.0.0.2 -> 0.0.0.0/0(tcp/22) ACCEPT rule 10 sec
            ### [+] add FWKNOP_PREROUTING 127.0.0.2 -> 192.168.10.3(tcp/22) DNAT rule 10 sec
            if (/\[\+\]\s+add\s+FWKNOP_FORWARD\s+/i) {
                $forward_access_stage1 = 1;
                next;
            }
            if (/\[\+\]\s+add\s+FWKNOP_PREROUTING\s+.*DNAT/i) {
                $forward_access_stage2 = 1;
                next;
            }
        }
        close SE;
        unless ($forward_access_stage1 and $forward_access_stage2) {
            return &print_errors("[-] FORWARD and DNAT " .
                "access not granted");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub forward_local_access_restricted() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $no_local_nat_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, make sure the local access request
        ### packet was detected and did not allow access
        my $local_nat_not_granted = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\].*without\s+ENABLE_IPT_LOCAL_NAT\s+enabled/) {
                $local_nat_not_granted = 1;
                next;
            }
        }
        close SE;
        unless ($local_nat_not_granted) {
            return &print_errors("[-] Local access granted " .
                "without ENABLE_IPT_LOCAL_NAT enabled");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub SPA_local_access_client_timeout() {
    return &local_access($default_fwknop_conf, $client_timeout_access_conf);
}

sub SPA_local_access() {
    return &local_access($default_fwknop_conf, $default_access_conf);
}

sub SPA_local_access_rand_port() {
    return &local_access($rand_port_fwknop_conf, $default_access_conf);
}

sub local_access() {
    my ($fwknop_conf, $access_conf) = @_;

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $fwknop_conf, $access_conf)) {

        ### now that fwknopd has exited, make sure the local access request
        ### packet was detected and did not allow access
        my $local_nat_access_stage1 = 0;
        my $local_nat_access_stage2 = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### [+] add FWKNOP_INPUT 127.0.0.2 -> 0.0.0.0/0(tcp/22) ACCEPT rule 10 sec
            ### [+] add FWKNOP_PREROUTING 127.0.0.2 -> 192.168.10.3(tcp/22) DNAT rule 10 sec
            if (/\[\+\]\s+add\s+FWKNOP_INPUT\s+/i) {
                $local_nat_access_stage1 = 1;
                next;
            }
            if (/\[\+\]\s+add\s+FWKNOP_PREROUTING\s+.*DNAT/i) {
                $local_nat_access_stage2 = 1;
                next;
            }
        }
        close SE;
        unless ($local_nat_access_stage1 and $local_nat_access_stage2) {
            return &print_errors("[-] Local access and DNAT " .
                "access not granted");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub fwknopd_command() {

    unlink $test_cmd_file if -e $test_cmd_file;

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_command = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### executing command "echo test > /tmp/fwknop_test.txt" for 127.0.0.1
            if (/\[\+\]\s+executing\s+command.*$test_cmd_file/i) {
                $found_command = 1;
                last;
            }
        }
        close SE;
        unless ($found_command and -e $test_cmd_file) {
            return &print_errors("[-] Command not executed by fwknopd");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub fwknopd_no_re_command() {

    unlink $test_cmd_file if -e $test_cmd_file;

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, make sure the command was not
        ### executed
        my $command_filtered = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### [-] received command "127.0.0.2,touch /tmp/fwknop_test.txt"
            ### from 127.0.0.1 but CMD_REGEX did not match 127.0.0.1
            if (/\[\-\]\s+.*but\s+CMD_REGEX\s+did\s+not\s+match/i) {
                $command_filtered = 1;
                last;
            }
        }
        close SE;
        unless ($command_filtered and not -e $test_cmd_file) {
            return &print_errors("[-] Command " .
                "executed by fwknopd but should have been filtered");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub spa_open_command() {

    if (-e 'output/spa.open') {
        return 1;
    }
    return &print_errors("[-] output/spa.open does not exist.");
}

sub spa_open_no_ports_command() {

    if (-e 'output/spa_noports.open') {
        return 1;
    }
    return &print_errors("[-] output/spa_noports.open does not exist.");
}

sub spa_open_no_dash_A_command() {

    if (-e 'output/spa_nodashA.open') {
        return 1;
    }
    return &print_errors("[-] output/spa_nodashA.open does not exist.");
}

sub spa_close_command() {

    if (-e 'output/spa.close') {
        return 1;
    }
    return &print_errors("[-] output/spa.close does not exist.");
}

sub spa_close_no_open_ports_command() {

    if (-e 'output/spa_noports.close') {
        return 1;
    }
    return &print_errors("[-] output/spa_noports.close does not exist.");
}

sub spa_close_no_dash_A_command() {

    if (-e 'output/spa_nodashA.close') {
        return 1;
    }
    return &print_errors("[-] output/spa_nodashA.close does not exist.");
}

sub fwknopd_ext_command() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $ext_command_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_command = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### executing external open command "echo "127.0.0.2 open" > output/spa.open" for 127.0.0.2
            if (/\[\+\]\s+executing\s+external\s+open\s+command.*spa\.open/i) {
                $found_command = 1;
                last;
            }
        }
        close SE;
        unless ($found_command) {
            return &print_errors("[-] Command not executed by fwknopd");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub fwknopd_ext_no_open_ports_command() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $ext_command_no_open_ports_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_command = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### executing external open command "echo "127.0.0.2 open" > output/spa.open" for 127.0.0.2
            if (/\[\+\]\s+executing\s+external\s+open\s+command.*noports\.open/i) {
                $found_command = 1;
                last;
            }
        }
        close SE;
        unless ($found_command) {
            return &print_errors("[-] Command not executed by fwknopd");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub fwknopd_ext_no_dash_A_command() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $ext_command_no_dash_A_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_command = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            ### executing external open command "echo "127.0.0.2 open" > output/spa.open" for 127.0.0.2
            if (/\[\+\]\s+executing\s+external\s+open\s+command.*nodashA\.open/i) {
                $found_command = 1;
                last;
            }
        }
        close SE;
        unless ($found_command) {
            return &print_errors("[-] Command not executed by fwknopd");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub del_ipt_chains() {
    my $cmd = "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
        "--fw-flush --fw-del-chains --debug --verbose";
    unless (&run_cmd($cmd, $NO_APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }
    $cmd = "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf --fw-list " .
        "--debug --verbose";
    unless (&run_cmd($cmd, $APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }
    my $chain_exists = 0;
    my $found_listing_cmd = 0;
    open F, "< $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    while (<F>) {
        if (/\-\-fw\-list\s+\-\-debug/) {
            $found_listing_cmd = 1;
            next;
        }
        next unless $found_listing_cmd;
        if (/FWKNOP_/) {
            $chain_exists = 1;
            last;
        }
    }
    close F;
    if ($chain_exists) {
        return &print_errors("[-] Not all fwknop chains were removed");
    }
    return 1;
}

sub send_packet() {
    my ($msg, $spa_packet, $socket_type) = @_;

    $spa_port = 62201 unless $spa_port > 0;

    if ($socket_type == $SEND_UDP) {

        my $socket = IO::Socket::INET->new(
            PeerAddr => $localhost,
            PeerPort => $spa_port,
            Proto    => 'udp',
            Timeout  => 1
        ) or die "[*] Could not acquire udp/$spa_port socket to $localhost: $!";

        $socket->send($spa_packet);
        undef $socket;

    } elsif ($socket_type == $SEND_TCP) {

        my $socket = IO::Socket::INET->new(
            PeerAddr => $localhost,
            PeerPort => $spa_port,
            Proto    => 'tcp',
            Timeout  => 1
        ) or die "[*] Could not acquire TCP/$spa_port socket ",
                "with $localhost: $!";

        $socket->send($spa_packet);
        undef $socket;

    } elsif ($socket_type == $SEND_HTTP) {
        die "[*] SPA HTTP request not read properly from fwknop client"
            unless $spa_http_request;
        my $socket = IO::Socket::INET->new(
            PeerAddr => $localhost,
            PeerPort => $spa_port,  ### fwknop_serv will listen here
            Proto    => 'tcp',
            Timeout  => 1
        ) or die "[*] Could not acquire TCP/$spa_port socket ",
                "with $localhost: $!";
        if (defined($socket)) {
            print $socket $spa_http_request;
            recv($socket, my $web_data, 1500, 0);
            close $socket;
        }

    } elsif ($socket_type == $SEND_ICMP) {

        require Net::RawIP;
        my $rawpkt = new Net::RawIP({
            ip => {
                saddr => $localhost,
                daddr => $localhost
            },
            icmp =>{}});
        $rawpkt->set({ ip => {
                saddr => $localhost,
                daddr => $localhost
            },
            icmp => {
                type => 8,
                code => 0,
                sequence => 0,
                data => $spa_packet
            }
        });
        $rawpkt->send();
    }

    sleep 1;
    return;
}

sub start_fwknopd() {
    my ($conf_file, $access_file) = @_;

    my $pid = fork();
    die "[*] Could not fork: $!" unless defined $pid;

    if ($pid == 0) {

        ### we are the child, so start fwknopd
        exit &run_cmd("$fwknopdCmd $gpg_mode_str --debug --verbose --Count 1 " .
            "-i $loopback_intf -c $conf_file -a $access_file --fw-type " .
            "$config{'FIREWALL_TYPE'} $server_test_mode_opt --knoptmCmd " .
            "$knoptmCmd --fwknop_servCmd $fwknop_servCmd " .
            "--knoptm-debug-pidname --fwkserv-debug-pidname ",
            $NO_APPEND);
    }
    return $pid;
}

sub pk_start_fwknopd() {
    my ($conf_file, $access_file) = @_;

    my $pid = fork();
    die "[*] Could not fork: $!" unless defined $pid;

    if ($pid == 0) {

        ### we are the child, so start fwknopd
        exit &run_cmd("$fwknopdCmd $gpg_mode_str --debug --verbose --Count 1 " .
            "-c $conf_file -a $access_file --fw-type " .
            "$config{'FIREWALL_TYPE'} $server_test_mode_opt --knoptmCmd " .
            "$knoptmCmd --knoptm-debug-pidname ",
            $NO_APPEND);
    }
    return $pid;
}

sub get_sniff_file() {
    my $msg = shift;  ### for --test-include and --test-exclude matches

    ### inclusions/exclusions
    if ($test_include) {
        my $found = 0;
        for my $test (@tests_to_include) {
            if ($msg =~ /\(.*$test.*\)/) {
                $found = 1;
                last;
            }
        }
        return unless $found;
    }
    if ($test_exclude) {
        my $found = 0;
        for my $test (@tests_to_exclude) {
            if ($msg =~ /\(.*$test.*\)/) {
                $found = 1;
                last;
            }
        }
        return if $found;
    }

    open F, "< $pcap_file_fwknop_conf" or die "[*] Could not open ",
        "$pcap_file_fwknop_conf: $!";
    while (<F>) {
        if (/^\s*PCAP_PKT_FILE\s+(\S+)\s*;/) {
            $sniff_file = $1;
        }
    }
    close F;
    die "[*] Could not get PCAP_PKT_FILE file." unless $sniff_file;
    if (-e $sniff_file) {
        unlink $sniff_file or die "[*] Could not unlink($sniff_file)";
    }
    return;
}

sub start_tcpdump() {
    my $msg = shift;  ### for --test-include and --test-exclude matches

    ### inclusions/exclusions
    if ($test_include) {
        my $found = 0;
        for my $test (@tests_to_include) {
            if ($msg =~ /\(.*$test.*\)/) {
                $found = 1;
                last;
            }
        }
        return unless $found;
    }
    if ($test_exclude) {
        my $found = 0;
        for my $test (@tests_to_exclude) {
            if ($msg =~ /\(.*$test.*\)/) {
                $found = 1;
                last;
            }
        }
        return if $found;
    }

    my $pid = fork();
    die "[*] Could not fork: $!" unless defined $pid;

    if ($pid == 0) {

        ### collect SPA packet data into a file with tcpdump where
        ### fwknopd can then acquire it.
        exit &run_cmd("$tcpdumpCmd -i $loopback_intf -c 2 -U -nn " .
            "-s 0 -w $sniff_file udp port 62201", $NO_APPEND);

    }
    sleep 1;
    return $pid;
}

sub SPA_gpg_access_packet() {
    return &get_access_packet("$default_fwknop_args " .
        "--gpg-home conf/client-gpg --gpg-recip $gpg_server_key " .
        "--gpg-sign $gpg_client_key", $default_fwknop_conf, $NO_QUIET);
}

sub SPA_gpg_access_packet_with_prefix() {
    return &get_access_packet("$default_fwknop_args " .
        "--gpg-home conf/client-gpg --gpg-recip $gpg_server_key " .
        "--gpg-sign $gpg_client_key --Include-gpg-prefix",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_gpg2_access_packet() {
    return &get_access_packet("$default_fwknop_args " .
        "--gpg-home conf/client-gpg --gpg-recip $gpg_server_key " .
        "--gpg-sign $gpg_client_key --gpg-path $gpg2Cmd",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_gpg2_access_packet_http() {
    return &get_access_packet("$default_fwknop_args " .
        "--gpg-home conf/client-gpg --gpg-recip $gpg_server_key " .
        "--gpg-sign $gpg_client_key --gpg-path $gpg2Cmd $http_opt",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_client_timeout_access_packet() {
    return &get_access_packet("$default_fwknop_args --fw-timeout 5",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_62203() {
    return &get_access_packet("$default_fwknop_args $server_port_opt 62203",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_plus60min() {
    return &get_access_packet("$default_fwknop_args --time-offset-plus 60min",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_minus60min() {
    return &get_access_packet("$default_fwknop_args --time-offset-minus 60min",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_icmp() {
    return &get_access_packet("$default_fwknop_args $spoof_proto_opt icmp",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_http() {
    return &get_access_packet("$default_fwknop_args $http_opt",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_http_localhost() {
    $default_fwknop_args =~ s/-D\s$localhost/-D localhost/;
    my $rv = &get_access_packet("$default_fwknop_args $http_opt",
        $default_fwknop_conf, $NO_QUIET);
    $default_fwknop_args =~ s/-D\slocalhost/-D $localhost/;
    return $rv;
}

sub SPA_access_packet_http_include_host() {
    my $rv = &get_access_packet("$default_fwknop_args " .
        "$http_opt $http_proxy_opt http://$http_proxy_host",
        $default_fwknop_conf, $NO_QUIET);
    return $rv;
}

sub SPA_gpg_access_packet_http() {
    return &get_access_packet("$default_fwknop_args " .
        "--gpg-home conf/client-gpg --gpg-recip $gpg_server_key " .
        "--gpg-sign $gpg_client_key $http_opt", $default_fwknop_conf,
        $NO_QUIET);
}

sub SPA_access_packet_established_tcp() {
    if ($client_language eq 'C') {
        return &get_access_packet("$default_fwknop_args --server-proto tcp",
            $default_fwknop_conf, $NO_QUIET);
    } else {
        return &get_access_packet("$default_fwknop_args --TCP-sock",
            $default_fwknop_conf, $NO_QUIET);
    }
}

sub SPA_access_packet() {
    return &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_multi_port() {
    return &get_access_packet("$fwknopCmd -A tcp/22,udp/1194 --no-save " .
        "--get-key $local_key_file -D $localhost -a $allow_src " .
        "$test_mode_opt -v $spoof_user_opt $require_user",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_salted() {
    return &get_access_packet("$default_fwknop_args --Include-salted",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_rand_dest_port() {
    return &get_access_packet("$default_fwknop_args --rand-port",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_no_dash_A() {
    return &get_access_packet($fwknop_args_no_dash_A,
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_access_packet_md5() {
    return &get_access_packet("$default_fwknop_args $digest_opt md5",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_command_packet() {
    return &get_access_packet("$fwknopCmd --no-save --get-key " .
        "$local_key_file -D $localhost -a $allow_src $test_mode_opt -v " .
        qq|$spoof_user_opt $require_user $server_cmd_opt "$test_cmd"|,
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_forward_access_packet_client_timeout() {
    return &get_access_packet("$default_fwknop_args " .
        "$nat_access_opt 192.168.10.3:55000 --fw-timeout 5",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_forward_access_packet() {
    return &get_access_packet("$default_fwknop_args " .
        "$nat_access_opt 192.168.10.3:55000",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_forward_access_packet_restricted_IP() {
    return &get_access_packet("$default_fwknop_args " .
        "$nat_access_opt 192.168.10.5:55000",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_output_access_packet() {
    return &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_local_nat_access_packet() {
    return &get_access_packet("$default_fwknop_args " .
        "$nat_local_opt $nat_access_opt $localhost:55000",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_local_nat_access_packet_rand_port() {
    return &get_access_packet("$default_fwknop_args " .
        "$nat_local_opt $nat_access_opt $localhost $nat_rand_opt ",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_local_nat_access_packet_rand_dst_port() {
    return &get_access_packet("$default_fwknop_args " .
        "$nat_local_opt $nat_access_opt $localhost $nat_rand_opt " .
        "--rand-port", $default_fwknop_conf, $NO_QUIET);
}

sub SPA_local_nat_access_packet_client_timeout() {
    return &get_access_packet("$default_fwknop_args " .
        "$nat_local_opt $nat_access_opt $localhost:55000 --fw-timeout 5",
        $default_fwknop_conf, $NO_QUIET);
}

sub SPA_non_matching_re_command_packet() {
    return &get_access_packet("$fwknopCmd --no-save --get-key " .
        "$local_key_file -D $localhost -a $allow_src $test_mode_opt -v " .
        qq|$spoof_user_opt $require_user $server_cmd_opt "$test_cmd"|,
        $default_fwknop_conf, $NO_QUIET);
}

sub short_key() {
    my $key_copy = $cache_key;
    $cache_key = 'short';
    my $rv = &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $QUIET);
    $cache_key = $key_copy;
    if ($client_language eq 'perl') {
        ### we want the perl version to fail since it will not accept a
        ### short Rijndael key, but the fwknop-c code allows this
        $rv = 1 if $rv == 0;
    }
    return $rv;
}

sub unauthorized_port_request() {
    $default_fwknop_args =~ s|\s$open_ports\s| tcp/1 |;
    my $rv = &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $NO_QUIET);
    $default_fwknop_args =~ s|\stcp/1\s| $open_ports |;
    return $rv;
}

sub sniff_unauthorized_port_request() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_non_permit = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/IP.*not\s+permitted\s+to\s+open\s/) {
                $found_non_permit = 1;
                last;
            }
        }
        close SE;
        unless ($found_non_permit) {
            return &print_errors("[-] fwknopd " .
                "accepted SPA packet with unauthorized port request");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub unauthorized_user() {
    $default_fwknop_args =~ s/\s$require_user/ mbr$require_user/;
    my $rv = &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $NO_QUIET);
    $default_fwknop_args =~ s/\smbr$require_user/ $require_user/;
    return $rv;
}

sub sniff_unauthorized_user() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_user_err = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+username\s+mismatch/) {
                ### [-] username mismatch from 127.0.0.1, expecting root, got mbr
                $found_user_err = 1;
                last;
            }
        }
        close SE;
        unless ($found_user_err) {
            return &print_errors("[-] fwknopd " .
                "accepted SPA packet with unauthorized user");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub truncated_SPA_packet() {
    my $rv = &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $NO_QUIET);
    ### chop off the last 11 chars
    $cache_encrypted_spa_packet =~ s|.{11}$||;
    return $rv;
}

sub non_base64_SPA_packet() {
    my $rv = &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $NO_QUIET);
    ### introduce one non-base64 encoded character "@" at the 11th position
    $cache_encrypted_spa_packet =~ s|(.{10}).|$1@|;
    return $rv;
}

sub append_SPA_packet() {
    my $rv = &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $NO_QUIET);
    ### append 12 garbage base64 chars
    $cache_encrypted_spa_packet .= '1234567890AA';
    return $rv;
}

sub append_invalid_multiple_SPA_packet() {
    my $rv = &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $NO_QUIET);
    ### append to multiple of 4 - 3.  +10 because of Salted__ prefix.
    my $remainder = (length($cache_encrypted_spa_packet) + 10) % 4;
    my $multiple = 0;
    if ($remainder == 0) {
        $multiple = 1;
    } elsif ($remainder == 2) {
        $multiple = 3;
    } elsif ($remainder == 3) {
        $multiple = 2;
    }
    $cache_encrypted_spa_packet .= 'A'x$multiple;
    return $rv;
}

sub truncated_SPA_sniff_decrypt() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_err = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/Premature\s+padding/i) {
                $found_err = 1;
                last;
            } elsif (/Premature\s+end/i) {
                $found_err = 1;
                last;
            } elsif (/broken\s+message\s+checksum\s+for\s+SOURCE/i) {
                $found_err = 1;
                last;
            } elsif (/would\s+require\s+three\s+\'=\'\s+chars/) {
                $found_err = 1;
                last;
            } elsif (/FKO\s+error\s+decrypting\s+data/) {
                $found_err = 1;
                last;
            }
        }
        close SE;
        if ($found_err) {
            return 1;
        } else {
            return &print_errors("[*] fwknopd accepted truncated SPA packet");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub non_base64_SPA_sniff_decrypt() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_err = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/Packet\s+contains\s+non-base64\s+encoded\s+characters/) {
                $found_err = 1;
                last;
            }
        }
        close SE;
        if ($found_err) {
            return 1;
        } else {
            return &print_errors("[*] fwknopd accepted non-base64 encoded SPA packet");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub client_timeout_sniff_decrypt() {
    return &sniff_decrypt($default_fwknop_conf, $client_timeout_access_conf);
}

sub append_SPA_sniff_decrypt() {
    return &sniff_decrypt($default_fwknop_conf, $default_access_conf);
}

sub bogus_SPA_sniff_decrypt() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_err = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+Key\s+mis\-?match/i) {
                ### [-] Key mis-match or broken message checksum for SOURCE \
                ### ANY (# 1 in access.conf)
                $found_err = 1;
                last;
            } elsif (/\[\-\]\s+Decrypted.*not\s+conform/i) {
                ### [-] Decrypted message does not conform to a valid SPA packet
                $found_err = 1;
                last;
            } elsif (/FKO\s+error\s+decrypting\s+data/) {
                $found_err = 1;
                last;
            }
        }
        close SE;
        if ($found_err) {
            return 1;
        } else {
            return &print_errors("[-] " .
                    "fwknopd accepted SPA packet with bogus key");
        }
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub source_addr() {
    $default_fwknop_args =~ s/\-a\s+$allow_src\s/-a 0.0.0.0 /;
    my $rv = &get_access_packet($default_fwknop_args,
        $default_fwknop_conf, $NO_QUIET);
    $default_fwknop_args =~ s/\-a\s+0(?:\.0){3}\s/-a $allow_src /;
    return $rv;
}

sub sniff_source_addr() {

    if (&run_fwknopd($cache_encrypted_spa_packet,
            $default_fwknop_conf, $default_access_conf)) {

        ### now that fwknopd has exited, see if the SPA packet was valid
        my $found_src_err = 0;
        open SE, "< $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        while (<SE>) {
            if (/\[\-\]\s+IP.*sent\s+SPA\s+packet.*but\s+
                    REQUIRE_SOURCE_ADDRESS\s+is\s+enabled/ix) {
                ### [-] IP: 127.0.0.1 sent SPA packet that contained 0.0.0.0 (-s
                ### on the client side) but REQUIRE_SOURCE_ADDRESS is enabled
                ### (SOURCE line num: 15)
                $found_src_err = 1;
                last;
            }
        }
        close SE;
        unless ($found_src_err) {
            return &print_errors("[-] fwknopd " .
                "accepted SPA packet with 0.0.0.0 source address");
        }
        return 1;
    }
    return &print_errors("[-] Sniff alarm ($sniff_alarm seconds) expired");
}

sub packet_randomness() {

    my %packet_cache = ();

    for (my $i=0; $i < $NUM_RAND; $i++) {

        &get_access_packet($default_fwknop_args,
            $default_fwknop_conf, $NO_QUIET);

        if (defined $packet_cache{$cache_encrypted_spa_packet}) {
            return &print_errors("[-] Packet $i is " .
                "identical to a previously generated SPA packet; " .
                "rand() not working?");
        } else {
            $packet_cache{$cache_encrypted_spa_packet} = '';
        }
    }
    return 1;
}

sub pk_write_iptables_msgs() {
    my ($sequence, $port_offset) = @_;

    ### TCP
    #
    ### Jun 20 11:24:56 iptfw kernel: [ 7356.475568] IN=lo OUT=
    ### MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=127.0.0.1
    ### DST=127.0.0.1 LEN=60 TOS=0x10 PREC=0x00 TTL=64 ID=34848 DF
    ### PROTO=TCP SPT=52798 DPT=55000 WINDOW=32792 RES=0x00 SYN URGP=0

    my $tcp_ipt_pre_str = 'Jun 20 11:24:56 iptfw kernel: [ 7356.475568] IN=lo OUT= ' .
        "MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=$allow_src " .
        'DST=127.0.0.1 LEN=60 TOS=0x10 PREC=0x00 TTL=64 ID=34848 DF ';

    my $tcp_ipt_post_str = 'WINDOW=32792 RES=0x00 SYN URGP=0';

    ### UDP
    #
    ### Jun 27 08:49:45 iptfw kernel: [  102.843791] IN=lo OUT=
    ### MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=127.0.0.1
    ### DST=127.0.0.1 LEN=36 TOS=0x00 PREC=0x00 TTL=64 ID=26930 DF
    ### PROTO=UDP SPT=33792 DPT=5003 LEN=16

    my $udp_ipt_pre_str = 'Jun 27 08:49:45 iptfw kernel: [  102.843791] IN=lo OUT= ' .
        "MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=$allow_src " .
        'DST=127.0.0.1 LEN=36 TOS=0x00 PREC=0x00 TTL=64 ID=26930 DF ';

    my $udp_ipt_post_str = 'LEN=16';

    ### ICMP
    #
    ### Jun 27 08:53:27 iptfw kernel: [  115.131936] IN=lo OUT=
    ### MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=127.0.0.1
    ### DST=127.0.0.1 LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF
    ### PROTO=ICMP TYPE=8 CODE=0 ID=53784 SEQ=1

    my $icmp_ipt_str = 'Jun 27 08:53:27 iptfw kernel: [  115.131936] IN=lo OUT= ' .
        "MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=$allow_src " .
        'DST=127.0.0.1 LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF ' .
        'PROTO=ICMP TYPE=8 CODE=0 ID=53784 SEQ=1';

    open T, ">> $current_test_file" or die $!;
    print T "SEQUENCE: $sequence\n";
    close T;

    open FWDATA, ">> output/fwdata" or die $!;

    for my $port_str (split /\s*\,\s*/, $sequence) {

        if ($port_str =~ m|tcp/(\d+)|) {
            my $port = $port_offset + $1;
            print FWDATA $tcp_ipt_pre_str . "PROTO=TCP SPT=12345 DPT=$port " .
                $tcp_ipt_post_str, "\n";
        } elsif ($port_str =~ m|udp/(\d+)|) {
            my $port = $port_offset + $1;
            print FWDATA $udp_ipt_pre_str . "PROTO=UDP SPT=12345 DPT=$port " .
                $udp_ipt_post_str, "\n";
        } elsif ($port_str =~ m|icmp|) {
            print FWDATA $icmp_ipt_str, "\n";
        } else {
            die "[*] Invalid sequence: $sequence";
        }
    }
    close FWDATA;

    return;
}

sub parse_access_conf() {
    my $file = shift;
    ### parse the Rijndael key from the test_access.conf file (this same
    ### will be used by fwknopd to decrypt the SPA packet)
    open F, "< $file" or
        die "[*] Could not open $file: $!";
    while (<F>) {
        if (/^\s*KEY:\s*(.*)\s*;/) {
            $cache_key = $1;
        } elsif (/^\s*FW_ACCESS_TIMEOUT:\s*(\d+)\s*;/) {
            $fw_access_timeout = $1;
        } elsif (/^\s*REQUIRE_USERNAME:\s*(.*)\s*;/) {
            $require_user = $1;
        } elsif (/^\s*REQUIRE_SOURCE_ADDRESS:\s*Y\s*;/) {
            $require_source_addr = 1;
        } elsif (/^\s*PERMIT_CLIENT_PORTS:\s*Y\s*;/) {
            $permit_client_ports = 1;
        } elsif (/^\s*OPEN_PORTS:\s*(\S+)\s*;/) {
            $open_ports = $1;
        } elsif (/^\s*CMD_REGEX:\s*(.*)\s*;/) {
            $cmd_regex = qr|$1|;
        } elsif (/^\s*SHARED_SEQUENCE:\s*(.*)\s*;/) {
            $pk_shared_sequence = $1;
        }
    }
    close F;
    return;
}

sub bogus_key_SPA_packet() {

    ### --Test so that SPA packet is not sent
    ### -a so that REQUIRE_SOURCE_ADDRESS checks out
    open K, "> $local_key_file"
        or die "[*] Could not open $local_key_file: $!";
    print K "$localhost: someboguskey\n";
    close K;

    unless (&run_cmd("$fwknopCmd -A $open_ports --no-save --get-key " .
            "$local_key_file -D $localhost -a $allow_src $test_mode_opt -v " .
            "$spoof_user_opt $require_user", $NO_APPEND)) {
        return &print_errors("[-] Could not generate encrypted SPA packet");
    }

    &get_packet_data_from_fwknop_output($default_fwknop_conf);

    unless ($cache_encrypted_spa_packet) {
        return &print_errors("[-] Could not generate encrypted SPA packet");
    }
    return 1;
}

sub get_access_packet() {
    my ($fwknop_cmdline, $fwknop_conf, $output) = @_;

    &write_key();

    ### append default port if necessary
    $fwknop_cmdline .= " $server_port_opt 62201"
        unless $fwknop_cmdline =~ /$server_port_opt/;

    unless (&run_cmd($fwknop_cmdline, $NO_APPEND)) {
        if ($fwknop_cmdline =~ /fw\-timeout/) {
            if ($output == $QUIET) {
                return 0;
            } else {
                return &print_errors("[-] Could not " .
                        "generate client timeout encrypted SPA packet");
            }
        } else {
            if ($output == $QUIET) {
                return 0;
            } else {
                return &print_errors("[-] Could not " .
                        "generate encrypted SPA packet");
            }
        }
    }

    &get_packet_data_from_fwknop_output($fwknop_conf);

    unless ($cache_encrypted_spa_packet) {
        if ($output == $QUIET) {
            return 0;
        } else {
            return &print_errors("[-] Could not generate " .
                "encrypted SPA packet");
        }
    }

    if ($fwknop_cmdline =~ /Include\-salted/) {
        ### look for base64-encoded "Salted__" prefix
        unless ($cache_encrypted_spa_packet =~ /^\s*U2FsdGVkX1/) {
            if ($output == $QUIET) {
                return 0;
            } else {
                return &print_errors("[-] Could not generate " .
                    "SPA packet with Salted__ prefix");
            }
        }
    }
    return 1;
}

sub get_packet_data_from_fwknop_output() {
    my $fwknop_conf = shift;

    $spa_port = 0;
    $cache_encrypted_spa_packet = '';
    $spa_packet_digest = '';
    $spa_http_request  = '';

    my $found_packet_data = 0;

    open F, "< $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    while (<F>) {
        if ($client_language eq 'perl') {
            if (/^\s*\[\+\]\s+Packet\s+data:/) {
                $found_packet_data = 1;
                next;
            }
            if ($found_packet_data and /(\S+)/) {
                $cache_encrypted_spa_packet = $1;
                $found_packet_data = 0;
                next;
            }
            ### [+] Sending 182 byte message to 127.0.0.1 over udp/43625...
#            if (m|Sending\s+.*byte\s+.*over\s+\w+/(\d+)|) {
            if (m|Sending\s.*\s\w+/(\d+)|) {
                $spa_port = $1;
                last;
            }
        } else {
            if (/^\s*Final\s+Packed.*\sData:/) {
                $found_packet_data = 1;
                next;
            }
            if (m|^\s+port:\s+(\d+)|) {
                $spa_port = $1;
                last;
            }
            if ($found_packet_data and /(\S+)/) {
                $cache_encrypted_spa_packet = $1;
                $found_packet_data = 0;
                next;
            }
        }
    }
    close F;

    ### extract any HTTP request data from the fwknop client output
    open F, "< $current_test_file"
        or die "[*] Could not open $current_test_file: $!";
    while (<F>) {
        if (m|^(GET\s+)(\S+)(\s+HTTP\S+)|) {
            $spa_http_request .= "$1$2$3" . "\x0d\x0a";
            $cache_encrypted_spa_packet = $2;
        } elsif (/(User-Agent:\s+\S+)/) {
            $spa_http_request .= $1 . "\x0d\x0a";
        } elsif (/(Accept:\s+\S+)/) {
            $spa_http_request .= $1 . "\x0d\x0a";
        } elsif (/(Host:\s+\S+)/) {
            $spa_http_request .= $1 . "\x0d\x0a";
        } elsif (/(Connection:\s+\S+)/) {
            $spa_http_request .= $1 . "\x0d\x0a";
        }
    }
    close F;
    $spa_http_request .= "\x0d\x0a" if $spa_http_request;

    ### now that we have the packet data, feed this data to fwknopd
    ### to get the digest that it would calculate
    die "[*] Could not acquire encrypted SPA packet from the fwknop client."
        unless $cache_encrypted_spa_packet;

    &get_spa_digests_from_fwknopd($fwknop_conf);

    return;
}

sub digest_format() {
    return &print_errors("[-] Digest file " .
            "$output_dir/digest.cache does not exist")
            unless -e "$output_dir/digest.cache";
    open F, "$output_dir/digest.cache" or die "[*] Could not open " .
        "$output_dir/digest.cache";
    my $error = 0;
    while (<F>) {
        ### 127.0.0.1 xFTZnnstv1GPHD7bZDVJ2A [Sat Jan 12 20:55:24 2008]
        unless (/^\s*$ip_re\s+\S+\s+\[.*\]/) {
            $error = 1;
            last;
        }
    }
    close F;
    if ($error) {
        return &print_errors("[-] Digest file " .
                "$output_dir/digest.cache has invalid formatted line")
    }
    return 1;
}

sub perl_compilation() {
    for my $prog ($fwknopCmd, $fwknopdCmd, $knoptmCmd) {
        if ($prog eq $fwknopCmd) {
            next if $client_language eq 'C';
        }
        if ($prog eq $fwknopdCmd) {
            next if $server_language eq 'C';
        }
        unless (&run_cmd("perl -c $prog", $NO_APPEND)) {
            return &print_errors("[-] $prog does not compile");
        }
    }
    return 1;
}

sub C_compilation() {
    unless (&run_cmd('make -C ..', $NO_APPEND)) {
        return &print_errors("[-] fwknop " .
                "C programs would not compile");
    }
    return 1;
}

sub getopt_test() {
    for my $cmd ($fwknopCmd, $fwknopdCmd, $knoptmCmd) {
        if (&run_cmd("$cmd --no-such-argument", $APPEND)) {
            return &print_errors("[-] $cmd " .
                    "allowed --no-such-argument on the command line");
        }
    }
    return 1;
}

sub dump_config() {
    my $cmd = "$fwknopdCmd $gpg_mode_str --fw-type $config{'FIREWALL_TYPE'} " .
        "--Override-config /etc/fwknop/fwknop.conf " .
        "--Dump-config -c $default_fwknop_conf";
    if (&run_cmd($cmd, $NO_APPEND)) {
        my $found = 0;
        open F, "< $current_test_file" or die $!;
        ### just look for an expected variable
        while (<F>) {
            if (/SLEEP_INTERVAL/) {
                $found = 1;
                last;
            }
        }
        close F;
        if ($found) {
            return 1;
        } else {
            return &print_errors("[-] Could not find expected " .
                "variable from --Dump-config output");
        }
    }
    return &print_errors("[-] Could not execute: $cmd");
}

sub override_config() {
    my $cmd = "$fwknopdCmd $gpg_mode_str --fw-type $config{'FIREWALL_TYPE'} " .
        "--Override-config $override_sleep_fwknop_conf --Dump-config " .
        "-c $default_fwknop_conf -a $default_access_conf";
    if (&run_cmd($cmd, $NO_APPEND)) {
        my $found = 0;
        open F, "< $current_test_file" or die $!;
        ### just look for an expected variable
        while (<F>) {
            if (/SLEEP_INTERVAL\s+42/) {
                $found = 1;
                last;
            }
        }
        close F;
        if ($found) {
            return 1;
        } else {
            return &print_errors("[-] Could not find expected " .
                "override value from --Dump-config output");
        }
    }
    return &print_errors("[-] Could not execute: $cmd");
}

sub SPA_disk_caching() {
    my $pkt_file = "$output_dir/SPA_pkt.single";
    unlink $pkt_file if -e $pkt_file;
    my $cmd = "$default_fwknop_args --Save-packet " .
        "--Save-packet-file $pkt_file";
    if ($client_language eq 'C') {
        $cmd = "$default_fwknop_args --save-packet " .
            $pkt_file;
    }
    unless (&run_cmd($cmd, $NO_APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }
    unless (&run_cmd($cmd, $APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }
    if (-e $pkt_file) {
        my $lines = 0;
        open F, "< $pkt_file" or die $!;
        while (<F>) {
            $lines++;
        }
        close F;
        if ($lines == 1) {
            return 1;
        } else {
            return &print_errors("[-] --Save-packet-file " .
                "$pkt_file does not contain a single SPA packet");
        }
    } else {
        return &print_errors("[-] --Save-packet-file " .
            "$pkt_file does not exist");
    }
    return &print_errors("[-] Could not write SPA packet " .
        "to --Save-packet-file $pkt_file");
}

sub SPA_multi_packet_disk_caching() {
    my $pkt_file = "$output_dir/SPA_pkt.multi";
    unlink $pkt_file if -e $pkt_file;
    my $cmd = "$default_fwknop_args --Save-packet " .
        "--Save-packet-file $pkt_file --Save-packet-append";
    if ($client_language eq 'C') {
        $cmd = "$default_fwknop_args --save-packet " .
            "$pkt_file --save-packet-append";
    }
    unless (&run_cmd($cmd, $NO_APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }
    unless (&run_cmd($cmd, $APPEND)) {
        return &print_errors("[-] Could not execute: $cmd");
    }
    if (-e $pkt_file) {
        my $lines = 0;
        open F, "< $pkt_file" or die $!;
        while (<F>) {
            $lines++;
        }
        close F;
        if ($lines == 2) {
            return 1;
        } else {
            return &print_errors("[-] --Save-packet-file " .
                "$pkt_file does not contain two SPA packets");
        }
    } else {
        return &print_errors("[-] --Save-packet-file " .
            "$pkt_file does not exist");
    }
    return &print_errors("[-] Could not write two SPA packets " .
        "with --Save-packet-append");
}

sub show_last() {
    &run_cmd("$fwknopCmd $show_last_opt", $APPEND);
    open F, "< $current_test_file" or die $!;
    my $found = 0;
    while (<F>) {
        ### If the fwknop client has not been executed yet:
        ### [*] fwknop argument save files (~/.fwknop.save and ~/.fwknop.run)
        ### not found. at ../fwknop line 1514.
        if (/not\s+found/) {
            $found = 1;
            last;
        }

        ### If executed once:
        ### [+] Last fwknop client command line: -A tcp/22 -R -D somehost
        if (/Last\s+fwknop/) {
            $found = 1;
            last;
        }
    }
    close F;
    unless ($found) {
        return &print_errors("[-] Could not extract last command line " .
            "args invocation");
    }
    return 1;
}

sub expected_code_version() {
    if (-e '../VERSION') {
        open F, "< ../VERSION" or die $!;
        my $version = <F>;
        chomp $version;
        close F;
        for my $cmd ($fwknopCmd, $fwknopdCmd) {
            unless (&run_cmd("$cmd -V", $APPEND)) {
                return &print_errors("[-] $cmd " .
                        "--Version arg not accepted");
            }
        }
        my $found_version = 0;
        open F, "< $current_test_file" or die $!;
        while (<F>) {
            if (/$version/) {
                $found_version = 1;
                last;
            }
        }
        close F;
        unless ($found_version) {
            return &print_errors("[-] Could not " .
                "find version $version in --Version output");
        }
        return 1;
    }
    return &print_errors("[-] ../VERSION file does not exist");
}

sub print_errors() {
    my $msg = shift;
    &logr("fail ($test_num)\n$msg\n");
    if (-e $current_test_file) {
        &logr("    STDOUT and STDERR available in: " .
            "$current_test_file file.\n");
        open F, ">> $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        print F localtime() . " MSG: $msg\n";
        close F;
    }
    return 0;
}

sub run_cmd() {
    my ($cmd, $append) = @_;

    if ($append == $APPEND) {
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

sub setup() {
    $< == 0 && $> == 0 or
        die "[*] $0: You must be root (or equivalent ",
            "UID 0 account) to effectively test fwknop";

    $|++; ### turn off buffering

    die "[*] $conf_dir directory does not exist." unless -d $conf_dir;
    unless (-d $output_dir) {
        mkdir $output_dir or die "[*] Could not mkdir $output_dir: $!";
    }

    for my $file (glob("$output_dir/cmd.*")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    for my $file (glob("$output_dir/*.test")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    for my $file (glob("$output_dir/*.warn")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    for my $file (glob("$output_dir/*.die")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    for my $file (glob("$output_dir/SPA*")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    for my $file (glob("$output_dir/spa*")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    for my $file (glob("$output_dir/*.debug")) {
        unlink $file or die "[*] Could not unlink($file)";
    }

    for my $file ("$output_dir/md5sums", "$output_dir/digest.cache",
            "$output_dir/fwdata") {
        if (-e $file) {
            unlink $file or die "[*] Could not unlink($file)";
        }
    }

    if ($test_system_installed_fwknop) {
        $fwknopCmd  = '/usr/bin/fwknop';
        $fwknopdCmd = '/usr/sbin/fwknopd';
        $knoptmCmd  = '/usr/sbin/knoptm';
    }

    for my $prog ($fwknopCmd, $fwknopdCmd, $knoptmCmd) {
        die "[*] $prog does not exist" unless -e $prog;
        die "[*] $prog not executable" unless -x $prog;
    }

    unless (-x $gpgCmd) {
        my $found = 0;
        for my $path qw|/bin /sbin /usr/bin /usr/sbin
                /usr/local/bin /usr/local/sbin| {
            if (-x "$path/gpg") {
                $gpgCmd = "$path/gpg";
                $found = 1;
                last;
            }
        }
        unless ($found) {
            &logr("[-] Warning: could not find gpg command, " .
                "disabling GnuPG tests\n");
            $gpg_mode_str = '--no-gpg';
        }
    }

    unless (-x $tcpdumpCmd) {
        my $found = 0;
        for my $path qw|/bin /sbin /usr/bin /usr/sbin
                /usr/local/bin /usr/local/sbin| {
            if (-x "$path/tcpdump") {
                $tcpdumpCmd = "$path/tcpdump";
                $found = 1;
                last;
            }
        }
        unless ($found) {
            &logr("[-] Warning: could not find tcpdump command, " .
                "disabling filesystem sniffing tests\n");
        }
    }

    if (-e $logfile) {
        unlink $logfile or die $!;
    }

    &import_config();

    ### make sure fwknopd is not already running
    for my $pid_file ($config{'FWKNOP_PID_FILE'},
            $config{'KNOPTM_PID_FILE'},
            $config{'KNOPWATCHD_PID_FILE'},
            $config{'TCPSERV_PID_FILE'}) {
        if (-e $pid_file) {
            open P, "< $pid_file"
                or die "[*] Could not open $pid_file: $!";
            my $pid = <P>;
            close P;
            chomp $pid;
            if (kill 0, $pid) {
                die "[*] Please stop the running fwknop ",
                    "instance with 'fwknopd -K'";
            }
        }
    }
    &flush_quiet();
    system "$fwknopdCmd $gpg_mode_str -c $default_fwknop_conf " .
        "--fw-type $config{'FIREWALL_TYPE'} --Kill > /dev/null 2>\&1";

    ### set the loopback interface to lo0 for FreeBSD
    if ($config{'FIREWALL_TYPE'} eq 'ipfw' and $loopback_intf eq 'lo') {
        $loopback_intf = 'lo0';
    }
    return;
}

sub import_config() {
    open C, "< $fwknop_conf_file"
        or die "[*] Could not open $fwknop_conf_file: $!";
    while (<C>) {
        next if /^\s*#/;
        if (/^\s*(\S+)\s+(.*?)\;/) {
            my $varname = $1;
            my $val     = $2;
            if ($val =~ m|/.+| and $varname =~ /^\s*(\S+)Cmd$/) {
                ### found a command
                $cmds{$1} = $val;
            } else {
                $config{$varname} = $val;
            }
        }
    }
    close C;

    $cmds{'tcpdump'} = $tcpdumpCmd;

    ### resolve internal vars within variable values
    &expand_vars({'EXTERNAL_CMD_OPEN' => '', 'EXTERNAL_CMD_CLOSE' => ''});
    return;
}

sub expand_vars() {
    my $exclude_hr = shift;

    my $has_sub_var = 1;
    my $resolve_ctr = 0;

    while ($has_sub_var) {
        $resolve_ctr++;
        $has_sub_var = 0;
        if ($resolve_ctr >= 20) {
            die "[*] Exceeded maximum variable resolution counter.";
        }
        for my $hr (\%config, \%cmds) {
            for my $var (keys %$hr) {
                next if defined $exclude_hr->{$var};
                my $val = $hr->{$var};
                if ($val =~ m|\$(\w+)|) {
                    my $sub_var = $1;
                    die "[*] sub-ver $sub_var not allowed within same ",
                        "variable $var" if $sub_var eq $var;
                    if (defined $config{$sub_var}) {
                        $val =~ s|\$$sub_var|$config{$sub_var}|;
                        $hr->{$var} = $val;
                    } else {
                        die "[*] sub-var \"$sub_var\" not defined in ",
                            "config for var: $var.";
                    }
                    $has_sub_var = 1;
                }
            }
        }
    }
    return;
}

sub prepare_results() {
    my $rv = 0;
    die "[*] $output_dir does not exist" unless -d $output_dir;
    die "[*] $logfile does not exist, has fwknop_test.pl been executed?"
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

sub write_key() {
    open K, "> $local_key_file"
        or die "[*] Could not open $local_key_file: $!";
    print K "$localhost: $cache_key\n";
    print K "localhost: $cache_key\n";
    close K;
    return;
}

sub pass() {
    &logr("pass ($test_num)\n");
    $successful_tests++;
    return;
}

sub fwknop_test_fko_exists() {
    my $cmd = "$fwknopCmd --test-FKO-exists";
    open C, "$cmd 2>&1 |" or die "[*] Could not execute $cmd: $!";
    while (<C>) {
        if (/Using\s+FKO/) {
            $fwknop_using_fko_module = 1;
            last;
        }
    }
    close C;
    return;
}

sub fwknopd_test_fko_exists() {
    my $cmd = "$fwknopdCmd -c $default_fwknop_conf --test-FKO-exists";
    open C, "$cmd 2>&1 |" or die "[*] Could not execute $cmd: $!";
    while (<C>) {
        if (/Using\s+FKO/) {
            $fwknopd_using_fko_module = 1;
            last;
        }
    }
    close C;
    return;
}

sub get_spa_digests_from_fwknopd() {
    my $fwknop_conf = shift;

    ### write the current packet out to the dump packets file
    open F, "> $dump_packets_file" or
        die "[*] Could not open $dump_packets_file: $!";
    print F $cache_encrypted_spa_packet, "\n";
    close F;

    my $cmd = "$fwknopdCmd -c $fwknop_conf " .
        "-a $default_access_conf --spa-dump-packets $dump_packets_file " .
        "--fw-type $config{'FIREWALL_TYPE'}";

    open C, "$cmd 2>&1 |" or die "[*] Could not execute $cmd: $!";
    while (<C>) {
        if (/Disk\s+write\s+digest:\s+(\S+)/) {
            $spa_packet_digest = $1;
            last;
        }
    }
    close C;

    return;
}

sub check_language() {
    open F, "$fileCmd $fwknopCmd |" or die $!;
    while (<F>) {
        if (/perl/i) {
            $client_language = 'perl';
        } elsif (/Bourne/ or /\sELF/) {  ### Bourne shell wrapper around compiled binary
            $client_language = 'C';
        }
    }
    close F;

    open F, "$fileCmd $fwknopdCmd |" or die $!;
    while (<F>) {
        if (/perl/i) {
            $server_language = 'perl';
        } elsif (/Bourne/ or /\sELF/) {  ### Bourne shell wrapper around compiled binary
            $server_language = 'C';
        }
    }
    close F;

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

sub import_perl_modules() {

    my $mod_paths_ar = &get_mod_paths();

    if ($#$mod_paths_ar > -1) {  ### /usr/lib/fwknop/ exists
        push @$mod_paths_ar, @INC;
        splice @INC, 0, $#$mod_paths_ar+1, @$mod_paths_ar;
    }

    return;
}

sub get_mod_paths() {

    my @paths = ();

    unless (-d $lib_dir) {
        my $dir_tmp = $lib_dir;
        $dir_tmp =~ s|lib/|lib64/|;
        if (-d $dir_tmp) {
            $lib_dir = $dir_tmp;
        } else {
            return [];
        }
    }

    opendir D, $lib_dir or die "[*] Could not open $lib_dir: $!";
    my @dirs = readdir D;
    closedir D;

    push @paths, $lib_dir;

    for my $dir (@dirs) {
        ### get directories like "/usr/lib/fwknop/x86_64-linux"
        next unless -d "$lib_dir/$dir";
        push @paths, "$lib_dir/$dir"
            if $dir =~ m|linux| or $dir =~ m|thread|
                or (-d "$lib_dir/$dir/auto");
    }
    return \@paths;
}

sub usage() {
    print <<_HELP_;

Usage: fwknop_test.pl [options]

Options:

    --access-conf <file>     - Path to the file containing the access
                               directives use during most of the test.
    -P, --Prepare-results    - Prepare test suite results for communication
                               to a third party.
    --fwknop-command <file>  - Path to the fwknop client to use rather than
                               the default ../fwknop
    --fwknopd-command <file> - Path to the fwknop daemon to use rather than
                               the default ../fwknopd
    --knoptm-command <file>  - Path to the daemon in charge to remove iptables
                               rules rather than the default ../knoptm
    --loopback-intf <intf>   - Interface used by fwknopd to sniff packets in
                               PCAP mode.
    --test-include <string>  - Restrict tests to those that match <string>.
    --include <string>       - Synonym for --test-include.
    --test-exclude <string>  - Run all tests except for those that match
                               <string>.
    --exclude <string>       - Synonym for --test-exclude.
    --IPT <version>          - Specify the version of the installed
                               IPTables::ChainMgr module.
    --test-system-fwknop     - Test any existing fwknop installation
                               instead of the fwknop/fwknopd programs in the
                               local source tree.
    --skip-language-check    - Assume fwknop client/server is written in
                               perl.
    --no-client-FKO-module   - Disable FKO usage of the fwknop perl client.
    --no-server-FKO-module   - Disable FKO usage of the fwknop perl server.
    -h, --help               - Display usage information.

_HELP_
    exit 0;
}
