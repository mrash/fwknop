#!/usr/bin/perl -w

use lib '/usr/lib/fwknop';
use IPTables::ChainMgr;
use IPTables::Parse;
use strict;

my $ipt = new IPTables::ChainMgr(
    'iptables' => '/sbin/iptables',
    'verbose'  => 1
);
my $total_rules = 0;

my ($rv, $out_aref, $err_aref) = $ipt->create_chain('filter', 'FWKNOP');
print "create_chain() rv: $rv\n";
print "$_\n" for @$out_aref;
print "$_\n" for @$err_aref;

($rv, $out_aref, $err_aref) = $ipt->add_jump_rule('filter', 'INPUT', 'FWKNOP');
print "add_jump_rule() rv: $rv\n";
print "$_\n" for @$out_aref;
print "$_\n" for @$err_aref;

($rv, $out_aref, $err_aref) = $ipt->add_ip_rule('1.1.1.1',
    '0.0.0.0/0', 10, 'filter', 'FWKNOP', 'DROP');
print "add_ip_rule() rv: $rv\n";
print "$_\n" for @$out_aref;
print "$_\n" for @$err_aref;

($rv, $total_rules) = $ipt->find_ip_rule('1.1.1.1', '0.0.0.0/0', 'filter', 'FWKNOP', 'DROP');
print "find ip: $rv, total chain rules: $total_rules\n";

($rv, $out_aref, $err_aref) = $ipt->add_ip_rule('2.2.1.1', '0.0.0.0/0', 10,
    'filter', 'FWKNOP', 'DROP');
print "add_ip_rule() rv: $rv\n";
print "$_\n" for @$out_aref;
print "$_\n" for @$err_aref;

($rv, $out_aref, $err_aref) = $ipt->add_ip_rule('2.2.4.1', '0.0.0.0/0', 10,
    'filter', 'FWKNOP', 'DROP');
print "add_ip_rule() rv: $rv\n";
print "$_\n" for @$out_aref;
print "$_\n" for @$err_aref;

($rv, $out_aref, $err_aref) = $ipt->delete_ip_rule('1.1.1.1', '0.0.0.0/0',
    'filter', 'FWKNOP', 'DROP');
print "delete_ip_rule() rv: $rv\n";
print "$_\n" for @$out_aref;
print "$_\n" for @$err_aref;

($rv, $out_aref, $err_aref) = $ipt->delete_chain('filter', 'INPUT', 'FWKNOP');
print "delete_chain() rv: $rv\n";
print "$_\n" for @$out_aref;
print "$_\n" for @$err_aref;

($rv, $out_aref, $err_aref) = $ipt->run_ipt_cmd('/sbin/iptables -nL INPUT');
print "list on 'INPUT' chain rv: $rv\n";
print for @$out_aref;
print for @$err_aref;

($rv, $out_aref, $err_aref) = $ipt->run_ipt_cmd('/sbin/iptables -nL INPU');
print "bogus list on 'INPU' chain rv: $rv (this is expected).\n";
print for @$out_aref;
print for @$err_aref;

exit 0;
