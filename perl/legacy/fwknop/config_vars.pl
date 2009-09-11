#!/usr/bin/perl -w
#
############################################################################
#
# File: config_vars.pl
#
# Purpose: To provide basic usage validation for cipherdyne.org project
#          variables.
#
############################################################################
#
# $Id: config_vars.pl 571 2006-10-16 02:41:41Z mbr $
#

use strict;

my $config_file = 'config_vars.conf';

open C, "< $config_file" or die $!;
my @lines = <C>;
close C;

my %config = ();
for my $line (@lines) {
    next unless $line;
    next if $line =~ /^\s*#/;
    if ($line =~ /^\s*(\S+)\s+(\S+)/) {
        $config{$1}{$2} = '';
    }
}

PROG: for my $prog (keys %config) {
    unless (-e $prog) {
        print "[-] program: $prog does not exist in current directory.\n";
        next PROG;
    }
    open F, "< $prog" or die "[*] Could not open $prog: $!";
    my @prog_lines = <F>;
    close F;
    my %config_vars = ();
    my %used_vars   = ();
    CONF: for my $config (keys %{$config{$prog}}) {
        unless (-e $config) {
            print "[-] config: $config for program: $prog does not exist.\n";
            next CONF;
        }
        open F, "< $config" or die "[*] Could not open $config: $!";
        my @config_lines = <F>;
        close F;
        for my $line (@config_lines) {
            next unless $line;
            next unless $line =~ /\S/;
            next if $line =~ /^\s*#/;
            if ($line =~ /^\s*(\S+)\s/) {
                $config_vars{$1} = '';
            }
        }
    }
    my $line_num = 1;
    ### see if the program is using an undefined configuration
    ### variable
    for my $line (@prog_lines) {
        if ($prog =~ /\.c/) {  ### C code file
            if ($line =~ m|\"(\w+)\s+\"|) {
                my $var = $1;
                unless (defined $config_vars{$var}) {
                    print "[-] Config var: $var (line $line_num) ",
                        "is not defined in config files for program: $prog\n";
                }
                $used_vars{$var} = '';
            }
        } else {
            my $var1 = '';
            my $var2 = '';
            if ($line =~ m|\$config\{\'(\S+)\'\}|) {
                $var1 = $1;
            }
            if ($line =~ m|\$cmds\{\'(\S+)\'\}|) {
                $var2 = "$1Cmd";
            }
            if ($var1) {
                unless (defined $config_vars{$var1}) {
                    print "[-] Config var: $var1 (line $line_num) ",
                        "is not defined in config files for program: $prog\n";
                }
                $used_vars{$var1} = '';
            }
            if ($var2) {
                unless (defined $config_vars{$var2}) {
                    print "[-] Config var: $var2 (line $line_num) ",
                        "is not defined in config files for program: $prog\n";
                }
                $used_vars{$var2} = '';
            }
        }
        $line_num++;
    }

    ### see if the config files define a configuration variable
    ### that is not used by the program
    for my $var (sort keys %config_vars) {
        unless (defined $used_vars{$var}) {
            print "[-] $var is defined in config files, ",
                "but not used in $prog\n";
        }
    }
}

exit 0;
