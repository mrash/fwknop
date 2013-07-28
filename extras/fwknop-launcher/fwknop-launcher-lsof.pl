#!/usr/bin/perl -w
#
#############################################################################
#
# File: fwknop-launcher-lsof.pl
#
# URL: http://www.cipherdyne.org/fwknop/
#
# Purpose:  This script provides a lightweight mechanism to launch the fwknop
#           client shortly after a local user tries to initiate a connection
#           to a remote service that is protected by fwknopd.  The advantage
#           of using this script is that local users don't have to run the
#           fwknop client themselves before initiating an outbound
#           connection.  The idea for this script came from Sebastien
#           Jeanquier.  It is not required to have the fwknopd daemon
#           installed in order for this script to be effective - only the
#           fwknop client needs to be available.
#
# Author: Michael Rash (mbr@cipherdyne.org)
#
# Version: 2.0.1
#
# Copyright (C) 2011 Michael Rash (mbr@cipherdyne.org)
#
# License - GNU General Public License version 2 (GPLv2):
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

use POSIX;
use Getopt::Long;
use strict;

#================== config ==================
my $launcher_config = '~/.fwknop-launcher.conf';

my $sleep_interval = 1;

my $lsof_cmd   = '/usr/bin/lsof';
my $fwknop_cmd = '/usr/bin/fwknop';
#================ end config ================

my $ip_re = qr|(?:[0-2]?\d{1,2}\.){3}[0-2]?\d{1,2}|;  ### IPv4

my %spa_dispatch_cache = ();
my %spa_config_dsts    = ();
my $fwknop_args_append   = '';
my $fwknop_args_override = '';
my $key_file  = '';
my $home_dir  = '';
my $user      = '';
my $no_daemon = 0;
my $verbose   = 0;
my $help      = 0;

die "[*] Use --help for usage information.\n" unless(GetOptions (
    'config=s'         => \$launcher_config, # launcher config
    'lsof-cmd=s'       => \$lsof_cmd,        # lsof path
    'fwknop-cmd=s'     => \$fwknop_cmd,      # fwknop path
    'sleep-interval=i' => \$sleep_interval,  # seconds
    'user=s'           => \$user,            # set the user
    'home-dir=s'       => \$home_dir,        # set the home dir
    'no-daemon'        => \$no_daemon,       # run in the foreground
    'verbose'          => \$verbose,         # verbose mode
    'help'             => \$help             # Print help
));

&usage() if $help;

&init();

&daemonize() unless $no_daemon;

&watch_lsof();

exit 0;

#============== end main =============

sub watch_lsof() {

    my $lsof_exec_ctr = 0;

    for (;;) {

        my $cmd = "$lsof_cmd -u $user -a -n -P -i 4";  ### IPv4

        print "[+] Executing: $cmd\n" if $no_daemon and $verbose;

        open LSOF, "$cmd |" or die "[*] Could not execute $cmd: $!";

        ### COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
        ### telnet  31483  mbr    3u  IPv4  54543      0t0  TCP 127.0.0.1:41619->127.0.0.1:1234 (SYN_SENT)

        while (<LSOF>) {
            if (/^(\S+)\s+(\d+)\s+\S+\s+.*\s(\S+)\s+($ip_re):
                    (\d+)\-\>($ip_re):(\d+)\s+\(SYN_SENT\)/x) {
                my $command = $1;
                my $pid     = $2;
                my $proto   = lc($3);
                my $src_ip  = $4;
                my $s_port  = $5;
                my $dst_ip  = $6;
                my $d_port  = $7;

                print "[+] Matched line: $_" if $no_daemon and $verbose;

                my $connection_string = "$command:$proto:$src_ip:$s_port:$dst_ip:$d_port";

                next if defined $spa_dispatch_cache{$connection_string};

                if (&is_valid_fwknop_dst($command, $proto, $dst_ip, $d_port)) {

                    if ($no_daemon and $verbose) {
                        print "[+] Matched connection, launching fwknop.\n";
                    }

                    &dispatch_fwknop($proto, $dst_ip, $d_port);

                    ### add this line to the dispatch cache so that we don't
                    ### send multiple SPA packets for the same connection
                    $spa_dispatch_cache{$connection_string} = '';

                } else {
                    if ($no_daemon and $verbose) {
                        print "[-] Attempted connection not matched by ",
                            "any SPA_ACCESS variable in $launcher_config\n";
                    }
                }
            }
        }
        close LSOF;

        $lsof_exec_ctr++;

        if ($lsof_exec_ctr == 3600) {
            %spa_dispatch_cache = ();
            $lsof_exec_ctr = 0;
        }

        sleep $sleep_interval;
    }
    return;
}

sub is_valid_fwknop_dst() {
    my ($cmd, $proto, $dst_ip, $d_port) = @_;

    CMD: for my $access_cmd (keys %spa_config_dsts) {
        next CMD unless $access_cmd eq 'any' or $cmd eq $access_cmd;
        PROTO: for my $access_proto (keys %{$spa_config_dsts{$access_cmd}}) {
            next PROTO unless $access_proto eq 'any' or $proto eq $access_proto;
            IP: for my $access_ip (keys %{$spa_config_dsts{$access_cmd}{$access_proto}}) {
                next IP unless $access_ip eq 'any' or $access_ip eq $dst_ip;
                PORT: for my $access_port
                        (keys %{$spa_config_dsts{$access_cmd}{$access_proto}{$access_ip}}) {
                    return 1 if $access_port eq 'any' or $d_port == $access_port;
                }
            }
        }
    }

    return 0;
}

sub dispatch_fwknop() {
    my ($proto, $dst_ip, $d_port) = @_;

    my $fwknop_cmd_str = "$fwknop_cmd -A $proto/$d_port -s -D " .
            "$dst_ip --get-key $key_file";

    if ($fwknop_args_append) {
        $fwknop_cmd_str .= " $fwknop_args_append";
    } elsif ($fwknop_args_override) {
        $fwknop_cmd_str = "$fwknop_cmd $fwknop_args_override";
    }

    print "[+] Executing: $fwknop_cmd_str\n" if $no_daemon;

    open FWKNOP, "$fwknop_cmd_str |"
        or die "[*] Could not execute: $fwknop_cmd_str: $!";
    close FWKNOP;

    return 0;
}

sub daemonize() {

    my $pid = fork();
    exit 0 if $pid;
    die "[*] $0: Couldn't fork: $!" unless defined $pid;
    POSIX::setsid() or die "[*] $0: Can't start a new session: $!";

    return;
}

sub init() {

    if ($launcher_config =~ m|^\~|) {

        ### get the path to the user's home directory
        &get_homedir() unless $home_dir;

        $launcher_config =~ s|^\~|$home_dir|;
    }

    my $found_key_file = 0;
    my $found_access_var = 0;

    my $line_ctr = 1;
    open F, "< $launcher_config"
        or die "[*] Could not open $launcher_config: $!";
    while (<F>) {
        if (/^SPA_ACCESS\s+(\S+):(\S+):(\S+):(\S+);/) {
            my $cmd    = $1;
            my $proto  = lc($2);
            my $dst_ip = $3;
            my $d_port = $4;

            ### validate the protocol
            unless ($proto eq 'any'
                or $proto eq 'tcp'
                or $proto eq 'udp'
            ) {
                die "[*] Invalid proto '$proto' ",
                    "in $launcher_config at line: $line_ctr";
            }

            ### validate connection destination IP
            unless ($dst_ip eq 'any'
                    or $dst_ip =~ /$ip_re/) {
                die "[*] Invalid IP '$dst_ip' ",
                    "in $launcher_config at line: $line_ctr";
            }

            ### validate connection destination port
            unless ($d_port eq 'any'
                    or $d_port =~ /^\d+$/) {
                die "[*] Invalid port '$d_port' ",
                    "in $launcher_config at line: $line_ctr";
            }

            ### add this dst into the valid destinations cache
            $spa_config_dsts{$cmd}{$proto}{$dst_ip}{$d_port} = '';

            $found_access_var = 1;

        } elsif (/^KEY_FILE\s+(\S+);/) {
            $key_file = $1;

            if ($key_file =~ m|^\~|) {
                &get_homedir() unless $home_dir;
                $key_file =~ s|^\~|$home_dir|;
            }

            $found_key_file = 1;

        } elsif (/^USER\s+(\S+);/) {
            ### might have been set via the command line
            $user = $1 unless $user;

        } elsif (/^FWKNOP_ARGS_APPEND\s+\"(.*)\";/) {
            $fwknop_args_append = $1;
        } elsif (/^FWKNOP_ARGS_OVERRIDE\s+\"(.*)\";/) {
            $fwknop_args_override = $1;
        }

        $line_ctr++;
    }
    close F;

    unless ($found_key_file) {
        die "[*] Must have a key file defined via KEY_FILE";
    }

    unless ($found_access_var) {
        die "[*] Must have at least one SPA_ACCESS var defined";
    }

    &get_username() unless $user;

    return;
}

sub get_homedir() {

    $home_dir = (getpwuid($<))[7];

    unless ($home_dir) {
        $home_dir = $ENV{'HOME'} if defined $ENV{'HOME'};
    }

    die "[*] Could not determine home directory. Use the -d <homedir> option."
        unless $home_dir;

    return;
}

sub get_username() {

    $user = (getpwuid($<))[0];

    unless ($user) {
        if (defined $ENV{'USER'}) {
            $user = $ENV{'USER'};
        } elsif (defined $ENV{'USERNAME'}) {
            $user = $ENV{'USERNAME'};
        }
    }

    die "[*] Could not determine username. Use the -u <user> option."
        unless $user;

    return;
}

sub usage() {
    print <<_HELP_;

Usage: fwknop-launcher-lsof.pl [options]

Options:

    -c,  --config     <file>   - Path to fwknop-launcher.conf config file.
    -l,  --lsof-cmd   <path>   - Path to lsof command.
    -f,  --fwknop-cmd <path>   - Path to fwknop client command.
    -s,  --sleep   <seconds>   - Specify sleep interval (default:
                                 $sleep_interval seconds)
    -n   --no-daemon           - Run in foreground mode.
    -u,  --user   <username>   - Specify username (usually this is not
                                 needed).
         --home-dir <dir>      - Path to user's home directory (usually
                                 this is not needed).
    -v   --verbose             - Print verbose information to the terminal
                                 (requires --no-daemon).
         --help                - Print usage info and exit.

_HELP_
    exit 0;
}
