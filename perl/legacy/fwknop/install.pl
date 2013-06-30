#!/usr/bin/perl -w
#
#############################################################################
#
# File: install.pl
#
# URL: http://www.cipherdyne.org/fwknop
#
# Purpose: Installer for fwknop
#
# Credits:  (see the CREDITS file)
#
# Copyright (C) 2004-2008 Michael Rash (mbr@cipherdyne.org)
#
# License (GNU General Public License):
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
# $Id: install.pl 1409 2009-02-23 05:38:33Z mbr $
#

use Cwd;
use File::Copy;
use File::Path;
use Getopt::Long;
use Sys::Hostname;
use strict;

#========================== config ===========================
my $USRBIN_DIR  = '/usr/bin';
my $USRSBIN_DIR = '/usr/sbin';

my $fwknop_conf_file = 'fwknop.conf';

### system binaries
my $chkconfigCmd = '/sbin/chkconfig';
my $rcupdateCmd  = '/sbin/rc-update';  ### Gentoo
my $updatercdCmd = '/usr/sbin/update-rc.d';  ### Ubuntu
my $makeCmd      = '/usr/bin/make';
my $perlCmd      = '/usr/bin/perl';
my $gzipCmd      = '/bin/gzip';
my $killallCmd   = '/usr/bin/killall';
my $mknodCmd     = '/bin/mknod';
my $ifconfigCmd  = '/sbin/ifconfig';
my $runlevelCmd  = '/sbin/runlevel';
#======================== end config =========================

### main configuration hash
my %config = ();

my $client_install = 0;
my $bsd_install    = 0;
my $cygwin_install = 0;
my $homedir = '';
my $distro  = '';
my $print_help  = 0;
my $uninstall   = 0;
my $syslog_conf = '';
my $data_method = '';
my $runlevel = -1;
my $deps_dir = 'deps';
my $init_dir = '/etc/init.d';
my $init_name = 'fwknop';
my $force_mod_re = '';
my $exclude_mod_re = '';
my $force_path_update = 0;
my $sniff_interface   = '';
my $cmdline_force_install = 0;
my $skip_module_install = 0;
my $install_syslog_fifo = 0;
my $single_module_install = '';
my $force_defaults  = 0;
my $cmdline_os_type = '';
my $os_type = 0;
my $locale = 'C';  ### default LC_ALL env variable
my $no_locale = 0;

### unless --OS-type is used, install.pl will try to figure out the
### OS where fwknop is being installed (this is usually best).
my $OS_LINUX  = 1;
my $OS_BSD    = 2;
my $OS_CYGWIN = 3;
my $OS_DARWIN = 4;  ### Mac OS X

my %os_types = (
    'linux'  => $OS_LINUX,
    'bsd'    => $OS_BSD,
    'cygwin' => $OS_CYGWIN,
    'darwin' => $OS_DARWIN
);

my %exclude_cmds = (
    'gpg'         => '',
    'mail'        => '',
    'fwknop'      => '',
    'fwknopd'     => '',
    'fwknop_serv' => '',
    'knopmd'      => '',
    'knoptm'      => '',
    'knopwatchd'  => '',
);

### perl module directories
my @required_perl_modules = (
    {   'module'              =>'Class::MethodMaker', ### GnuPG::Interface dependency
        'force-install'       => 0,
        'client-mode-install' => 1,
        'mod-dir'             => 'Class-MethodMaker'
    },
    {   'module'              => 'GnuPG::Interface',
        'force-install'       => 0,
        'client-mode-install' => 1,
        'mod-dir'             => 'GnuPG-Interface'
    },
    {   'module'              => 'Unix::Syslog',
        'force-install'       => 0,
        'client-mode-install' => 0,
        'mod-dir'             => 'Unix-Syslog'
    },
    {   'module'              => 'Net::IPv4Addr',
        'force-install'       => 0,
        'client-mode-install' => 1,
        'mod-dir'             => 'Net-IPv4Addr'
    },
    {   'module'              => 'Net::Pcap',
        'force-install'       => 0,
        'client-mode-install' => 0,
        'mod-dir'             => 'Net-Pcap'
    },
    {   'module'              => 'Net::RawIP',
        'force-install'       => 0,
        'client-mode-install' => 1,
        'mod-dir'             => 'Net-RawIP'
    },
    {   'module'              => 'Net::Ping::External',
        'force-install'       => 0,
        'client-mode-install' => 1,
        'mod-dir'             => 'Net-Ping-External'
    },
    {   'module'              => 'Digest::SHA',
        'force-install'       => 0,
        'client-mode-install' => 1,
        'mod-dir'             => 'Digest-SHA'
    },
    {   'module'              => 'Crypt::Rijndael',
        'force-install'       => 0,
        'client-mode-install' => 1,
        'mod-dir'             => 'Crypt-Rijndael'
    },
    {   'module'              => 'Crypt::CBC',
        'force-install'       => 0,
        'client-mode-install' => 1,
        'mod-dir'             => 'Crypt-CBC'
    },
    {   'module'              => 'Term::ReadKey',
        'force-install'       => 0,
        'client-mode-install' => 1,
        'mod-dir'             => 'TermReadKey'
    },
    {   'module'              => 'IPTables::Parse',
        'force-install'       => 1,
        'client-mode-install' => 0,
        'mod-dir'             => 'IPTables-Parse'
    },
    {   'module'              => 'IPTables::ChainMgr',
        'force-install'       => 1,
        'client-mode-install' => 0,
        'mod-dir'             => 'IPTables-ChainMgr'
    }
);

my %cmds = (
    'make'     => $makeCmd,
    'perl'     => $perlCmd,
    'gzip'     => $gzipCmd,
    'killall'  => $killallCmd,
    'mknod'    => $mknodCmd,
    'ifconfig' => $ifconfigCmd,
    'runlevel' => $runlevelCmd
);

my @cmd_search_paths = qw(
    /bin
    /sbin
    /usr/bin
    /usr/sbin
    /usr/local/bin
    /usr/local/sbin
);

### for user answers
my $ACCEPT_YES_DEFAULT = 1;
my $ACCEPT_NO_DEFAULT  = 2;
my $NO_ANS_DEFAULT     = 0;

### make Getopts case sensitive
Getopt::Long::Configure('no_ignore_case');

&usage(1) unless (GetOptions(
    'Single-mod-install=s'  => \$single_module_install,  ### install a single module
    'force-mod-install' => \$cmdline_force_install,  ### force install of all modules
    'Force-mod-regex=s' => \$force_mod_re, ### force specific mod install with regex
    'Exclude-mod-regex=s' => \$exclude_mod_re, ### exclude a particular perl module
    'Skip-mod-install' => \$skip_module_install,
    'OS-type=s'        => \$cmdline_os_type,
    'Cygwin-install'   => \$cygwin_install,
    'BSD-install'   => \$bsd_install,
    'Defaults'      => \$force_defaults,
    'client-only'   => \$client_install, # Force client-only installation
    'path-update'   => \$force_path_update,
    'uninstall'     => \$uninstall,       # Uninstall fwknop.
    'syslog-conf=s' => \$syslog_conf,     # Specify path to syslog config file.
    'interface=s'   => \$sniff_interface, # Specify interface to sniff from
    'init-dir=s'    => \$init_dir,
    'init-name=s'   => \$init_name,
    'install-syslog-fifo' => \$install_syslog_fifo,
    'runlevel=i'    => \$runlevel,
    'Home-dir=s'    => \$homedir, # specify home directory manually
    'LC_ALL=s'      => \$locale,
    'no-LC_ALL'     => \$no_locale,
    'help'          => \$print_help # Display help.
));
&usage(0) if $print_help;

$force_mod_re = qr|$force_mod_re| if $force_mod_re;
$exclude_mod_re = qr|$exclude_mod_re| if $exclude_mod_re;
$single_module_install = qr|$single_module_install| if $single_module_install;

### set LC_ALL env variable
$ENV{'LC_ALL'} = $locale unless $no_locale;

&handle_cmd_line();

### import paths from default fwknopd.conf
&import_config();

### see if the deps/ directory exists, and if not then we are installing
### from the -nodeps sources so don't install any perl modules
$skip_module_install = 1 unless -d $deps_dir;

### check to see if we are installing as a non-root user
&check_non_root_user() unless $client_install;

### get the OS type
&get_os() unless $os_type;

if ($os_type == $OS_LINUX) {
    print "[+] OS: Linux\n";
} elsif ($os_type == $OS_CYGWIN) {
    print "[+] OS: Cygwin\n";
} elsif ($os_type == $OS_DARWIN) {
    print "[+] OS: Darwin\n";
} elsif ($os_type == $OS_BSD) {
    print "[+] OS: BSD\n";
}

if ($client_install) {

    ### we are installing as a normal user instead of root, so see
    ### if it is ok to install within the user's home directory
    unless ($homedir) {
        $homedir = $ENV{'HOME'} or die '[*] Could not get home ',
            "directory, use --Home-dir <directory>";
    }

    print
"    The fwknop client will be installed at $homedir/bin/fwknop, and a few\n",
"    perl modules needed by fwknop will be installed in $homedir/lib/fwknop/.\n\n",

    $config{'FWKNOP_MOD_DIR'} = "$homedir/lib/fwknop";
    $USRBIN_DIR = "$homedir/bin";
}

if ($os_type == $OS_LINUX) {

    $distro = &get_linux_distro();

    if ($distro eq 'redhat' or $distro eq 'fedora') {
        ### add chkconfig only if we are runing on a redhat distro
        $cmds{'chkconfig'} = $chkconfigCmd;
    } elsif ($distro eq 'gentoo') {
        ### add rc-update if we are running on a gentoo distro
        $cmds{'rc-update'} = $rcupdateCmd;
    } elsif ($distro eq 'ubuntu') {
        ### add update-rc.d if we are running on an ubuntu distro
        $cmds{'update-rc.d'} = $updatercdCmd;
    }
    print "[+] Distro: $distro\n";
}

### make sure the system binaries are where we expect
### them to be.
&check_commands();

my $hostname = hostname();

my $src_dir = getcwd() or die "[*] Could not get current working directory.";

if (not $uninstall) {
    &install();
} else {
    &uninstall();
}
exit 0;
#======================= end main ==========================

sub install() {
    print "[+] Installing fwknop on $hostname\n";

    if ($homedir) {
        die "[*] $homedir does not exist" unless -d $homedir;
    }

    my $preserve_rv = 0;
    unless ($client_install) {
        if (&ask_to_stop_fwknop()) {
            &stop_fwknop();
        }

        for my $dir qw| /usr/lib /var/run /var/log /var/lib | {
            unless (-d $dir) {
                mkdir $dir or die "[*] Could not mkdir $dir: $!";
            }
        }
        unless (-d $USRSBIN_DIR) {
            mkdir $USRSBIN_DIR or die "[*] Could not mkdir $USRSBIN_DIR: $!";
        }
        for my $dir qw/FWKNOP_DIR FWKNOP_RUN_DIR
                    FWKNOP_LIB_DIR/ {
            unless (-d $config{$dir}) {
                mkdir $config{$dir}, 0500 or
                    die "[*] Could not mkdir $config{$dir}: $!";
            }
        }
    }
    unless (-d $USRBIN_DIR) {
        print "[+] Creating: $USRBIN_DIR\n";
        mkdir $USRBIN_DIR or die "[*] Could not mkdir $USRBIN_DIR: $!";
    }

    ### config directory
    unless ($client_install) {
        unless (-d $config{'FWKNOP_CONF_DIR'}) {
            ### Note that root will only be able to view files in
            ### /etc/fwknop since fwknop only needs to view fwknop.conf
            ### when being run as a daemon.
            print "[+] Creating config directory: ",
                "$config{'FWKNOP_CONF_DIR'}\n";
            mkdir $config{'FWKNOP_CONF_DIR'}, 0500
                or die "[*] Could not mkdir $config{'FWKNOP_CONF_DIR'}: $!";
        }

        ### archive directory for previously installed config files
        unless (-d "$config{'FWKNOP_CONF_DIR'}/archive") {
            print "[+] Creating config{'FWKNOP_CONF_DIR'}/archive ",
                "directory: $config{'FWKNOP_CONF_DIR'}/archive\n";
            mkdir "$config{'FWKNOP_CONF_DIR'}/archive", 0500 or die
                "[*] Could not mkdir $config{'FWKNOP_CONF_DIR'}/archive: $!";
        }
    }

    print "[+] Several perl modules needed by fwknop will be installed in\n",
        "    $config{'FWKNOP_MOD_DIR'}. Installing them here will keep the ",
        "system perl\n    library tree clean.\n";

    ### make our library directory (for perl modules)
    if ($client_install) {
        unless (-d "$homedir/lib") {
            print "[+] Creating directory $homedir/lib\n";
            mkdir "$homedir/lib", 0755
                or die "[*] Could not mkdir $homedir/lib: $!";
        }
    }
    unless (-d $config{'FWKNOP_MOD_DIR'}) {
        print "[+] Creating directory $config{'FWKNOP_MOD_DIR'}\n";
        mkdir $config{'FWKNOP_MOD_DIR'}, 0755
            or die "[*] Could not mkdir $config{'FWKNOP_MOD_DIR'}: $!";
    }

    ### install perl modules
    unless ($skip_module_install) {
        for my $mod_href (@required_perl_modules) {
            &install_perl_module($mod_href);
        }
    }
    chdir $src_dir or die "[*] Could not chdir $src_dir: $!";

    if ($single_module_install) {
        print "    Finished module installation, exiting.\n";
        exit 0;
    }

    unless ($client_install) {

        ### install man pages
        &install_manpage('knopmd.8');
        &install_manpage('knopwatchd.8');
        &install_manpage('fwknop.8');
        &install_manpage('fwknopd.8');

        if (-e "$config{'FWKNOP_CONF_DIR'}/fwknop.conf") {
            $preserve_rv = &query_preserve_config();
        }

        print "[+] Compiling knopmd and knopwatchd daemons:\n";

        ### remove any previously compiled knopmd
        unlink 'knopmd' if -e 'knopmd';

        ### remove any previously compiled knopwatchd
        unlink 'knopwatchd' if -e 'knopwatchd';

        ### compile the C fwknop daemons
        system $cmds{'make'};

        unless (-e 'knopmd' and -e 'knopwatchd') {
            die "[*] Compilation failed.";
        }

        ### install fwknop server-side daemons/programs
        for my $daemon qw(fwknopd knopmd knopwatchd knoptm fwknop_serv) {
            if ($daemon eq 'fwknopd' or $daemon eq 'knoptm') {
                unless (((system "$cmds{'perl'} -c $daemon")>>8) == 0) {
                    die "[*] $daemon does not compile with \"perl -c\".  ",
                        "Download the latest sources ",
                        "from:\n\nhttp://www.cipherdyne.org/\n";
                }
            }
            print "[+] Copying $daemon -> $USRSBIN_DIR\n";
            copy $daemon, $USRSBIN_DIR or
                die "[*] Could not cp $daemon to $USRSBIN_DIR: $!";
            chmod 0500, "$USRSBIN_DIR/$daemon" or
                die "[*] Could not chmod 500 $USRSBIN_DIR/$daemon: $!";
        }
    }

    print "[+] Copying fwknop -> $USRBIN_DIR\n";
    copy 'fwknop', $USRBIN_DIR or
        die "[*] Could not cp fwknop to $USRBIN_DIR: $!";

    if ($client_install) {
        open F, "< $USRBIN_DIR/fwknop" or die "[*] Could not open ",
            "$USRBIN_DIR/fwknop: $!";
        my @lines = <F>;
        close F;
        open P, "> $USRBIN_DIR/fwknop.tmp" or die "[*] Could not open ",
            "$USRBIN_DIR/fwknop.tmp: $!";
        for my $line (@lines) {
            ### change the lib dir to new homedir path
            if ($line =~ m|^\s*use\s+lib\s+\'/usr/lib/fwknop\';|) {
                print P "use lib '", $config{'FWKNOP_MOD_DIR'}, "';\n";
            } elsif ($line =~ m|^\s*my\s+\$lib_dir\s+=\s+\'/usr/lib/fwknop\';|) {
                print P 'my $lib_dir = ' . "'"
                    . $config{'FWKNOP_MOD_DIR'} . "';\n";
            } else {
                print P $line;
            }
        }
        close P;
        move "$USRBIN_DIR/fwknop.tmp", "$USRBIN_DIR/fwknop" or die "[*] Could ",
            "not move $USRBIN_DIR/fwknop.tmp -> $USRBIN_DIR/fwknop: $!";
        chmod 0700, "$USRBIN_DIR/fwknop" or
            die "[*] Could not chmod 755 $USRBIN_DIR/fwknop: $!";
    } else {
        chmod 0755, "$USRBIN_DIR/fwknop" or
            die "[*] Could not chmod 755 $USRBIN_DIR/fwknop: $!";
    }

    unless (((system "$cmds{'perl'} -c $USRBIN_DIR/fwknop")>>8) == 0) {
        die "[*] $USRBIN_DIR/fwknop does not compile with \"perl -c\".  ",
            "Download the latest sources ",
            "from:\n\nhttp://www.cipherdyne.org/\n";
    }


    if ($client_install) {
        print
"\n[+] fwknop has been installed at $USRBIN_DIR/fwknop.  Since this is a\n",
"    client-only install, the man pages could not be installed.  For more\n",
"    information about how to use fwknop, execute \"$USRBIN_DIR/fwknop -h\" or\n",
"    refer to:\n\n",
"        http://www.cipherdyne.org/fwknop/docs/manpages/index.html\n\n";

    } else {

        ### install config and access files
        for my $file qw(fwknop.conf access.conf pf.os) {
            if (-e "$config{'FWKNOP_CONF_DIR'}/$file") {
                &archive("$config{'FWKNOP_CONF_DIR'}/$file");
                if ($preserve_rv) {
                    if ($file eq 'access.conf') {
                        ### access.conf can have missing fields (i.e.
                        ### REQUIRE_OS_REGEX and REQUIRE_USERNAME),
                        ### and also it can have multiple sequences
                        ### defined.  Hence we just use the old one.
                        print "[+] Using original access.conf\n";
                    } elsif ($file ne 'pf.os') {
                        &preserve_config($file);
                    }
                } else {
                    print "[+] Copying $file -> $config{'FWKNOP_CONF_DIR'}\n";
                    copy $file, $config{'FWKNOP_CONF_DIR'} or
                        die "[*] Could not cp $file to $config{'FWKNOP_CONF_DIR'}";
                }
            } else {
                print "[+] Copying $file -> $config{'FWKNOP_CONF_DIR'}\n";
                copy $file, $config{'FWKNOP_CONF_DIR'} or
                    die "[*] Could not cp $file to $config{'FWKNOP_CONF_DIR'}";
            }

            if ($force_path_update or not $preserve_rv) {
                &update_command_paths("$config{'FWKNOP_CONF_DIR'}/$file")
                    if ($file eq 'fwknop.conf');
            }

            if ($file eq 'fwknop.conf') {
                &set_hostname("$config{'FWKNOP_CONF_DIR'}/$file");
            }
            chmod 0600, "$config{'FWKNOP_CONF_DIR'}/$file" or die
                "[*] Could not chmod(600, $config{'FWKNOP_CONF_DIR'}/$file: $!";
            chown 0, 0, "$config{'FWKNOP_CONF_DIR'}/$file" or die
                "[*] Could not chown 0,0, $config{'FWKNOP_CONF_DIR'}/$file: $!";
        }

        ### get data acquisition method (e.g. syslogd, sysylog-ng, ulogd
        ### or pcap)
        $data_method = &query_data_method();

        if ($data_method =~ /syslog/) {

            &syslog_reconfig() if $install_syslog_fifo;

        } elsif ($data_method =~ /pcap/i or $data_method =~ /ulog/i) {

            if ($os_type == $OS_BSD or $os_type == $OS_DARWIN) {
                ### update to use the ipfw firewall on *BSD systems
                &put_string('FIREWALL_TYPE', 'ipfw',
                    "$config{'FWKNOP_CONF_DIR'}/fwknop.conf");
            }

            ### we are using a pcap method
            if ($data_method eq 'ulogd' or $data_method eq 'file_pcap') {
                print
"[+] By default, fwknop uses the file /var/log/sniff.pcap in order to\n",
"    acquire packet data logged via a sniffer (or ulogd) to a pcap file,\n",
"    but this path may be changed by altering the PCAP_PKT_FILE keyword\n",
"    in $config{'FWKNOP_CONF_DIR'}/fwknop.conf.\n\n";

                if ($data_method eq 'file_pcap') {
                    &put_string('AUTH_MODE', 'FILE_PCAP',
                        "$config{'FWKNOP_CONF_DIR'}/fwknop.conf");
                } else {
                    &put_string('AUTH_MODE', 'ULOG_PCAP',
                        "$config{'FWKNOP_CONF_DIR'}/fwknop.conf");
                }
            } else {
                unless ($sniff_interface) {
                    $sniff_interface = &get_pcap_intf();
                }
                if ($sniff_interface) {
                    &put_string('PCAP_INTF', $sniff_interface,
                        "$config{'FWKNOP_CONF_DIR'}/fwknop.conf");
                } else {
print "[-] Could not get sniffing interface, edit the PCAP_INTF var in\n",
    "    config{'FWKNOP_CONF_DIR'}/fwknop.conf\n";
                }
            }
        } else {
            ### it is a client-only install, so don't reconfigure syslog
            ### or anything.
        }

        unless ($preserve_rv) {
            my $email_str = &query_email();
            if ($email_str) {
                for my $file qw(fwknop.conf) {
                    &put_string('EMAIL_ADDRESSES', $email_str,
                        "$config{'FWKNOP_CONF_DIR'}/$file");
                }
            }
        }


        if ($client_install) {
            print "\n[+] fwknop has been installed!\n\n";
        } else {

            &get_init_dir();
            if (-d $init_dir) {
                &enable_fwknop_at_boot($distro);
            }

            print "\n[+] fwknop has been installed!";

            if ($os_type == $OS_LINUX) {
                print "  To start in server mode, run\n\n",
                    "    \"$init_dir/$init_name start\"\n\n";
            } else {
                print "\n\n";
            }
            print
"    You may want to consider running the fwknop test suite in the test/\n",
"    directory to ensure that fwknop will function correctly on your system.\n\n",

"    Note: You will need to edit $config{'FWKNOP_CONF_DIR'}/access.conf for fwknop to\n",
"    function properly in server mode.  More information can be found in\n",
"    the fwknopd(8) manpage.\n\n";
            if ($os_type == $OS_BSD or $os_type == $OS_DARWIN) {
                print
"    You may need to update your /etc/syslog.conf file to log local info\n",
"    messages to a file in the /var/log/ directory in order to see syslog\n",
"    messages from the fwknop daemons.\n\n";
            }
        }
    }
    return;
}

sub syslog_reconfig() {

    ### create the named pipe
    unless (-e $config{'KNOPMD_FIFO'} and -p $config{'KNOPMD_FIFO'}) {
        unlink $config{'KNOPMD_FIFO'} if -e $config{'KNOPMD_FIFO'};
        print "[+] Creating named pipe $config{'KNOPMD_FIFO'}\n";
        my $created_pipe = 1;
        unless (((system "$cmds{'mknod'} -m 600 $config{'KNOPMD_FIFO'} p")>>8)
                == 0) {
            $created_pipe = 0;
        }
        unless (-e $config{'KNOPMD_FIFO'} and -p $config{'KNOPMD_FIFO'}) {
            $created_pipe = 0;
        }
        unless ($created_pipe) {
            die
"[*] Could not create the named pipe \"$config{'KNOPMD_FIFO'}\"!\n",
"[*] fwknop requires this file to exist!  Aborting install.\n";
        }
    }

    unless (-e "$config{'FW_DATA_FILE'}") {
        print "[+] Creating $config{'FW_DATA_FILE'} file\n";
        open F, "> $config{'FW_DATA_FILE'}" or die "[*] Could not open ",
            "$config{'FW_DATA_FILE'}: $!";
        close F;
        &perms_ownership("$config{'FW_DATA_FILE'}", 0600);
    }

    ### we are acquiring data via syslog
    &put_string('AUTH_MODE', 'KNOCK',
        "$config{'FWKNOP_CONF_DIR'}/fwknop.conf");

    if ($os_type == $OS_BSD or $os_type == $OS_DARWIN) {
        ### update to use the ipfw firewall on *BSD systems
        &put_string('FIREWALL_TYPE', 'ipfw',
            "$config{'FWKNOP_CONF_DIR'}/fwknop.conf");
    }

    &put_string('SYSLOG_DAEMON', $data_method,
        "$config{'FWKNOP_CONF_DIR'}/fwknop.conf");

    my $restarted_syslog = 0;
    if ($data_method eq 'syslogd') {
        if (-e $syslog_conf) {
            &append_fifo_syslog($syslog_conf);
            if (((system "$cmds{'killall'} -HUP syslogd " .
                    "2> /dev/null")>>8) == 0) {
                print "[+] HUP signal sent to syslogd.\n";
                $restarted_syslog = 1;
            }
        }
    } elsif ($data_method eq 'syslog-ng') {
        if (-e $syslog_conf) {
            &append_fifo_syslog_ng($syslog_conf);
            if (((system "$cmds{'killall'} -HUP syslog-ng " .
                    "2> /dev/null")>>8) == 0) {
                print "[+] HUP signal sent to syslog-ng.\n";
                $restarted_syslog = 1;
            }
        }
    }

    unless ($restarted_syslog) {
        print "[-] Could not restart any syslog daemons.\n";
    }
    return;
}

sub uninstall() {

    print "[+] Uninstalling fwknop...\n";

    ### stop any running fwknop daemons.
    &stop_fwknop();

    ### get the init directory
    &get_init_dir();

    for my $daemon qw(fwknopd knopmd knopwatchd knoptm fwknop_serv) {
        unlink "$USRSBIN_DIR/$daemon" if -e "$USRSBIN_DIR/$daemon";
    }
    unlink "$USRBIN_DIR/fwknop" if -e "$USRBIN_DIR/fwknop";
    unlink "$init_dir/$init_name" if -e "$init_dir/$init_name";
    rmtree $config{'FWKNOP_CONF_DIR'}, 1, 1 if -d $config{'FWKNOP_CONF_DIR'};
    rmtree $config{'FWKNOP_LIB_DIR'}, 1, 1 if -d $config{'FWKNOP_LIB_DIR'};
    rmtree $config{'FWKNOP_MOD_DIR'}, 1, 1 if -d $config{'FWKNOP_MOD_DIR'};

    return;
}

sub get_init_dir() {
    return if $client_install;

    if ($os_type == $OS_DARWIN) {

        ### Mac OS X init directory for user programs
        $init_dir = '/Library/StartupItems';
        die "[*] The $init_dir directory does not exist."
            unless -d $init_dir;
        return;
    }

    ### accommodates Linux and BSD systems
    unless (-d $init_dir) {
        if (-d '/etc/rc.d/init.d') {
            $init_dir = '/etc/rc.d/init.d';
        } elsif (-d '/etc/rc.d') {
            $init_dir = '/etc/rc.d';
        } elsif (-d '/etc/init.d') {
            $init_dir = '/etc/init.d';
        } else {
            die "[*] Cannot find the init script directory, use ",
                "--init-dir <path>\n";
        }
    }
    return;
}

### check paths to commands and attempt to correct if any are wrong.
sub check_commands() {

    return if $client_install;

    if ($os_type == $OS_LINUX or $os_type == $OS_CYGWIN) {
        $exclude_cmds{'ipfw'} = '';
    } else {
        ### we are installing on BSD or Mac OS X
        $exclude_cmds{'iptables'} = '';

        ### the runlevel does not apply here
        $exclude_cmds{'runlevel'} = '';
    }

    CMD: for my $cmd (keys %cmds) {
        unless (-x $cmds{$cmd}) {
            my $found = 0;
            PATH: for my $dir (@cmd_search_paths) {
                if (-x "${dir}/${cmd}") {
                    $cmds{$cmd} = "${dir}/${cmd}";
                    $found = 1;
                    last PATH;
                }
            }
            unless ($found) {
                next CMD if defined $exclude_cmds{$cmd};
                if ($cmd eq 'runlevel') {
                    if ($runlevel > 0) {
                        next CMD;
                    } else {
                        die "[*] Could not find the $cmd command, ",
                            "use --runlevel <N>";
                    }
                }
                die "[*] Could not find $cmd anywhere. ",
                    "Please edit the config section to include the path to ",
                    "$cmd.\n";
            }
        }
        unless (-x $cmds{$cmd}) {
            die "[*] $cmd is located at ",
                "$cmds{$cmd} but is not executable by uid: $<\n"
                unless $client_install;
        }
    }
    return;
}

sub archive() {
    my $file = shift;
    return unless -e $file;
    my $curr_pwd = cwd();
    chdir "$config{'FWKNOP_CONF_DIR'}/archive" or die $!;
    my ($filename) = ($file =~ m|.*/(.*)|);
    my $base = "${filename}.old";
    for (my $i = 5; $i > 1; $i--) {  ### keep five copies of old config files
        my $j = $i - 1;
        unlink "${base}${i}.gz" if -e "${base}${i}.gz";
        move "${base}${j}.gz", "${base}${i}.gz" if -e "${base}${j}.gz";
    }
    print "[+] Archiving $file -> ${base}1\n";
    unlink "${base}1.gz" if -e "${base}1.gz";
    copy $file, "${base}1";   ### move $file into the archive directory
    system "$cmds{'gzip'} ${base}1";
    chdir $curr_pwd or die $!;
    return;
}

sub preserve_config() {
    my $file = shift;

    my %preserved_lines = ();

    open C, "< $file" or die "[*] Could not open $file: $!";
    my @new_lines = <C>;
    close C;

    open CO, "< $config{'FWKNOP_CONF_DIR'}/$file" or die "[*] Could not open ",
        "$config{'FWKNOP_CONF_DIR'}}/$file: $!";
    my @orig_lines = <CO>;
    close CO;

    print "[+] Preserving existing config: $config{'FWKNOP_CONF_DIR'}/$file\n";
    ### write to a tmp file and then move so any running fwknop daemon will
    ### re-import a full config file if a HUP signal is received during
    ### the install.
    open CONF, "> $config{'FWKNOP_CONF_DIR'}/${file}.new" or die "[*] Could not open ",
        "$config{'FWKNOP_CONF_DIR'}/${file}.new: $!";
    for my $new_line (@new_lines) {
        if ($new_line =~ /^\s*#/) {
            print CONF $new_line;  ### take comments from new file.
        } elsif ($new_line =~ /^\s*(\S+)/) {
            my $var = $1;
            my $found = 0;
            my $ctr = 0;
            for my $orig_line (@orig_lines) {
                if ($orig_line =~ /^\s*$var\s/) {
                    next if defined $preserved_lines{$ctr};
                    $preserved_lines{$ctr} = '';
                    print CONF $orig_line;
                    $found = 1;
                    last;
                }
                $ctr++;
            }
            unless ($found) {
                print CONF $new_line;
            }
        } else {
            print CONF $new_line;
        }
    }
    close CONF;
    move "$config{'FWKNOP_CONF_DIR'}/${file}.new",
            "$config{'FWKNOP_CONF_DIR'}/$file" or die "[*] ",
        "Could not move $config{'FWKNOP_CONF_DIR'}/${file}.new -> ",
        "$config{'FWKNOP_CONF_DIR'}/$file: $!";
    return;
}

sub append_fifo_syslog() {
    print "[+] Modifying /etc/syslog.conf to write kern.info messages to\n",
        "    $config{'KNOPMD_FIFO'}\n";
    unless (-e '/etc/syslog.conf.orig') {
        copy '/etc/syslog.conf', '/etc/syslog.conf.orig';
    }
    &archive('/etc/syslog.conf');
    open RS, '< /etc/syslog.conf' or
        die "[*] Unable to open /etc/syslog.conf: $!\n";
    my @slines = <RS>;
    close RS;
    open SYSLOG, '> /etc/syslog.conf' or
        die "[*] Unable to open /etc/syslog.conf: $!\n";
    for my $line (@slines) {
        unless ($line =~ /fwknopfifo/) {
            print SYSLOG $line;
        }
    }
    ### reinstate kernel logging to our named pipe
    print SYSLOG '### Send kern.info messages to fwknopfifo for ',
        "analysis by knopmd\n",
        "kern.info\t\t|$config{'KNOPMD_FIFO'}\n";
    close SYSLOG;
    return;
}

sub append_fifo_syslog_ng() {
    print "[+] Modifying /etc/syslog-ng/syslog-ng.conf to write kern.info ",
        "messages to\n";
    print "    $config{'KNOPMD_FIFO'}\n";
    unless (-e '/etc/syslog-ng/syslog-ng.conf.orig') {
        copy '/etc/syslog-ng/syslog-ng.conf',
            '/etc/syslog-ng/syslog-ng.conf.orig';
    }
    &archive('/etc/syslog-ng/syslog-ng.conf');
    open RS, '< /etc/syslog-ng/syslog-ng.conf' or
        die "[*]  Unable to open /etc/syslog-ng/syslog-ng.conf: $!\n";
    my @slines = <RS>;
    close RS;

    my $found_fifo = 0;
    for my $line (@slines) {
        $found_fifo = 1 if ($line =~ /fwknopfifo/);
    }

    unless ($found_fifo) {
        open SYSLOGNG, '>> /etc/syslog-ng/syslog-ng.conf' or
            die "[*] Unable to open /etc/syslog-ng/syslog-ng.conf: $!\n";
        print SYSLOGNG "\n",
            "destination fwknoppipe { pipe(\"/var/lib/fwknop/fwknopfifo\"); };\n",
            "filter f_kerninfo { facility(kern) and level(info); };\n",
            "log { source(src); filter(f_kerninfo); destination(fwknoppipe); };\n";
        close SYSLOGNG;
    }
    return;
}

sub check_non_root_user() {

    unless ($< == 0 && $> == 0) {

        print
"[+] It looks like you are installing fwknop as a non-root user.  This will\n",
"    result in fwknop being installed in your local home directory.\n",
"    If you want fwknop to act as a server (i.e. monitor the network for\n",
"    Single Packet Authorization activity and modify firewall access or\n",
"    execute commands accordingly), you will need to install as root.\n\n";

        $client_install = 1;
    }
    return;
}

sub get_os() {

    ### This function implements a set of simple heuristics to determine
    ### the OS type.  Note that the user can always just set the OS from
    ### the command line with --OS-type

    ### get OS output from uname
    open UNAME, 'uname |' or die "[*] Could not execute 'uname', use ",
        "--OS-type.";
    while (<UNAME>) {

        if (/Darwin/) {

            print
"[+] It looks like you are installing fwknop on a Mac OS X system.\n",
"    Installation of iptables perl modules will be skipped.\n";
            $os_type = $OS_DARWIN;

        } elsif (/[a-z]BSD/) {

            print
"[+] It looks like you are installing fwknop on a *BSD system. Installation\n",
"    of iptables perl modules will be skipped.\n";
            $os_type = $OS_BSD;
        }
        last;
    }
    close UNAME;

    unless ($os_type) {
        ### 'uname -o' does not work on Mac OS X or FreeBSD, so we had to check
        ### for this above

        open UNAME, 'uname -o |' or die "[*] Could not execute 'uname -o', ",
            "use --OS-type.";
        while (<UNAME>) {

            if (/Cygwin/ or /Gygwin/) {

                print
"[+] It looks like you are installing fwknop in a Cygwin environment, so the\n",
"    fwknop client will be installed (the fwknopd server does not yet\n",
"    function with a Windows-based firewall).\n\n";

                $client_install = 1;
                $os_type = $OS_CYGWIN;
            }
            last;
        }
        close UNAME;
    }

    ### default to Linux
    $os_type = $OS_LINUX unless $os_type;

    unless ($client_install) {

        my $have_iptables = 0;
        $have_iptables = 1 if (-e '/usr/sbin/iptables' or -e '/sbin/iptables');

        if ($os_type == $OS_LINUX) {
            unless ($have_iptables) {
                die "[*] iptables does not seem to be installed, ",
                    "use --OS-type.";
            }
        } elsif ($os_type == $OS_BSD or $os_type == $OS_DARWIN) {
            if ($have_iptables) {
                die "[*] iptables exists on what looks like a non-Linux ",
                    "system, use --OS-type.";
            }
        }
    }
    return;
}

sub get_linux_distro() {
    return 'gentoo' if -e '/etc/gentoo-release';
    if (-e '/etc/issue') {
        ### Red Hat Linux release 6.2 (Zoot)
        open ISSUE, '< /etc/issue' or
            die "[*] Could not open /etc/issue: $!";
        my @lines = <ISSUE>;
        close ISSUE;
        for my $line (@lines) {
            chomp $line;
            return 'redhat' if $line =~ /red\s*hat/i;
            return 'fedora' if $line =~ /fedora/i;
            return 'ubuntu' if $line =~ /ubuntu/i;
        }
    }
    return 'NA';
}

sub install_manpage() {
    my $manpage = shift;

    ### default location to put man pages, but check with
    ### /etc/man.config
    my $mpath = '/usr/share/man/man8';
    if (-e '/etc/man.config') {
        ### prefer to install $manpage in /usr/local/man/man8 if
        ### this directory is configured in /etc/man.config
        open M, '< /etc/man.config' or
            die "[*] Could not open /etc/man.config: $!";
        my @lines = <M>;
        close M;
        ### prefer the path "/usr/share/man"
        my $found = 0;
        for my $line (@lines) {
            chomp $line;
            if ($line =~ m|^MANPATH\s+/usr/share/man|) {
                $found = 1;
                last;
            }
        }
        ### try to find "/usr/local/man" if we didn't find /usr/share/man
        unless ($found) {
            for my $line (@lines) {
                chomp $line;
                if ($line =~ m|^MANPATH\s+/usr/local/man|) {
                    $mpath = '/usr/local/man/man8';
                    $found = 1;
                    last;
                }
            }
        }
        ### if we still have not found one of the above man paths,
        ### just select the first one out of /etc/man.config
        unless ($found) {
            for my $line (@lines) {
                chomp $line;
                if ($line =~ m|^MANPATH\s+(\S+)|) {
                    $mpath = $1;
                    last;
                }
            }
        }
    }
    mkdir $mpath, 0755 unless -d $mpath;
    my $mfile = "${mpath}/${manpage}";
    print "[+] Installing $manpage man page at $mfile\n";
    copy $manpage, $mfile or die "[*] Could not copy $manpage to ",
        "$mfile: $!";
    &perms_ownership($mfile, 0644);
    print "[+] Compressing manpage $mfile\n";
    ### remove the old one so gzip doesn't prompt us
    unlink "${mfile}.gz" if -e "${mfile}.gz";
    system "$cmds{'gzip'} $mfile";
    return;
}

sub enable_fwknop_at_boot() {
    my $distro = shift;

    if (&query_yes_no("[+] Enable fwknop at boot time ([y]/n)?  ",
            $ACCEPT_YES_DEFAULT)) {

        if ($os_type == $OS_LINUX) {

        } elsif ($os_type == $OS_DARWIN) {
            my $dir = "$init_dir/Fwknop";
            unless (-d $dir) {
                print "[+] mkdir $dir\n";
                mkdir $dir, 0755 or die "[*] Could not mkdir $dir";
            }
            copy "init-scripts/OS_X/Fwknop", $dir or die "[*] Could not ",
                "copy init-scripts/OS_X/Fwknop -> $dir";
            copy "init-scripts/OS_X/StartupParameters.plist", $dir or die "[*] ",
                "Could not copy init-scripts/OS_X/StartupParameters.plist -> $dir";

        } elsif ($os_type == $OS_BSD) {
            print "[+] Copying init-scripts/fwknop-init.freebsd ",
                "-> ${init_dir}/$init_name\n";
            copy "init-scripts/fwknop-init.freebsd", "${init_dir}/$init_name"
                or die "[*] Could not cp fwknop init script to $init_dir: $!";
            &perms_ownership("${init_dir}/$init_name", 0744);
        }

        if ($os_type == $OS_LINUX) {

            my $init_file = '';

            if ($distro eq 'redhat') {
                $init_file = 'fwknop-init.redhat-chkconfig-enable';
            } elsif ($distro eq 'fedora') {
                $init_file = 'fwknop-init.fedora';
            } elsif ($distro eq 'gentoo') {
                $init_file = 'fwknop-init.gentoo';
            } else {
                $init_file = 'fwknop-init.generic';
            }

            copy "init-scripts/$init_file", "${init_dir}/$init_name"
                or die "[*] Could not cp fwknop init script to $init_dir: $!";
            &perms_ownership("${init_dir}/$init_name", 0744);

            if ($distro eq 'redhat' or $distro eq 'fedora') {
                system "$cmds{'chkconfig'} --add $init_name";
            } elsif ($distro eq 'gentoo') {
                system "$cmds{'rc-update'} add $init_name default";
            } elsif ($distro eq 'ubuntu') {
                system "$cmds{'update-rc.d'} $init_name defaults 99";
            } else {

                ### get the current run level
                &get_runlevel();

                if ($runlevel) {
                    ### the link already exists, so don't re-create it
                    if (-d '/etc/rc.d' and -d "/etc/rc.d/rc${runlevel}.d") {
                        unless (-e "/etc/rc.d/rc${runlevel}.d/S99$init_name") {
                            symlink "$init_dir/$init_name",
                                "/etc/rc.d/rc${runlevel}.d/S99$init_name";
                        }
                    } else {
                        print "[-] The /etc/rc.d/rc${runlevel}.d directory does ",
                            "exist, not sure how to enable fwknop at boot time.";
                    }
                }
            }
        }
    }
    return;
}

sub install_perl_module() {
    my $mod_hr = shift;

    chdir $src_dir or die "[*] Could not chdir $src_dir: $!";
    chdir $deps_dir or die "[*] Could not chdir($deps_dir): $!";

    for my $key qw/module force-install client-mode-install mod-dir/ {
        die "[*] Missing $key key in required_perl_modules hash."
            unless defined $mod_hr->{$key};
    }
    my $mod_name = $mod_hr->{'module'};

    if ($client_install) {
        return unless $mod_hr->{'client-mode-install'};
    }

    if ($os_type != $OS_LINUX) {
        return if $mod_name eq 'IPTables::Parse'
            or $mod_name eq 'IPTables::ChainMgr';
    }

    if ($exclude_mod_re and $exclude_mod_re =~ /$mod_name/) {
        print "[+] Excluding installation of $mod_name module.\n";
        return;
    }

    if ($single_module_install and $mod_name !~ /$single_module_install/) {
        print "[+] Excluding installation of $mod_name module.\n";
        return;
    }

    my $version = '(NA)';

    my $mod_dir = $mod_hr->{'mod-dir'};

    if (-e "$mod_dir/VERSION") {
        open F, "< $mod_dir/VERSION" or
            die "[*] Could not open $mod_dir/VERSION: $!";
        $version = <F>;
        close F;
        chomp $version;
    } else {
        print "[-] Warning: VERSION file does not exist in $mod_dir\n";
    }

    my $install_module = 0;

    if ($mod_hr->{'force-install'}
            or $cmdline_force_install) {
        ### install regardless of whether the module may already be
        ### installed (this module may be a CPAN module that has been
        ### modified specifically for this project, or is a dedicated
        ### module for this project).
        $install_module = 1;
    } elsif ($force_mod_re and $force_mod_re =~ /$mod_name/) {
        print "[+] Forcing installation of $mod_name module.\n";
        $install_module = 1;
    } else {
        if (has_perl_module($mod_name)) {
            print "[+] Module $mod_name is already installed in the ",
                "system perl tree, skipping.\n";
        } else {
            ### install the module in the /usr/lib/fwknop directory because
            ### it is not already installed.
            $install_module = 1;
        }
    }

    if ($install_module) {
        unless (-d $config{'FWKNOP_MOD_DIR'}) {
            print "[+] Creating $config{'FWKNOP_MOD_DIR'}\n";
            mkdir $config{'FWKNOP_MOD_DIR'}, 0755
                or die "[*] Could not mkdir $config{'FWKNOP_MOD_DIR'}: $!";
        }
        print "[+] Installing $mod_name $version perl module in ",
            "$config{'FWKNOP_MOD_DIR'}/\n";
        chdir $mod_dir or die "[*] Could not chdir to ",
            "$mod_dir: $!";
        unless (-e 'Makefile.PL') {
            die "[*] Your $mod_name source directory appears to be incomplete!\n",
                "    Download the latest sources from ",
                "http://www.cipherdyne.org\n";
        }
        system "$cmds{'make'} clean" if -e 'Makefile';
        system "$cmds{'perl'} Makefile.PL PREFIX=$config{'FWKNOP_MOD_DIR'} " .
            "LIB=$config{'FWKNOP_MOD_DIR'}";
        system $cmds{'make'};
#        system "$cmds{'make'} test";
        system "$cmds{'make'} install";

        print "\n\n";
    }
    chdir $src_dir or die "[*] Could not chdir $src_dir: $!";
    return;
}

sub set_hostname() {
    my $file = shift;
    if (-e $file) {
        open P, "< $file" or die "[*] Could not open $file: $!";
        my @lines = <P>;
        close P;
        ### replace the "HOSTNAME           CHANGE_ME" line
        open PH, "> $file" or die "[*] Could not open $file: $!";
        for my $line (@lines) {
            chomp $line;
            if ($line =~ /^\s*HOSTNAME(\s+)_?CHANGE.?ME_?/) {
                print PH "HOSTNAME${1}$hostname;\n";
            } else {
                print PH "$line\n";
            }
        }
        close PH;
    } else {
        die "[*] Your source directory appears to be incomplete!  $file ",
            "is missing.\n    Download the latest sources from ",
            "http://www.cipherdyne.org\n";
    }
    return;
}

sub query_preserve_config() {
    print "\n",
"[+] It appears that there is an existing fwknop installation on the system.\n";

    return &query_yes_no("    Would you like to merge the " .
        "config from the existing\n    fwknop installation ([y]/n)?  ",
        $ACCEPT_YES_DEFAULT);
}

sub query_email() {
    my $email_str = '';
    open F, "< $config{'FWKNOP_CONF_DIR'}/fwknop.conf" or die "[*] Could not open ",
        "$config{'FWKNOP_CONF_DIR'}/fwknop.conf: $!";
    my @clines = <F>;
    close F;
    my $email_addresses;
    for my $line (@clines) {
        chomp $line;
        if ($line =~ /^\s*EMAIL_ADDRESSES\s+(.+);/) {
            $email_addresses = $1;
            last;
        }
    }
    unless ($email_addresses) {
        return '';
    }
    print "[+] fwknop access alerts will be sent to:\n\n",
        "       $email_addresses\n\n";

    if ($force_defaults) {
        print "    Setting default [$email_addresses].\n";
        return $email_addresses;
    }

    if (&query_yes_no("[+] Would you like access alerts sent to a " .
                "different address ([y]/n)?  ", $ACCEPT_YES_DEFAULT)) {

        print "\n",
"[+] To which email address(es) would you like fwknop alerts to be sent?\n",
"    You can enter as many email addresses as you like; each on its own line.\n\n",
"    End with a \".\" on a line by itself.\n\n";
        my $ans = '';
        while ($ans !~ /^\s*\.\s*$/) {
            print "    Email Address: ";
            $ans = <STDIN>;
            chomp $ans;
            if ($ans =~ m|^\s*(\S+\@\S+)$|) {
                $email_str .= "$1, ";
            } elsif ($ans !~ /^\s*\.\s*$/) {
                print "[-] Invalid email address \"$ans\"\n";
            }
        }
        $email_str =~ s/\,\s*$//;
    }
    return $email_str;
}

sub ask_to_stop_fwknop() {

    if (&is_fwknop_running()) {
        print "[+] An existing fwknop process is running.\n";

        if (&query_yes_no("    Can I stop the existing fwknop " .
                "process ([y]/n)?  ", $ACCEPT_YES_DEFAULT)) {
            return 1;
        } else {
            die "[*] Aborting install (you can run ./install.pl again).";
        }

    }
    return 0;
}

sub is_fwknop_running() {
    for my $pid_file ($config{'FWKNOP_PID_FILE'},
            $config{'KNOPTM_PID_FILE'},
            $config{'KNOPMD_PID_FILE'},
            $config{'TCPSERV_PID_FILE'}) {

        next unless -e $pid_file;
        open P, "< $pid_file" or die "[*] Could not open $pid_file: $!";
        my $pid = <P>;
        close P;
        return 1 if kill 0, $pid;
    }
    return 0;
}

sub stop_fwknop() {

    my $ctr = 0;
    while (&is_fwknop_running()) {

        if (-d $init_dir and -e "$init_dir/$init_name") {
            system "$init_dir/$init_name stop";
        }

        if (&is_fwknop_running()) {
            system "fwknopd -K";
        }

        $ctr++;
        if ($ctr >= 5) {
            print "[-] Could not stop running fwknop processes, ",
                "continuing anyway";
            return;
        }
    }
    return;
}

sub get_pcap_intf() {
    print
"\n[+] It appears that the following network interfaces are attached to the\n",
"    system:\n";
    open IFC, "$cmds{'ifconfig'} -a |" or die "[*] Could not execute ",
        "$cmds{'ifconfig'} -a: $!";
    my @ifconfig_out = <IFC>;
    close IFC;
    my %interfaces = ();
    my $default_intf = '';

    if ($os_type == $OS_BSD or $os_type == $OS_DARWIN) {
        for my $line (@ifconfig_out) {
            if ($line =~ /^\s*(\w+):\s+flags=/) {
                $interfaces{$1} = '';
                print "        $1\n";
                $default_intf = $1 unless $default_intf;
            }
        }
    } else {
        for my $line (@ifconfig_out) {
            if ($line =~ /^\s*(\w+)\s+Link/) {
                $interfaces{$1} = '';
                print "        $1\n";
                $default_intf = $1 unless $default_intf;
            }
        }
    }

    ### return the default interface
    if ($force_defaults) {
        if (defined $interfaces{'eth0'}) {
            $default_intf = 'eth0';
        }
        print "    Setting default [$default_intf]\n";
        return $default_intf;
    }

    my $ans = '';
    my $loop_ctr = 0;
    while (not defined $interfaces{$ans}) {
        print
"    Which network interface would you like fwknop to sniff packets from?  ";
        $ans = <STDIN>;
        chomp $ans;
        $loop_ctr++;
        if ($loop_ctr >= 10) {
            return '';
        }
    }
    return $ans;
}

sub query_data_method() {
    print
"[+] fwknop can act as a server (i.e. monitoring authentication packets\n",
"    and sequences, and taking the appropriate action on the local system\n",
"    to alter the firewall policy or execute commands), or as a client (i.e.\n",
"    by manufacturing authentication packets and sequences).\n\n";
    my $ans = '';

    print
"    In which mode will fwknop be executed on the local system?  (Note that\n",
"    fwknop can still be used as a client even if you select \"server\" here).\n";

    if ($force_defaults) {
        print "    Setting default [server] mode.\n";
        return 'server';
    }

    while ($ans ne 'client' and $ans ne 'server') {
        print "    (client/[server]): ";
        $ans = <STDIN>;
        if ($ans eq "\n") {
            $ans = 'server';
        }
        $ans =~ s/\s*//g;
    }
    if ($ans eq 'client') {
        $client_install = 1;
        return $ans;
    }

    print
"\n[+] In server mode, fwknop can acquire packet through a pcap file that is\n",
"    generated by a sniffer (or through the Netfilter ulogd pcap writer), or\n",
"    by sniffing packets directly off the wire via the Net::Pcap perl module.\n",
"    Fwknop can also acquire packet data from iptables syslog messages, but\n",
"    this is only supported for the legacy port knocking mode; Single Packet\n",
"    Authorization (SPA), which is used in the pcap modes, is a better\n",
"    authorization strategy from every perspective (see the fwknop man page for\n",
"    more information). If you intend to use iptables log messages (only makes\n",
"    sense for the legacy port knocking mode), then fwknop will need to\n",
"    reconfigure your syslog daemon to write kern.info messages to the\n",
"    $config{'KNOPMD_FIFO'} named pipe. It is highly recommended\n",
"    to use one of the pcap modes unless you really want the old port knocking\n",
"    method.\n\n";

    $ans = '';

    if ($force_defaults) {
        print "    Setting default [pcap] mode.\n";
        return 'pcap';
    }

        print
"    Which of the following data acquistion methods would you like to use?\n";
    while ($ans ne 'syslogd' and $ans ne 'syslog-ng' and $ans ne 'ulogd'
            and $ans ne 'pcap' and $ans ne 'file_pcap') {

        print "    ([pcap], file_pcap, ulogd, syslogd, syslog-ng): ";
        $ans = <STDIN>;

        return 'pcap' if $ans eq "\n";
        $ans =~ s/\s*//g;

        if ($ans eq 'syslogd' or $ans eq 'syslog-ng') {
            if ($ans eq 'syslogd') {
                ### allow command line --syslog-conf arg to take over
                $syslog_conf = '/etc/syslog.conf' unless $syslog_conf;
            } elsif ($ans eq 'syslog-ng') {
                ### allow command line --syslog-conf arg to take over
                $syslog_conf = '/etc/syslog-ng/syslog-ng.conf' unless $syslog_conf;
            }
            if ($syslog_conf and not -e $syslog_conf) {
                die
"[-] The config file $syslog_conf does not exist. Re-run install.pl\n",
"    with the --syslog-conf argument to specify the path to the syslog\n",
"    daemon config file.\n";
            }
        }
        print "[-] Invalid acquistion method \"$ans\"\n"
        unless ($ans and
            ($ans eq 'syslogd' or $ans eq 'syslog-ng'
            or $ans eq 'file_pcap' or $ans eq 'ulogd' or $ans eq 'pcap'));
    }
    return $ans;
}

sub put_string() {
    my ($var, $value, $file) = @_;
    open RF, "< $file" or die "[*] Could not open $file: $!";
    my @lines = <RF>;
    close RF;
    open F, "> $file" or die "[*] Could not open $file: $!";
    for my $line (@lines) {
        if ($line =~ /^\s*$var\s+.*;/) {
            printf F "%-28s%s;\n", $var, $value;
        } else {
            print F $line;
        }
    }
    close F;
    return;
}

sub perms_ownership() {  ### only gets called in full-installation mode
    my ($file, $perm_value) = @_;
    chmod $perm_value, $file or die "[*] Could not ",
        "chmod($perm_value, $file): $!";
    ### root (maybe should take the group assignment out?)
    chown 0, 0, $file or die "[*] Could not chown 0,0,$file: $!";
    return;
}

sub has_perl_module() {
    my $module = shift;

    # 5.8.0 has a bug with require Foo::Bar alone in an eval, so an
    # extra statement is a workaround.
    my $file = "$module.pm";
    $file =~ s{::}{/}g;
    eval { require $file };

    return $@ ? 0 : 1;
}

sub update_command_paths() {
    my $file = shift;

    open F, "< $file" or die "[*] Could not open file: $!";
    my @lines = <F>;
    close F;

    my @newlines = ();
    my $new_cmd = 0;
    CMD: for my $line (@lines) {
        my $found = 0;
        if ($line =~ /^\s*(\w+)Cmd(\s+)(\S+);/) {
            my $cmd    = $1;
            my $spaces = $2;
            my $path   = $3;
            unless (-e $path and -x $path) {
                ### the command is not at this path, try to find it
                my $cmd_minor_name = $cmd;
                if ($path =~ m|.*/(\S+)|) {
                    $cmd_minor_name = $cmd if $cmd ne $1;
                }
                DIR: for my $dir (@cmd_search_paths) {
                    if (-e "$dir/$cmd_minor_name"
                            and -x "$dir/$cmd_minor_name") {
                        ### found the command
                        push @newlines,
                            "${cmd}Cmd${spaces}${dir}/${cmd_minor_name};\n";
                        $found   = 1;
                        $new_cmd = 1;
                        last DIR;
                    }
                }
                unless ($found) {
                    next CMD if ($cmd eq 'iptables' and $os_type != $OS_LINUX);
                    next CMD if ($cmd eq 'ipfw' and $os_type == $OS_LINUX);
                    print
"[-] Could not find the path to the $cmd command, you will need to manually\n",
"    edit the path for the ${cmd}Cmd variable in $file\n";
                }
            }
        }
        unless ($found) {
            push @newlines, $line;
        }
    }
    if ($new_cmd) {
        open C, "> $file" or die "[*] Could not open file: $!";
        print C for @newlines;
        close C;
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

    ### resolve internal vars within variable values
    &expand_vars();

    &required_vars();

    return;
}

sub expand_vars() {

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
                            "config for var: $var."
                    }
                    $has_sub_var = 1;
                }
            }
        }
    }
    return;
}

sub handle_cmd_line() {
    if ($bsd_install and $cygwin_install) {
        die "[*] Cannot use --BSD-install and --Cygwin-install at the same time.";
    }

    if ($bsd_install) {

        $os_type = $OS_BSD;

    } elsif ($cygwin_install) {

        $os_type = $OS_CYGWIN;

    } elsif ($cmdline_os_type) {

        my $found = 0;
        for my $type (keys %os_types) {
            if ($cmdline_os_type =~ /$type/i) {
                $os_type = $os_types{$type};
            }
        }
        unless ($found) {
            print "[*] --OS-type accepts the following operating systems:\n";
            for my $type (keys %os_types) {
                print "    $type\n";
            }
            exit 1;
        }
    }

    return;
}

sub get_runlevel() {
    die "[*] The runlevel cannot be greater than 6"
        if $runlevel > 6;

    return if $runlevel > 0;

    open RUN, "$cmds{'runlevel'} |" or die "[*] Could not execute the runlevel ",
        "command, use --runlevel <N>";
    while (<RUN>) {
        if (/^\s*\S+\s+(\d+)/) {
            $runlevel = $1;
            last;
        }
    }
    close RUN;
    return;
}

sub required_vars() {
    my @vars = qw(
        FWKNOP_DIR FWKNOP_RUN_DIR FWKNOP_LIB_DIR KNOPMD_FIFO FWKNOP_PID_FILE
        FWKNOP_CONF_DIR FW_DATA_FILE FWKNOP_MOD_DIR
    );
    for my $var (@vars) {
        die "[*] Missing required var: $var in $fwknop_conf_file"
            unless defined $config{$var};
    }
    return;
}

sub query_yes_no() {
    my ($msg, $style) = @_;
    my $ans = '';

    if ($force_defaults) {
        if ($style == $ACCEPT_YES_DEFAULT or $style == $NO_ANS_DEFAULT) {
            print "    Setting default [y]\n";
            return 1;
        } elsif ($ACCEPT_NO_DEFAULT) {
            print "    Setting default [n]\n";
            return 0;
        }
    }

    while ($ans ne 'y' and $ans ne 'n') {
        print $msg;
        $ans = lc(<STDIN>);
        if ($style == $ACCEPT_YES_DEFAULT) {
            return 1 if $ans eq "\n";
        } elsif ($style == $ACCEPT_NO_DEFAULT) {
            return 0 if $ans eq "\n";
        }
        chomp $ans;
    }
    return 1 if $ans eq 'y';
    return 0;
}

sub usage() {
    my $exit_status = shift;
    print <<_HELP_;

Usage: install.pl [options]

    -c, --client-only         - Only install fwknop client.
    -u, --uninstall           - Uninstall fwknop.
    -O, --OS-type <OS>        - Specify installation target OS (e.g.
                                "linux", "cygwin", or "darwin").
    --Single-mod-install <re> - Install a particular perl module.
    --force-mod-install       - Force all perl modules to be installed
                                even if some already exist in the system
                                /usr/lib/perl5 tree.
    --Force-mod-regex <re>    - Specify a regex to match a module name
                                and force the installation of such modules.
    -D, --Defaults            - Force all default values without asking.
    -p, --path-update         - Run path update code regardless of whether
                                a previous config is being merged.
    --interface <intf>        - Manually specify an interface to sniff
                                from.
    --init-dir <path>         - Specify path to the init directory (the
                                default is $init_dir).
    --init-name <name>        - Specify the name for the fwknop init
                                script (the default is $init_name).
    -r, --runlevel <N>        - Specify the current system runlevel.
    --Skip-mod-install        - Do not install any perl modules.
    -s, --syslog <file>       - Specify path to syslog.conf file.
    -L, --LANG <locale>       - Specify LANG env variable (actually the
                                LC_ALL variable).
    -n, --no-LANG             - Do not export the LANG env variable.
    -H, --Home-dir <dir>      - Manually specify the home directory for
                                client-mode installs.
    -h  --help                - Prints this help message.

_HELP_
    exit $exit_status;
}
