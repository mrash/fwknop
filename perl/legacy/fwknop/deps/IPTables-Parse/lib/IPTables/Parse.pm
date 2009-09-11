#
##################################################################
#
# File: IPTables::Parse.pm
#
# Purpose: Perl interface to parse iptables rulesets.
#
# Author: Michael Rash (mbr@cipherdyne.org)
#
# Version: 0.7
#
##################################################################
#
# $Id: Parse.pm 1309 2008-10-18 04:06:37Z mbr $
#

package IPTables::Parse;

use 5.006;
use POSIX ":sys_wait_h";
use Carp;
use strict;
use warnings;
use vars qw($VERSION);

$VERSION = '0.7';

sub new() {
    my $class = shift;
    my %args  = @_;

    my $self = {
        _iptables => $args{'iptables'} || '/sbin/iptables',
        _iptout    => $args{'iptout'}    || '/tmp/ipt.out',
        _ipterr    => $args{'ipterr'}    || '/tmp/ipt.err',
        _ipt_alarm => $args{'ipt_alarm'} || 30,
        _debug     => $args{'debug'}     || 0,
        _verbose   => $args{'verbose'}   || 0,
        _ipt_exec_style => $args{'ipt_exec_style'} || 'waitpid',
        _ipt_exec_sleep => $args{'ipt_exec_sleep'} || 0,
        _sigchld_handler => $args{'sigchld_handler'} || \&REAPER,
    };
    croak "[*] $self->{'_iptables'} incorrect path.\n"
        unless -e $self->{'_iptables'};
    croak "[*] $self->{'_iptables'} not executable.\n"
        unless -x $self->{'_iptables'};
    bless $self, $class;
}

sub chain_policy() {
    my $self   = shift;
    my $table  = shift || croak '[*] Specify a table, e.g. "nat"';
    my $chain  = shift || croak '[*] Specify a chain, e.g. "OUTPUT"';
    my $file   = shift || '';
    my $iptables  = $self->{'_iptables'};
    my @ipt_lines = ();

    if ($file) {
        ### read the iptables rules out of $file instead of executing
        ### the iptables command.
        open F, "< $file" or croak "[*] Could not open file $file: $!";
        @ipt_lines = <F>;
        close F;
    } else {
        my ($rv, $out_ar, $err_ar) = $self->exec_iptables(
                "$iptables -t $table -v -n -L $chain");
        @ipt_lines = @$out_ar;
    }

    my $policy = '';

    for my $line (@ipt_lines) {
        ### Chain INPUT (policy ACCEPT 16 packets, 800 bytes)
        if ($line =~ /^\s*Chain\s+$chain\s+\(policy\s+(\w+)/) {
            $policy = $1;
            last;
        }
    }

    return $policy;
}

sub chain_action_rules() {
    return &chain_rules();
}

sub chain_rules() {
    my $self   = shift;
    my $table  = shift || croak '[*] Specify a table, e.g. "nat"';
    my $chain  = shift || croak '[*] Specify a chain, e.g. "OUTPUT"';
    my $file   = shift || '';
    my $iptables  = $self->{'_iptables'};

    my $found_chain  = 0;
    my @ipt_lines = ();
    my $ip_re = qr|(?:[0-2]?\d{1,2}\.){3}[0-2]?\d{1,2}|;

    ### array of hash refs
    my @chain = ();
    my @global_accept_state = ();

    if ($file) {
        ### read the iptables rules out of $file instead of executing
        ### the iptables command.
        open F, "< $file" or croak "[*] Could not open file $file: $!";
        @ipt_lines = <F>;
        close F;
    } else {
        my ($rv, $out_ar, $err_ar) = $self->exec_iptables(
                "$iptables -t $table -v -n -L $chain");
        @ipt_lines = @$out_ar;
    }

    ### determine the output style (e.g. "-nL -v" or just plain "-nL"; if the
    ### policy data came from a file then -v might not have been used)
    my $ipt_verbose = 0;
    for my $line (@ipt_lines) {
        if ($line =~ /^\s*pkts\s+bytes\s+target/) {
            $ipt_verbose = 1;
            last;
        }
    }

    LINE: for my $line (@ipt_lines) {
        chomp $line;

        last LINE if ($found_chain and $line =~ /^\s*Chain\s+/);

        if ($line =~ /^\s*Chain\s+$chain\s+\(/i) {
            $found_chain = 1;
            next LINE;
        }
        if ($ipt_verbose) {
            next LINE if $line =~ /^\s*pkts\s+bytes\s+target\s/i;
        } else {
            next LINE if $line =~ /^\s*target\s+prot/i;
        }
        next LINE unless $found_chain;

        ### initialize hash
        my %rule = (
            'packets'  => '',
            'bytes'    => '',
            'target'   => '',
            'protocol' => '',
            'proto'    => '',
            'intf_in'  => '',
            'intf_out' => '',
            'src'      => '',
            's_port'   => '',
            'sport'    => '',
            'dst'      => '',
            'd_port'   => '',
            'dport'    => '',
            'to_ip'    => '',
            'to_port'  => '',
            'extended' => '',
            'state'    => '',
            'raw'      => $line
        );

        if ($ipt_verbose) {
            ### 0     0 ACCEPT  tcp  --  eth1 * 192.168.10.3  0.0.0.0/0  tcp dpt:80
            ### 0     0 ACCEPT  tcp  --  eth1 * 192.168.10.15 0.0.0.0/0  tcp dpt:22
            ### 33 2348 ACCEPT  tcp  --  eth1 * 192.168.10.2  0.0.0.0/0  tcp dpt:22
            ### 0     0 ACCEPT  tcp  --  eth1 * 192.168.10.2  0.0.0.0/0  tcp dpt:80
            ### 0     0 DNAT    tcp  --  *    * 123.123.123.123 0.0.0.0/0 tcp dpt:55000 to:192.168.12.12:80
            if ($line =~ m|^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\-\-\s+
                                (\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)|x) {
                $rule{'packets'}  = $1;
                $rule{'bytes'}    = $2;
                $rule{'target'}   = $3;

                my $proto = $4;
                $proto = 'all' if $proto eq '0';
                $rule{'protocol'} = $rule{'proto'} = $4;
                $rule{'intf_in'}  = $5;
                $rule{'intf_out'} = $6;
                $rule{'src'}      = $7;
                $rule{'dst'}      = $8;
                $rule{'extended'} = $9;

                if ($proto eq 'all') {
                    $rule{'s_port'} = $rule{'sport'} = '0:0';
                    $rule{'d_port'} = $rule{'dport'} = '0:0';
                }
                if ($rule{'extended'}) {
                    if ($rule{'protocol'} eq 'tcp'
                            or $rule{'protocol'} eq 'udp') {
                        my $s_port  = '0:0';  ### any to any
                        my $d_port  = '0:0';
                        if ($rule{'extended'} =~ /dpts?:(\S+)/) {
                            $d_port = $1;
                        }
                        if ($rule{'extended'} =~ /spts?:(\S+)/) {
                            $s_port = $1;
                        }
                        $rule{'s_port'} = $rule{'sport'} = $s_port;
                        $rule{'d_port'} = $rule{'dport'} = $d_port;
                        if ($rule{'extended'} =~ /\sto:($ip_re):(\d+)/) {
                            $rule{'to_ip'}   = $1;
                            $rule{'to_port'} = $2;
                        }

                        for my $state_hr (@global_accept_state) {
                            next unless $state_hr->{'src'} eq '0.0.0.0/0';
                            next unless $state_hr->{'dst'} eq '0.0.0.0/0';
                            next unless $state_hr->{'proto'} eq 'all' or
                                $state_hr->{'proto'} = $rule{'proto'};
                            next unless $state_hr->{'intf_in'} eq '*' or
                                $state_hr->{'intf_in'} eq $rule{'intf_in'};
                            next unless $state_hr->{'intf_out'} eq '*' or
                                $state_hr->{'intf_out'} eq $rule{'intf_out'};
                            ### if we make it here, then the state rule
                            ### applies to this rule
                            $rule{'state'} = $state_hr->{'state'};
                        }
                    }
                    if ($rule{'target'} eq 'ACCEPT'
                            and $rule{'extended'} =~ m|^state\s+(\S+)|) {
                        my $state_str = $1;
                        if ($state_str =~ /ESTABLISHED/
                                or $state_str =~ /RELATED/) {

                            push @global_accept_state, {
                                'state'    => $state_str,
                                'src'      => $rule{'src'},
                                'dst'      => $rule{'dst'},
                                'intf_in'  => $rule{'intf_in'},
                                'intf_out' => $rule{'intf_out'},
                                'proto'    => $rule{'protocol'}
                            };
                            my %state_hash = ();
                        }
                    }
                }
            }
        } else {
            ### ACCEPT tcp  -- 164.109.8.0/24  0.0.0.0/0  tcp dpt:22 flags:0x16/0x02
            ### ACCEPT tcp  -- 216.109.125.67  0.0.0.0/0  tcp dpts:7000:7500
            ### ACCEPT udp  -- 0.0.0.0/0       0.0.0.0/0  udp dpts:7000:7500
            ### ACCEPT udp  -- 0.0.0.0/0       0.0.0.0/0  udp dpt:!7000
            ### ACCEPT icmp --  0.0.0.0/0      0.0.0.0/0
            ### ACCEPT tcp  --  0.0.0.0/0      0.0.0.0/0  tcp spt:35000 dpt:5000
            ### ACCEPT tcp  --  10.1.1.1       0.0.0.0/0

            ### LOG  all  --  0.0.0.0/0  0.0.0.0/0  LOG flags 0 level 4 prefix `DROP '
            ### LOG  all  --  127.0.0.2  0.0.0.0/0  LOG flags 0 level 4
            ### ### DNAT tcp  --  123.123.123.123  0.0.0.0/0  tcp dpt:55000 to:192.168.12.12:80

            if ($line =~ m|^\s*(\S+)\s+(\S+)\s+\-\-\s+(\S+)\s+(\S+)\s*(.*)|) {
                $rule{'target'}   = $1;
                my $proto = $2;
                $proto = 'all' if $proto eq '0';
                $rule{'protocol'} = $rule{'proto'} = $proto;
                $rule{'src'}      = $3;
                $rule{'dst'}      = $4;
                $rule{'extended'} = $5;

                if ($proto eq 'all') {
                    $rule{'s_port'} = $rule{'sport'} = '0:0';
                    $rule{'d_port'} = $rule{'dport'} = '0:0';
                }

                if ($rule{'extended'}
                        and ($rule{'protocol'} eq 'tcp'
                        or $rule{'protocol'} eq 'udp')) {
                    my $s_port  = '0:0';  ### any to any
                    my $d_port  = '0:0';
                    if ($rule{'extended'} =~ /dpts?:(\S+)/) {
                        $d_port = $1;
                    }
                    if ($rule{'extended'} =~ /spts?:(\S+)/) {
                        $s_port = $1;
                    }
                    $rule{'s_port'} = $rule{'sport'} = $s_port;
                    $rule{'d_port'} = $rule{'dport'} = $d_port;
                    if ($rule{'extended'} =~ /\sto:($ip_re):(\d+)/) {
                        $rule{'to_ip'}   = $1;
                        $rule{'to_port'} = $2;
                    }
                }
            }
        }
        push @chain, \%rule;
    }
    return \@chain;
}

sub default_drop() {
    my $self  = shift;
    my $table = shift || croak "[*] Specify a table, e.g. \"nat\"";
    my $chain = shift || croak "[*] Specify a chain, e.g. \"OUTPUT\"";
    my $file  = shift || '';
    my $iptables  = $self->{'_iptables'};
    my @ipt_lines = ();

    if ($file) {
        ### read the iptables rules out of $file instead of executing
        ### the iptables command.
        open F, "< $file" or croak "[*] Could not open file $file: $!";
        @ipt_lines = <F>;
        close F;
    } else {
### FIXME -v for interfaces?
        my ($rv, $out_ar, $err_ar) = $self->exec_iptables(
                "$iptables -t $table -n -L $chain");
        @ipt_lines = @$out_ar;
    }

    return '[-] Could not get iptables output!', 0
        unless @ipt_lines;

    my %protocols = ();
    my $found_chain = 0;
    my $rule_ctr = 1;
    my $prefix;
    my $policy = 'ACCEPT';
    my $any_ip_re = '(?:0\.){3}0/0';

    LINE: for my $line (@ipt_lines) {
        chomp $line;

        last if ($found_chain and $line =~ /^\s*Chain\s+/);

        ### Chain INPUT (policy DROP)
        ### Chain FORWARD (policy ACCEPT)
        if ($line =~ /^\s*Chain\s+$chain\s+\(policy\s+(\w+)\)/) {
            $policy = $1;
            $found_chain = 1;
        }
        next LINE if $line =~ /^\s*target\s/i;
        next LINE unless $found_chain;

        ### include ULOG target as well
        if ($line =~ m|^\s*U?LOG\s+(\w+)\s+\-\-\s+.*
            $any_ip_re\s+$any_ip_re\s+(.*)|x) {
            my $proto  = $1;
            my $p_tmp  = $2;
            my $prefix = 'NONE';

            ### some recent iptables versions return "0" instead of "all"
            ### for the protocol number
            $proto = 'all' if $proto eq '0';
            ### LOG flags 0 level 4 prefix `DROP '
            if ($p_tmp && $p_tmp =~ m|LOG.*\s+prefix\s+
                \`\s*(.+?)\s*\'|x) {
                $prefix = $1;
            }
            ### $proto may equal "all" here
            $protocols{$proto}{'LOG'}{'prefix'} = $prefix;
            $protocols{$proto}{'LOG'}{'rulenum'} = $rule_ctr;
        } elsif ($policy eq 'ACCEPT' and $line =~ m|^DROP\s+(\w+)\s+\-\-\s+.*
            $any_ip_re\s+$any_ip_re\s*$|x) {
            my $proto = $1;
            $proto = 'all' if $proto eq '0';
            ### DROP    all  --  0.0.0.0/0     0.0.0.0/0
            $protocols{$1}{'DROP'} = $rule_ctr;
        }
        $rule_ctr++;
    }
    ### if the policy in the chain is DROP, then we don't
    ### necessarily need to find a default DROP rule.
    if ($policy eq 'DROP') {
        $protocols{'all'}{'DROP'} = 0;
    }
    return \%protocols;
}

sub default_log() {
    my $self  = shift;
    my $table = shift || croak "[*] Specify a table, e.g. \"nat\"";
    my $chain = shift || croak "[*] Specify a chain, e.g. \"OUTPUT\"";
    my $file  = shift || '';
    my $iptables  = $self->{'_iptables'};

    my $any_ip_re  = '(?:0\.){3}0/0';
    my @ipt_lines  = ();
    my %log_chains = ();
    my %log_rules  = ();

    ### note that we are not restricting the view to the current chain
    ### with the iptables -nL output; we are going to parse the given
    ### chain and all chains to which packets are jumped from the given
    ### chain.
    if ($file) {
        ### read the iptables rules out of $file instead of executing
        ### the iptables command.
        open F, "< $file" or croak "[*] Could not open file $file: $!";
        @ipt_lines = <F>;
        close F;
    } else {
        my ($rv, $out_ar, $err_ar) = $self->exec_iptables(
                "$iptables -t $table -n -L $chain");
        @ipt_lines = @$out_ar;
    }

    ### determine the output style (e.g. "-nL -v" or just plain "-nL"; if the
    ### policy data came from a file then -v might not have been used)
    my $ipt_verbose = 0;
    for my $line (@ipt_lines) {
        if ($line =~ /^\s*pkts\s+bytes\s+target/) {
            $ipt_verbose = 1;
            last;
        }
    }

    return '[-] Could not get iptables output!', 0
        unless @ipt_lines;

    ### first get all logging rules and associated chains
    my $log_chain;

    for my $line (@ipt_lines) {
        chomp $line;

        ### Chain INPUT (policy DROP)
        ### Chain fwsnort_INPUT_eth1 (1 references)
        if ($line =~ /^\s*Chain\s+(.*?)\s+\(/ and
                $line !~ /0\s+references/) {
            $log_chain = $1;
        }
        $log_chain = '' unless $line =~ /\S/;
        next unless $log_chain;

        my $proto = '';
        my $found = 0;
        if ($ipt_verbose) {
            if ($line =~ m|^\s*\d+\s+\d+\s*U?LOG\s+(\w+)\s+\-\-\s+
                    \S+\s+\S+\s+$any_ip_re
                    \s+$any_ip_re\s+.*U?LOG|x) {
                $proto = $1;
                $found = 1;
            }
        } else {
            if ($line =~ m|^\s*U?LOG\s+(\w+)\s+\-\-\s+$any_ip_re
                    \s+$any_ip_re\s+.*U?LOG|x) {
                $proto = $1;
                $found = 1;
            }
        }

        if ($found) {
            $proto = 'all' if $proto eq '0';
            ### the above regex allows the limit target to be used
            $log_chains{$log_chain}{$proto} = '';  ### protocol
            $log_rules{$proto} = '' if $log_chain eq $chain;
        }
    }

    return '[-] There are no logging rules in the iptables policy!', 0
        unless %log_chains;

    my %sub_chains = ();

    ### get all sub-chains of the main chain we passed into default_log()
    &sub_chains($chain, \%sub_chains, \@ipt_lines);

    ### see which (if any) logging rules can be mapped back to the
    ### main chain we passed in.
    for my $log_chain (keys %log_chains) {
        if (defined $sub_chains{$log_chain}) {
            ### the logging rule is in the main chain (e.g. INPUT)
            for my $proto (keys %{$log_chains{$log_chain}}) {
                $log_rules{$proto} = '';
            }
        }
    }

    return \%log_rules;
}

sub sub_chains() {
    my ($start_chain, $chains_href, $ipt_lines_aref) = @_;
    my $found = 0;
    for my $line (@$ipt_lines_aref) {
        chomp $line;
        ### Chain INPUT (policy DROP)
        ### Chain fwsnort_INPUT_eth1 (1 references)
        if ($line =~ /^\s*Chain\s+$start_chain\s+\(/ and
                $line !~ /0\s+references/) {
            $found = 1;
            next;
        }
        next unless $found;
        if ($found and $line =~ /^\s*Chain\s/) {
            last;
        }
        if ($line =~ m|^\s*(\S+)\s+\S+\s+\-\-|) {
            my $new_chain = $1;
            if ($new_chain ne 'LOG'
                    and $new_chain ne 'DROP'
                    and $new_chain ne 'REJECT'
                    and $new_chain ne 'ACCEPT'
                    and $new_chain ne 'RETURN'
                    and $new_chain ne 'QUEUE'
                    and $new_chain ne 'SNAT'
                    and $new_chain ne 'DNAT'
                    and $new_chain ne 'MASQUERADE') {
                $chains_href->{$new_chain} = '';
                &sub_chains($new_chain, $chains_href, $ipt_lines_aref);
            }
        }
    }
    return;
}

sub exec_iptables() {
    my $self  = shift;
    my $cmd = shift || croak '[*] Must specify an iptables command to run.';
    my $iptables  = $self->{'_iptables'};
    my $iptout    = $self->{'_iptout'};
    my $ipterr    = $self->{'_ipterr'};
    my $debug     = $self->{'_debug'};
    my $ipt_alarm = $self->{'_ipt_alarm'};
    my $verbose   = $self->{'_verbose'};
    my $ipt_exec_style = $self->{'_ipt_exec_style'};
    my $ipt_exec_sleep = $self->{'_ipt_exec_sleep'};
    my $sigchld_handler = $self->{'_sigchld_handler'};

    croak "[*] $cmd does not look like an iptables command."
        unless $cmd =~ m|^\s*iptables| or $cmd =~ m|^\S+/iptables|;

    my $rv = 1;
    my @stdout = ();
    my @stderr = ();

    my $fh = *STDERR;
    $fh = *STDOUT if $verbose;

    if ($debug or $verbose) {
        print $fh localtime() . " [+] IPTables::Parse::",
            "exec_iptables(${ipt_exec_style}()) $cmd\n";
        if ($ipt_exec_sleep > 0) {
            print $fh localtime() . " [+] IPTables::Parse::",
                "exec_iptables() sleep seconds: $ipt_exec_sleep\n";
        }
    }

    if ($ipt_exec_sleep > 0) {
    	if ($debug or $verbose) {
            print $fh localtime() . " [+] IPTables::Parse: ",
                "sleeping for $ipt_exec_sleep seconds before ",
                "executing iptables command.\n";
        }
        sleep $ipt_exec_sleep;
    }

    if ($ipt_exec_style eq 'system') {
        system qq{$cmd > $iptout 2> $ipterr};
    } elsif ($ipt_exec_style eq 'popen') {
        open CMD, "$cmd 2> $ipterr |" or croak "[*] Could not execute $cmd: $!";
        @stdout = <CMD>;
        close CMD;
        open F, "> $iptout" or croak "[*] Could not open $iptout: $!";
        print F for @stdout;
        close F;
    } else {
        my $ipt_pid;

    	if ($debug or $verbose) {
            print $fh localtime() . " [+] IPTables::Parse: " .
                "Setting SIGCHLD handler to: " . $sigchld_handler . "\n";
        }

        local $SIG{'CHLD'} = $sigchld_handler;
        if ($ipt_pid = fork()) {
            eval {
                ### iptables should never take longer than 30 seconds to execute,
                ### unless there is some absolutely enormous policy or the kernel
                ### is exceedingly busy
                local $SIG{'ALRM'} = sub {die "[*] iptables command timeout.\n"};
                alarm $ipt_alarm;
                waitpid($ipt_pid, 0);
                alarm 0;
            };
            if ($@) {
                kill 9, $ipt_pid unless kill 15, $ipt_pid;
            }
        } else {
            croak "[*] Could not fork iptables: $!"
                unless defined $ipt_pid;

            ### exec the iptables command and preserve stdout and stderr
            exec qq{$cmd > $iptout 2> $ipterr};
        }
    }

    if (-e $iptout) {
        open F, "< $iptout" or croak "[*] Could not open $iptout";
        @stdout = <F>;
        close F;
    }
    if (-e $ipterr) {
        open F, "< $ipterr" or croak "[*] Could not open $ipterr";
        @stderr = <F>;
        close F;

        $rv = 0 if @stderr;
    }

    if ($debug or $verbose) {
        print $fh localtime() . "     iptables command stdout:\n";
        for my $line (@stdout) {
            if ($line =~ /\n$/) {
                print $fh $line;
            } else {
                print $fh $line, "\n";
            }
        }
        print $fh localtime() . "     iptables command stderr:\n";
        for my $line (@stderr) {
            if ($line =~ /\n$/) {
                print $fh $line;
            } else {
                print $fh $line, "\n";
            }
        }
    }

    return $rv, \@stdout, \@stderr;
}

sub REAPER {
    my $stiff;
    while(($stiff = waitpid(-1,WNOHANG))>0){
        # do something with $stiff if you want
    }
    local $SIG{'CHLD'} = \&REAPER;
    return;
}

1;
__END__

=head1 NAME

IPTables::Parse - Perl extension for parsing iptables firewall rulesets

=head1 SYNOPSIS

  use IPTables::Parse;

  my %opts = (
      'iptables' => '/sbin/iptables',
      'iptout'   => '/tmp/iptables.out',
      'ipterr'   => '/tmp/iptables.err',
      'debug'    => 0,
      'verbose'  => 0
  );

  my $ipt_obj = new IPTables::Parse(%opts)
      or die "[*] Could not acquire IPTables::Parse object";

  my $rv = 0;

  my $table = 'filter';
  my $chain = 'INPUT';

  my ($ipt_hr, $rv) = $ipt_obj->default_drop($table, $chain);
  if ($rv) {
      if (defined $ipt_hr->{'all'}) {
          print "The INPUT chain has a default DROP rule for all protocols.\n";
      } else {
          for my $proto qw/tcp udp icmp/ {
              if (defined $ipt_hr->{$proto}) {
                  print "The INPUT chain drops $proto by default.\n";
              }
          }
      }
  } else {
      print "[-] Could not parse iptables policy\n";
  }

  ($ipt_hr, $rv) = $ipt_obj->default_log($table, $chain);
  if ($rv) {
      if (defined $ipt_hr->{'all'}) {
          print "The INPUT chain has a default LOG rule for all protocols.\n";
      } else {
          for my $proto qw/tcp udp icmp/ {
              if (defined $ipt_hr->{$proto}) {
                  print "The INPUT chain logs $proto by default.\n";
              }
          }
      }
  } else {
      print "[-] Could not parse iptables policy\n";
  }

=head1 DESCRIPTION

The C<IPTables::Parse> package provides an interface to parse iptables
rules on Linux systems through the direct execution of iptables commands, or
from parsing a file that contains an iptables policy listing.  You can get the
current policy applied to a table/chain, look for a specific user-defined chain,
check for a default DROP policy, or determing whether or not logging rules exist.

=head1 FUNCTIONS

The IPTables::Parse extension provides an object interface to the following
functions:

=over 4

=item chain_policy($table, $chain)

This function returns the policy (e.g. 'DROP', 'ACCEPT', etc.) for the specified
table and chain:

  print "INPUT policy: ", $ipt_obj->chain_policy('filter', 'INPUT'), "\n";

=item chain_rules($table, $chain)

This function parses the specified chain and table and returns an array reference
for all rules in the chain.  Each element in the array reference is a hash with
the following keys (that contain values depending on the rule): C<src>, C<dst>,
C<protocol>, C<s_port>, C<d_port>, C<target>, C<packets>, C<bytes>, C<intf_in>,
C<intf_out>, C<to_ip>, C<to_port>, C<state>, C<raw>, and C<extended>.  The C<extended>
element contains the rule output past the protocol information, and the C<raw>
element contains the complete rule itself as reported by iptables.

=item default_drop($table, $chain)

This function parses the running iptables policy in order to determine if
the specified chain contains a default DROP rule.  Two values are returned,
a hash reference whose keys are the protocols that are dropped by default
if a global ACCEPT rule has not accepted matching packets first, along with
a return value that tells the caller if parsing the iptables policy was
successful.  Note that if all protocols are dropped by default, then the
hash key 'all' will be defined.

  ($ipt_hr, $rv) = $ipt_obj->default_drop('filter', 'INPUT');

=item default_log($table, $chain)

This function parses the running iptables policy in order to determine if
the specified chain contains a default LOG rule.  Two values are returned,
a hash reference whose keys are the protocols that are logged by default
if a global ACCEPT rule has not accepted matching packets first, along with
a return value that tells the caller if parsing the iptables policy was
successful.  Note that if all protocols are logged by default, then the
hash key 'all' will be defined.  An example invocation is:

  ($ipt_hr, $rv) = $ipt_obj->default_log('filter', 'INPUT');

=back

=head1 AUTHOR

Michael Rash, E<lt>mbr@cipherdyne.orgE<gt>

=head1 SEE ALSO

The IPTables::Parse is used by the IPTables::ChainMgr extension in support of
the psad, fwsnort, and fwknop projects to parse iptables policies (see the psad(8),
fwsnort(8), and fwknop(8) man pages).  As always, the iptables(8) provides the
best information on command line execution and theory behind iptables.

Although there is no mailing that is devoted specifically to the IPTables::Parse
extension, questions about the extension will be answered on the following
lists:

  The psad mailing list: http://lists.sourceforge.net/lists/listinfo/psad-discuss
  The fwknop mailing list: http://lists.sourceforge.net/lists/listinfo/fwknop-discuss
  The fwsnort mailing list: http://lists.sourceforge.net/lists/listinfo/fwsnort-discuss

The latest version of the IPTables::Parse extension can be found at:

http://www.cipherdyne.org/modules/

=head1 CREDITS

Thanks to the following people:

  Franck Joncourt <franck.mail@dthconnex.com>
  Grant Ferley

=head1 AUTHOR

The IPTables::Parse extension was written by Michael Rash F<E<lt>mbr@cipherdyne.orgE<gt>>
to support the psad, fwknop, and fwsnort projects.  Please send email to
this address if there are any questions, comments, or bug reports.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005-2008 by Michael Rash

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.5 or,
at your option, any later version of Perl 5 you may have available.

=cut
