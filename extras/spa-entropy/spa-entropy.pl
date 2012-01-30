#!/usr/bin/perl -w

use MIME::Base64;
use IPC::Open2;
use Data::Password::Entropy;
use strict;

my %min_max_entropy = (
    'min' => {
        'val' => 0,
        'pos' => 0,
    },
    'max' => {
        'val' => 0,
        'pos' => 0,
    }
);
my @encrypted_data = ();
my @cross_pkt_data = ();

while (<STDIN>) {
    next unless $_ =~ /\S/;
    chomp;

    push @encrypted_data, $_;
    next;

    my $base64_str = $_;
    unless ($base64_str =~ /^U2FsdGVkX1/) {
        $base64_str = 'U2FsdGVkX1' . $base64_str;
    }
    my ($equals_rv, $equals_padding) = &base64_equals_padding($base64_str);
    if ($equals_padding) {
        $base64_str .= $equals_padding;
    }
    push @encrypted_data, decode_base64($base64_str);
}

### calculate minimum length
my $min_len = 0;
for my $line (@encrypted_data) {
    chomp $line;
    next unless $line =~ /\S/;
    my $len = length($line);
    if ($min_len == 0) {
        $min_len = $len;
    } else {
        if ($len < $min_len) {
            $min_len = $len;
        }
    }
}

my $l_ctr = 0;
for my $line (@encrypted_data) {
    my @chars = split //, $line;
    my $c_ctr = 0;
    for my $char (@chars) {
        $cross_pkt_data[$c_ctr] .= $char;
        last if $c_ctr == $min_len;
        $c_ctr++;
    }
    $l_ctr++;
}

open F, "> entropy.dat" or die $!;
my $pos = 0;
for my $str (@cross_pkt_data) {

    my $entropy = &get_entropy($str);

    print F "$pos $entropy\n";

    if ($min_max_entropy{'min'}{'val'} == 0
            and $min_max_entropy{'max'}{'val'} == 0) {
        $min_max_entropy{'min'}{'val'} = $entropy;
        $min_max_entropy{'min'}{'pos'} = $pos;
        $min_max_entropy{'max'}{'val'} = $entropy;
        $min_max_entropy{'max'}{'pos'} = $pos;
    } else {
        if ($entropy < $min_max_entropy{'min'}{'val'}) {
            $min_max_entropy{'min'}{'val'} = $entropy;
            $min_max_entropy{'min'}{'pos'} = $pos;
        }
        if ($entropy > $min_max_entropy{'max'}{'val'}) {
            $min_max_entropy{'max'}{'val'} = $entropy;
            $min_max_entropy{'max'}{'pos'} = $pos;
        }
    }
    $pos++;
}
close F;

my $min = $min_max_entropy{'min'}{'val'};
my $max = $min_max_entropy{'max'}{'val'};
print "Min entropy: $min at position: $min_max_entropy{'min'}{'pos'}\n";
print "Max entropy: $max at position: $min_max_entropy{'max'}{'pos'}\n";

open F, "> entropy.gnu" or die $!;
print F <<_GNUPLOT_;
set title "entropy measurement"
set terminal gif nocrop enhanced
set output "entropy.gif"
set grid
plot 'entropy.dat' using 1:2 with lines title 'min: $min, max: $max'
_GNUPLOT_
close F;

system "gnuplot entropy.gnu";

exit 0;

sub get_entropy() {
    my $data = shift;

    #return password_entropy($data);

    my $entropy = '';

    ### Entropy = 5.637677 bits per byte.
#    system "echo -n $data | ent | grep Entropy > tmp.ent";
#    open ENT, "< tmp.ent" or die $!;
#    my $line = <ENT>;
#    if ($line =~ /\s=\s(\d\S+)/) {
#        $entropy = $1;
#    }
#    close ENT;
#    return $entropy;

    my $pid = open2(\*CHLD_OUT, \*CHLD_IN, 'ent');

    print CHLD_IN $data;
    close CHLD_IN;

    while (<CHLD_OUT>) {
        if (/Entropy\s=\s(\d\S+)/) {
            $entropy = $1;
            last;
        }
    }

    close CHLD_OUT;

    waitpid( $pid, 0 );
    my $child_exit_status = $? >> 8;

    return $entropy;
}

sub base64_equals_padding() {
    my $msg = shift;
    my $padding = '';

    return 1, $padding if $msg =~ /=$/;

    my $remainder = 4 - length($msg) % 4;

    if ($remainder == 3) {
        ### not possible for valid base64 data - should only have
        ### pad with one or two '=' chars
        return 0, $padding;
    }

    unless ($remainder == 4) {
        $padding .= '='x$remainder;
    }
    return 1, $padding;
}

sub hex_dump() {
    my $data = shift;

    my @chars = split //, $data;
    my $ctr = 0;
    my $ascii_str = '';
    for my $char (@chars) {
        if ($ctr % 16 == 0) {
            print STDOUT " $ascii_str\n" if $ascii_str;
            printf STDOUT "        0x%.4x:  ", $ctr;
            $ascii_str = '';
        }
        printf STDOUT "%.2x", ord($char);

        if ((($ctr+1) % 2 == 0) and ($ctr % 16 != 0)) {
            print STDOUT ' ';
        }

        if ($char =~ /[^\x20-\x7e]/) {
            $ascii_str .= '.';
        } else {
            $ascii_str .= $char;
        }
        $ctr++;
    }
    if ($ascii_str) {
        my $remainder = 1;
        if ($ctr % 16 != 0) {
            $remainder = 16 - $ctr % 16;
            if ($remainder % 2 == 0) {
                $remainder = 2*$remainder + int($remainder/2) + 1;
            } else {
                $remainder = 2*$remainder + int($remainder/2) + 2;
            }
        }
        print STDOUT ' 'x$remainder, $ascii_str;
    }
    print STDOUT "\n";
    return;
}
