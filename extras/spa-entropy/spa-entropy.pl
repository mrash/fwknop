#!/usr/bin/perl -w
#
# File: spa-entropy.pl
#
# Purpose: To measure cross-packet SPA entropy on a byte by byte slice basis
#          and produce gunplot graphs.  This is useful to measure SPA packet
#          randomness after encryption.
#
# Author: Michael Rash <mbr@cipherdyne.org>
#
# License: GPL v2
#

use MIME::Base64;
use IPC::Open2;
use Getopt::Long 'GetOptions';
use strict;

my $use_ent = 1;
my $base64_decode = 1;
my $packets = 0;
my $prefix = 'entropy';
my $file_to_measure = '';
my $run_fwknop_client = 0;
my $min_len = 0;
my $lib_dir = '../../lib/.libs';
my $fwknop_client_path = '../../client/.libs/fwknop';
my $enc_mode = 'cbc';
my $enable_fwknop_client_gpg = 0;
my $spa_key_file = '../../test/local_spa.key';
my $help = 0;

my $use_openssl = 0;
my $openssl_salt = '0000000000000000';
my $openssl_mode = 'aes-256-cbc';

my %min_max_entropy = (
    'min' => {
        'val' => -1,
        'pos' => 0,
    },
    'max' => {
        'val' => -1,
        'pos' => 0,
    }
);

my @encrypted_data = ();
my @plaintext_data = ();
my @cross_pkt_data = ();

Getopt::Long::Configure('no_ignore_case');
die "[*] See '$0 -h' for usage information" unless (GetOptions(
    'file-to-measure=s' => \$file_to_measure,
    'base64-decode'     => \$base64_decode,
    'count=i'           => \$packets,
    'prefix=s'          => \$prefix,
    'run-fwknop-client' => \$run_fwknop_client,
    'enc-mode=s'        => \$enc_mode,
    'gpg'               => \$enable_fwknop_client_gpg,
    'lib-dir=s'         => \$lib_dir,
    'Client-path=s'     => \$fwknop_client_path,
    'use-openssl'       => \$use_openssl,
    'openssl-salt=s'    => \$openssl_salt,
    'openssl-mode=s'    => \$openssl_mode,
    'help'              => \$help,
));
&usage() if $help;

die "[*] Must execute --run-fwknop-client in --use-openssl mode"
    if $use_openssl and not $run_fwknop_client;

&run_fwknop_client() if $run_fwknop_client;

&read_data();

&get_min_len();

&build_data_slices();

open F, "> $prefix.dat" or die $!;
my $pos = 0;
for my $str (@cross_pkt_data) {

    my $entropy = &get_entropy($str);

#    print F "$pos $entropy\n";
    print F "$pos $entropy   ### " . &hex_dump($str) . "\n";

    if ($min_max_entropy{'min'}{'val'} == -1
            and $min_max_entropy{'max'}{'val'} == -1) {
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

my $min = sprintf "%.2f", $min_max_entropy{'min'}{'val'};
my $max = sprintf "%.2f", $min_max_entropy{'max'}{'val'};

print "[+] Min entropy: $min at byte: $min_max_entropy{'min'}{'pos'}\n";
print "[+] Max entropy: $max at byte: $min_max_entropy{'max'}{'pos'}\n";

&run_gnuplot();

exit 0;

sub read_data() {

    if ($use_openssl) {

        ### we've already gotten plaintext information from the fwknop client,
        ### so encrypt this data with openssl and use it to re-write the
        ### $file_to_measure
        unlink $file_to_measure if -e $file_to_measure;

        my @openssl_encrypted_data = ();

        ### encrypt the plaintext and use it to re-write the -f file
        for my $line (@plaintext_data) {

            my $ptext_file = 'ptext.tmp';
            my $enc_file   = 'ptext.enc';

            open F, "> $ptext_file" or die $!;
            print F $line;
            close F;

            unlink $enc_file if -e $enc_file;

            system "openssl enc -$openssl_mode -a -S $openssl_salt " .
                "-in ptext.tmp -out ptext.enc -k fwknoptest000000";

            my $base64_enc_data = '';
            open F, "< $enc_file" or die $!;
            while (<F>) {
                chomp;
                $base64_enc_data .= $_;
            }
            close F;

            push @openssl_encrypted_data, $base64_enc_data;

        }

        open F, "> $file_to_measure" or die $!;
        for my $line (@openssl_encrypted_data) {
            print F $line, "\n";
        }
        close F;
    }

    my $fh = *STDIN;
    if ($file_to_measure) {
        open IN, "< $file_to_measure" or die "[*] Could not open $file_to_measure: $!";
        $fh = *IN;
    }

    my $l_ctr = 0;
    while (<$fh>) {
        next unless $_ =~ /\S/;
        chomp;

        if ($base64_decode) {
            if (&is_base64($_)) {
                my $base64_str = $_;

                if ($enable_fwknop_client_gpg) {
                    unless ($base64_str =~ /^hQ/) {
                        $base64_str = 'hQ' . $base64_str;
                    }
                } else {
                    ### base64-encoded "Salted__" prefix
                    unless ($base64_str =~ /^U2FsdGVkX1/) {
                        $base64_str = 'U2FsdGVkX1' . $base64_str;
                    }
                }

                my ($equals_rv, $equals_padding) = &base64_equals_padding($base64_str);
                if ($equals_padding) {
                    $base64_str .= $equals_padding;
                }
                my $str = decode_base64($base64_str);

                if ($enable_fwknop_client_gpg) {
                    $str =~ s/^\x85\x02//;
                } else {
                    $str =~ s/^Salted__//;
                }
                push @encrypted_data, $str;
            } else {
                push @encrypted_data, $_;
            }
        } else {
            push @encrypted_data, $_;
        }

        $l_ctr++;
        if ($packets > 0) {
            last if $l_ctr == $packets;
        }
    }

    ### hex dump encrypted data
    open HEX, "> hex_dump.data" or die $!;
    for my $line (@encrypted_data) {
        print HEX &hex_dump($line), "\n";
    }
    close HEX;

    print "[+] Read in $l_ctr SPA packets...\n";
    return;
}

sub run_fwknop_client() {
    die "[*] Must set packets file with -f <file>" unless $file_to_measure;
    die "[*] Must set packet count with -c <count>" unless $packets;

    if (-e $file_to_measure) {
        unlink $file_to_measure or die $!;
    }

    my $cmd = "LD_LIBRARY_PATH=$lib_dir $fwknop_client_path -A tcp/22 " .
        "-a 127.0.0.2 -D 127.0.0.1 --get-key $spa_key_file " .
        "-B $file_to_measure -b -v --test";

    if ($enable_fwknop_client_gpg) {
        $cmd .= ' --gpg-recipient-key 361BBAD4 --gpg-signer-key 6A3FAD56 ' .
            '--gpg-home-dir ../../test/conf/client-gpg';
    } else {
        $cmd .= " -M $enc_mode";
    }
    $cmd .= " 2> /dev/null";

    print "[+] Running fwknop client via the following command:\n\n$cmd\n\n";

    for (my $i=0; $i < $packets; $i++) {
        open C, "$cmd |" or die $!;
        while (<C>) {
            if (/Plaintext\:\s+(\S+)/) {
                push @plaintext_data, $1;
                last;
            }
        }
        close C;
    }

    return;
}

sub get_min_len() {

    ### calculate minimum length
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
    return;
}

sub build_data_slices() {
    for my $line (@encrypted_data) {
        my @chars = split //, $line;
        my $c_ctr = 0;
        for my $char (@chars) {
            $cross_pkt_data[$c_ctr] .= $char;
            last if $c_ctr == $min_len;
            $c_ctr++;
        }
    }
    return;
}

sub run_gnuplot() {
    open F, "> $prefix.gnu" or die $!;

    my $enc_str = $enc_mode;
    $enc_str = 'gpg' if $enable_fwknop_client_gpg;

    my $yrange = '[0:9]';
    print F <<_GNUPLOT_;
set title "SPA slice entropy (encryption mode: $enc_str)"
set terminal gif nocrop enhanced
set output "$prefix.gif"
set grid
set yrange $yrange
plot '$prefix.dat' using 1:2 with lines title 'min: $min \\@ byte: $min_max_entropy{'min'}{'pos'}, max: $max \\@ byte: $min_max_entropy{'max'}{'pos'}'
_GNUPLOT_
    close F;

    print "[+] Creating $prefix.gif gnuplot graph...\n\n";
    system "gnuplot $prefix.gnu";

    return;
}

sub get_entropy() {
    my $data = shift;

    my $entropy = '';

    my $pid = open2(\*CHLD_OUT, \*CHLD_IN, 'ent');

    print CHLD_IN $data;
    close CHLD_IN;

    while (<CHLD_OUT>) {
        ### Entropy = 5.637677 bits per byte.
        if (/Entropy\s=\s(\d\S+)/) {
            $entropy = $1;
            last;
        }
    }

    close CHLD_OUT;

    waitpid $pid, 0;
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

    my $hex_part   = '';
    my $ascii_part = '';

    for my $char (@chars) {

        $hex_part .= sprintf "%.2x", ord($char);

        if ($char =~ /[^\x20-\x7e]/) {
            $ascii_part .= '.';
        } else {
            $ascii_part .= $char;
        }
        $ctr++;
    }
    return "$hex_part $ascii_part";
#    return "$ascii_part";
}

sub is_base64() {
    my $data = shift;

    ### check to make sure the packet data only contains base64 encoded
    ### characters per RFC 3548:   0-9, A-Z, a-z, +, /, =
    if ($data =~ /[^\x30-\x39\x41-\x5a\x61-\x7a\x2b\x2f\x3d]/) {
        return 0;
    }
    if ($data =~ /=[^=]/) {
        return 0;
    }
    return 1;
}

sub usage() {
    print "$0 [options]\n";
    exit 0;
}
