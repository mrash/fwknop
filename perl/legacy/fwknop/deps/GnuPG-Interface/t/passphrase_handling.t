#!/usr/bin/perl -w
#
# $Id: passphrase_handling.t 1125 2008-06-07 17:27:50Z mbr $
#

use strict;
use English qw( -no_match_vars );
use Symbol;
use IO::File;

use lib './t';
use MyTest;
use MyTestSpecific;

TEST
{
    reset_handles();
    return $gnupg->test_default_key_passphrase()
};


$gnupg->clear_passphrase();
    
TEST
{
    reset_handles();
    
    my $passphrase_handle = gensym;
    $handles->passphrase( $passphrase_handle );
    
    my $pid = $gnupg->sign( handles => $handles );
    
    print $passphrase_handle 'test';
    print $stdin @{ $texts{plain}->data() };
    
    close $passphrase_handle;
    close $stdin;
    
    waitpid $pid, 0;
    return $CHILD_ERROR == 0;
};



TEST
{
    reset_handles();
    $handles->clear_stderr();
    $handles->stderr( '>&STDERR' );
    
    my $pass_fn = 'test/passphrase';
    my $passfile = IO::File->new( $pass_fn )
      or die "cannot open $pass_fn: $ERRNO";
    $handles->passphrase( $passfile );
    $handles->options( 'passphrase' )->{direct} = 1;
    
    my $pid = $gnupg->sign( handles => $handles );
    close $stdin;
    
    waitpid $pid, 0;
    return $CHILD_ERROR == 0;
};
