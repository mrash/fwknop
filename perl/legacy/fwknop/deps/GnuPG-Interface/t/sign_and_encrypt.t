#!/usr/bin/perl -w
#
# $Id: sign_and_encrypt.t 1125 2008-06-07 17:27:50Z mbr $
#

use strict;
use English qw( -no_match_vars );

use lib './t';
use MyTest;
use MyTestSpecific;

TEST
{
    reset_handles();
    
    $gnupg->options->push_recipients( '0x2E854A6B' );
    my $pid = $gnupg->sign_and_encrypt( handles => $handles );
    
    print $stdin @{ $texts{plain}->data() };
    close $stdin;
    waitpid $pid, 0;
    
    return $CHILD_ERROR == 0;
};


TEST
{
    reset_handles();
    
    $handles->stdin( $texts{plain}->fh() );
    $handles->options( 'stdin' )->{direct} = 1;
    my $pid = $gnupg->sign_and_encrypt( handles => $handles );
    
    waitpid $pid, 0;
    
    return $CHILD_ERROR == 0;
};
