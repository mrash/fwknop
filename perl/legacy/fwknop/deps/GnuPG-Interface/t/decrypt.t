#!/usr/bin/perl -w
#
# $Id: decrypt.t 1125 2008-06-07 17:27:50Z mbr $
#

use strict;
use English qw( -no_match_vars );
use File::Compare;

use lib './t';
use MyTest;
use MyTestSpecific;

my $compare;

TEST
{
    reset_handles();
    
    my $pid = $gnupg->decrypt( handles => $handles );
    
    print $stdin @{ $texts{encrypted}->data() };
    close $stdin;
    
    $compare = compare( $texts{plain}->fn(), $stdout );
    close $stdout;
    waitpid $pid, 0;
    
    return $CHILD_ERROR == 0;;
};


TEST
{ 
    return $compare == 0;
};


TEST
{
    reset_handles();
    
    $handles->stdin( $texts{encrypted}->fh() );
    $handles->options( 'stdin' )->{direct} = 1;
    
    $handles->stdout( $texts{temp}->fh() );
    $handles->options( 'stdout' )->{direct} = 1;
    
    my $pid = $gnupg->decrypt( handles => $handles );
    
    waitpid $pid, 0;
    
    return $CHILD_ERROR == 0;
};


TEST
{
    return compare( $texts{plain}->fn(), $texts{temp}->fn() ) == 0;
};
