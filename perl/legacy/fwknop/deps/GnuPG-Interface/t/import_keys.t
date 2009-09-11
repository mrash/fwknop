#!/usr/bin/perl -w
#
# $Id: import_keys.t 1125 2008-06-07 17:27:50Z mbr $
#

use strict;
use English qw( -no_match_vars );

use lib './t';
use MyTest;
use MyTestSpecific;

TEST
{
    reset_handles();
    
    my $pid = $gnupg->import_keys( handles => $handles );
    
    print $stdin @{ $texts{key}->data() };
    close $stdin;
    my @output = <$stdout>;
    waitpid $pid, 0;
    
    return $CHILD_ERROR == 0;
};


TEST
{
    reset_handles();
    
    $handles->stdin( $texts{key}->fh() );
    $handles->options( 'stdin' )->{direct} = 1;
    
    my $pid = $gnupg->import_keys( handles => $handles );
    waitpid $pid, 0;
    
    return $CHILD_ERROR == 0;
};
