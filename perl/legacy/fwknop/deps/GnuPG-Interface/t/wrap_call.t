#!/usr/bin/perl -w
#
#  $Id: wrap_call.t 389 2005-12-11 22:46:36Z mbr $
#

use strict;

use lib './t';
use MyTest;
use MyTestSpecific;

TEST
{
    reset_handles();
    
    my $pid = $gnupg->wrap_call
      ( commands     => [ qw( --list-packets ) ],
	command_args => [ qw( test/key.1.asc ) ],
	handles      => $handles,
      );
    
    close $stdin;
    
    my @out = <$stdout>;
    waitpid $pid, 0;
    
    return @out > 0;  #just check if we have output.
};
  
TEST
{
    return $CHILD_ERROR == 0;
};


# same as above, but now with deprecated stuff
TEST
{
    reset_handles();
    
    my $pid = $gnupg->wrap_call
      ( gnupg_commands     => [ qw( --list-packets ) ],
	gnupg_command_args => [ qw( test/key.1.asc ) ],
	handles      => $handles,
      );
    
    close $stdin;
    
    my @out = <$stdout>;
    waitpid $pid, 0;
    
    return @out > 0;  #just check if we have output.
};   


TEST
{
    return $CHILD_ERROR == 0;
};
