#!/usr/local/bin/perl

package X;
use strict;

use Class::MethodMaker
  get_set  => [qw[  setable_00 ]],
  get_set  => [qw[ -set_once           dier_00 dier_01]],
  get_set  => [qw[  setable_01 -set_once dier_04]],
  get_set  => [qw[ -set_once_or_die    dier_02 dier_03]],
  get_set  => [qw[ -set_once_or_warn   warner_00 warner_01]],
  get_set  => [qw[ -set_once_or_carp   carper_00 carper_01]],
  get_set  => [qw[ -set_once_or_cluck  clucker_00 clucker_01]],
  get_set  => [qw[ -set_once_or_croak   croaker_00 croaker_01]],
  get_set  => [qw[ -set_once_or_confess   confessor_00 confessor_01]],
  get_set  => [qw[ -set_once_or_myonce  myonce_00 myonce_01]],
  get_set  => [qw[ -set_once_or_ignore  ignore_00]],
  ;

sub new { bless {}, shift; }
sub myonce { die "myonce" };

package main;
use lib qw ( ./t );
use test_v1;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new X;
my $p = new X;

# trigger a get on all values
TEST { 1 }; # (1)
TEST { !defined $o->setable_00 }; # (2)
TEST { !defined $o->setable_01 }; # (3)
TEST { !defined $o->dier_00 }; # (4)
TEST { !defined $o->dier_01 }; # (5)
TEST { !defined $o->dier_02 }; # (6)
TEST { !defined $o->dier_03 }; # (7)
TEST { !defined $o->dier_04 }; # (8)
TEST { !defined $o->warner_00 }; # (9)
TEST { !defined $o->warner_01 }; # (10)
TEST { !defined $o->carper_00 }; # (11)
TEST { !defined $o->carper_01 }; # (12)
TEST { !defined $o->clucker_00 }; # (13)
TEST { !defined $o->clucker_01 }; # (14)
TEST { !defined $o->croaker_00 }; # (15)
TEST { !defined $o->croaker_01 }; # (16)
TEST { !defined $o->confessor_00 }; # (17)
TEST { !defined $o->confessor_01 }; # (18)
TEST { !defined $o->myonce_00 }; # (19)
TEST { !defined $o->myonce_01 }; # (20)

# trigger a set on all values
TEST { $o->setable_00(1) == 1 }; # (21)
TEST { $o->setable_01(2) == 2 }; # (22)
TEST { $o->dier_00(3) == 3 }; # (23)
TEST { $o->dier_01(4) == 4 }; # (24)
TEST { $o->dier_02(5) == 5 }; # (25)
TEST { $o->dier_03(6) == 6 }; # (26)
TEST { $o->dier_04(7) == 7 }; # (27)
TEST { $o->warner_00(8) == 8 }; # (28)
TEST { $o->warner_01(9) == 9 }; # (29)
TEST { $o->carper_00(10) == 10 }; # (30)
TEST { $o->carper_01(11) == 11 }; # (31)
TEST { $o->clucker_00(12) == 12 }; # (32)
TEST { $o->clucker_01(13) == 13 }; # (33)
TEST { $o->croaker_00(14) == 14 }; # (34)
TEST { $o->croaker_01(15) == 15 }; # (35)
TEST { $o->myonce_00(16) == 16 }; # (36)
TEST { $o->myonce_01(17) == 17 }; # (37)

# trigger ANOTHER set on all values
my $w; # 1 if a warn() of sorts was called.
$SIG{__WARN__} = sub { $w=1; die(@_) };

TEST {  eval{$w=0};  eval{$o->setable_00(1)    };  $w == 0 &&  !length($@)  }; # (38)
TEST {  eval{$w=0};  eval{$o->setable_01(2)    };  $w == 0 &&  !length($@)  }; # (39)
TEST {  eval{$w=0};  eval{$o->dier_00(3)       };  $w == 0 &&   length($@)  }; # (40)
TEST {  eval{$w=0};  eval{$o->dier_01(4)       };  $w == 0 &&   length($@)  }; # (41)
TEST {  eval{$w=0};  eval{$o->dier_02(5)       };  $w == 0 &&   length($@)  }; # (42)
TEST {  eval{$w=0};  eval{$o->dier_03(6)       };  $w == 0 &&   length($@)  }; # (43)
TEST {  eval{$w=0};  eval{$o->dier_04(7)       };  $w == 0 &&   length($@)  }; # (44)
TEST {  eval{$w=0};  eval{$o->warner_00(8)     };  $w == 1 &&   length($@)  }; # (45)
TEST {  eval{$w=0};  eval{$o->warner_01(9)     };  $w == 1 &&   length($@)  }; # (46)
TEST {  eval{$w=0};  eval{$o->carper_00(10)    };  $w == 1 &&   length($@)  }; # (47)
TEST {  eval{$w=0};  eval{$o->carper_01(11)    };  $w == 1 &&   length($@)  }; # (48)
TEST {  eval{$w=0};  eval{$o->clucker_00(12)   };  $w == 1 &&   length($@)  }; # (49)
TEST {  eval{$w=0};  eval{$o->clucker_01(13)   };  $w == 1 &&   length($@)  }; # (50)
TEST {  eval{$w=0};  eval{$o->croaker_00(14)   };  $w == 0 &&   length($@)  }; # (51)
TEST {  eval{$w=0};  eval{$o->croaker_01(15)   };  $w == 0 &&   length($@)  }; # (52)
TEST {  eval{$w=0};  eval{$o->confessor_00(14) };  $w == 0 &&  !length($@) }; # (53)
TEST {  eval{$w=0};  eval{$o->confessor_01(15) };  $w == 0 &&  !length($@) }; # (54)
TEST {  eval{$w=0};  eval{$o->myonce_00(16)    };  $w == 0 &&  $@ =~ /^myonce/ }; # (55)
TEST {  eval{$w=0};  eval{$o->myonce_01(17)    };  $w == 0 &&  $@ =~ /^myonce/ }; # (56)

# Prove absence of static effects

TEST { $o->ignore_00(1) == 1 }; # (57)
TEST { $o->ignore_00(2) == 1 }; # (58)
TEST { ! defined $p->ignore_00 }; # (59)
TEST { $p->ignore_00(2) == 2 }; # (60)
TEST { $p->ignore_00(3) == 2 }; # (61)

TEST { ! defined $p->carper_01 }; # (62)
TEST { $p->carper_01(2) == 2 }; # (63)
TEST { eval{$w=0};  eval{$p->carper_01(11)    };  $w == 1 &&   length($@)  }; # (64)

TEST { ! defined $p->dier_04 }; # (65)
TEST { $p->dier_04(2) == 2 }; # (66)
TEST {  eval{$w=0};  eval{$p->dier_04(7)       };  $w == 0 &&   length($@)  }; # (67)

TEST { ! defined $p->myonce_00 }; # (68)
TEST { $p->myonce_00(7) == 7 }; # (69)
TEST { $p->myonce_00 == 7 }; # (70)
TEST {  eval{$w=0};  eval{$p->myonce_00(16)    };  $w == 0 &&  $@ =~ /^myonce/ }; # (71)

exit 0;

