use Benchmark qw(cmpthese);

package Foo;

sub new { bless {slot => "blot"}, shift }

sub getset_orig {
   my $self = shift;
   if (@_) {
       $self->{slot} = shift;
   } else {
       $self->{slot};
   }
}

sub getset_fast {
    return $_[0]->{slot} if @_ == 1;
    return $_[0]->{slot} = $_[1];
}

# lvalue doesn't play nicely with return :-(
sub getset_lvalue {
  if ( @_ == 1 ) {
    $_[0]->{slot};
  } else {
    $_[0]->{slot} = $_[1];
  }
}

package main;

my $obj = Foo->new();

cmpthese(-2, {
              getset_orig => sub {
                  $_ = $obj->getset_orig();
                  $obj->getset_orig($_);
              },
              getset_fast => sub {
                  $_ = $obj->getset_fast();
                  $obj->getset_fast($_);
              },
              getset_lvalue => sub {
                  $_ = $obj->getset_lvalue();
                  $obj->getset_lvalue($_);
              },
             });
