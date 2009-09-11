'INTEGER:*_incr' => sub {
                      my $x = $names{'*'};
                      my $incr = @_ > 1 ? $_[1] : 1;
                      $_[0]->$x($_[0]->$x()+$incr);
                    },

'INTEGER:*_decr' => sub {
                      my $x = $names{'*'};
                      my $decr = @_ > 1 ? $_[1] : 1;
                      $_[0]->$x($_[0]->$x()-$decr);
                    },

'INTEGER:*_zero' => sub {
                      my $x = $names{'*'};
                      $_[0]->$x(0);
                    },
