use strict;
use warnings;

use Test::More;
eval {
    require Test::Pod::Coverage;
    import Test::Pod::Coverage;
};
plan skip_all => "Test::Pod::Coverage 1.00 required for testing POD coverage" if $@;
plan skip_all => "for now....";
all_pod_coverage_ok();
