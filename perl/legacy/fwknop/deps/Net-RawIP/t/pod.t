use strict;
use warnings;

use Test::More;
eval {
    require Test::Pod;
    import Test::Pod;
};
plan skip_all => "Test::Pod 1.00 required for testing POD" if $@;
all_pod_files_ok(all_pod_files('.'));
