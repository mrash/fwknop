### make sure we can load the module

use Test;
BEGIN { plan tests => 1 };
use IPTables::ChainMgr;
ok(1); # If we made it this far, we're ok.
