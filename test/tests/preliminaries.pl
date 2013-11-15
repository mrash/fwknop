@preliminaries = (
    {
        'category' => 'preliminaries',
        'subcategory' => 'client',
        'detail'   => 'usage info',
        'function' => \&generic_exec,
        'cmdline'  => "$fwknopCmd -h",
    },
    {
        'category' => 'preliminaries',
        'subcategory' => 'client',
        'detail'   => 'getopt() no such argument',
        'function' => \&generic_exec,
        'cmdline'  => "$fwknopCmd --no-such-arg",
        'exec_err' => $YES,
    },
    {
        'category' => 'preliminaries',
        'subcategory' => 'client',
        'detail'   => '--test mode, packet not sent',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/test\smode\senabled/],
        'cmdline'  => "$default_client_args --test",
    },

    {
        'category' => 'preliminaries',
        'subcategory' => 'client',
        'detail'   => 'expected code version',
        'function' => \&expected_code_version,
        'cmdline'  => "$fwknopCmd --version",
    },

    {
        'category' => 'preliminaries',
        'subcategory' => 'server',
        'detail'   => 'usage info',
        'function' => \&generic_exec,
        'cmdline'  => "$fwknopdCmd -h",
    },
    {
        'category' => 'preliminaries',
        'subcategory' => 'server',
        'detail'   => 'getopt() no such argument',
        'function' => \&generic_exec,
        'cmdline'  => "$fwknopdCmd --no-such-arg",
        'exec_err' => $YES,
    },

    {
        'category' => 'preliminaries',
        'subcategory' => 'server',
        'detail'   => 'expected code version',
        'function' => \&expected_code_version,
        'cmdline'  => "$fwknopdCmd -c $cf{'def'} -a " .
            "$cf{'def_access'} --version",
    },
    {
        'category' => 'preliminaries',
        'detail'   => 'collecting system specifics',
        'function' => \&specs,
        'binary'   => $fwknopdCmd,
    },
);
