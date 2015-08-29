@afl_fuzzing = (
    ### run fwknopd with the -A arg for American Fuzzy Lop support regardless
    ### of whether AFL support has been compiled in - if not, an error is
    ### thrown and is therefore good for code coverage
    {
        'category' => 'AFL',
        'subcategory' => 'FUZZING',
        'detail'   => 'pkt to stdin',
        'function' => \&generic_exec,
        'cmdline' =>
            'echo -n "1716411011200157:root:1397329899:2.0.1:1:127.0.0.2,tcp/22:AAAAA" | ' .
            "$lib_view_str $valgrind_str $fwknopdCmd $default_server_conf_args -A -f -v",
    },
);
