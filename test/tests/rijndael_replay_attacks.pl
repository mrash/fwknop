@rijndael_replay_attacks = (
    {
        'category' => 'Rijndael',
        'subcategory' => 'client+server',
        'detail'   => 'replay attack detection',
        'function' => \&replay_detection,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/Replay\sdetected\sfrom\ssource\sIP/],
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (Rijndael prefix)',
        'function' => \&replay_detection,
        'pkt_prefix' => 'U2FsdGVkX1',
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
    },

    {
        'category' => 'Rijndael',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (GnuPG prefix)',
        'function' => \&replay_detection,
        'pkt_prefix' => 'hQ',
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
    },
);
