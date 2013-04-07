@client_nat_dns_resolution_fko = (
    {
        'category' => 'Franck',
        'subcategory' => 'client nat-local',
        'detail'   => 'Bad dns resolution in nat-local mode',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Unable\sto\sresolve\swww.cipherdyne.co\sas\san\sip\saddress/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -a 1.2.3.4 -A tcp/22 --nat-local --nat-port 80 -D www.cipherdyne.co",
        'fatal'    => $NO
    },
    {
        'category' => 'Franck',
        'subcategory' => 'client nat-local',
        'detail'   => 'Good dns resolution in nat-local mode',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Nat\sAccess:\s74.220.215.85,22/i],
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -a 1.2.3.4 -A tcp/22 --nat-local --nat-port 80 -D www.cipherdyne.com " .
            "--get-key $local_key_file --no-save-args --verbose --verbose",
        'fatal'    => $NO
    },    
);
