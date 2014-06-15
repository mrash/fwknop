@fault_injection = (
    {
        'category' => 'fault injection',
        'subcategory' => 'libfko',
        'detail'   => 'acquire FKO context',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'faultinjection',
        'wrapper_script'  => $wrapper_exec_script,
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_fault_injection',
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'libfko',
        'detail'   => 'acquire FKO context (with valgrind)',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'faultinjection',
        'wrapper_script'  => $wrapper_exec_script_valgrind,
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_fault_injection',
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run libc/mm/*',
        'detail'   => 'acquire FKO context',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'all',
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_basic',
        'fiu_run' => $YES,
        'fiu_injection_style' => 'enable_random name=libc/mm/*,probability=0.05',
        'fiu_iterations' => 1000
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run libc/str/strdup',
        'detail'   => 'acquire FKO context',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'all',
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_basic',
        'fiu_run' => $YES,
        'fiu_injection_style' => 'enable_random name=libc/str/strdup,probability=0.05',
        'fiu_iterations' => 1000
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run posix/io/rw/*',
        'detail'   => 'acquire FKO context',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'all',
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_basic',
        'fiu_run' => $YES,
        'fiu_injection_style' => 'enable_random name=posix/io/rw/*,probability=0.05',
        'fiu_iterations' => 1000
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run libc/mm/*',
        'detail'   => 'client',
        'function' => \&fiu_run_fault_injection,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --no-save-args $verbose_str",
        'fiu_injection_style' => 'enable_random name=libc/mm/*,probability=0.05',
        'fiu_iterations' => 1000
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run posix/io/rw/*',
        'detail'   => 'client',
        'function' => \&fiu_run_fault_injection,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --no-save-args $verbose_str",
        'fiu_injection_style' => 'enable_random name=posix/io/rw/*,probability=0.05',
        'fiu_iterations' => 1000
    },

    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run libc/mm/*',
        'detail'   => 'server',
        'function' => \&fiu_run_fault_injection,
        'cmdline'  => "$fwknopdCmd $default_server_conf_args $intf_str --exit-parse-config",
        'fiu_injection_style' => 'enable_random name=libc/mm/*,probability=0.05',
        'fiu_iterations' => 1000
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run posix/io/rw/*',
        'detail'   => 'server',
        'function' => \&fiu_run_fault_injection,
        'cmdline'  => "$fwknopdCmd $default_server_conf_args $intf_str --exit-parse-config",
        'fiu_injection_style' => 'enable_random name=posix/io/rw/*,probability=0.05',
        'fiu_iterations' => 1000
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run libc/mm/*',
        'detail'   => 'server pcap file',
        'function' => \&fiu_run_fault_injection,
        'cmdline'  => "$fwknopdCmd $default_server_conf_args $intf_str --exit-parse-config",
        'cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} -C 100 " .
            "-d $default_digest_file -p $default_pid_file " .
            "--pcap-file $multi_pkts_pcap_file --foreground $verbose_str --test " .
            "--no-ipt-check-support",
        'fiu_injection_style' => 'enable_random name=libc/mm/*,probability=0.05',
        'fiu_iterations' => 1000
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run posix/io/rw/*',
        'detail'   => 'server pcap file',
        'function' => \&fiu_run_fault_injection,
        'cmdline'  => "$fwknopdCmd $default_server_conf_args $intf_str --exit-parse-config",
        'cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} -C 100 " .
            "-d $default_digest_file -p $default_pid_file " .
            "--pcap-file $multi_pkts_pcap_file --foreground $verbose_str --test " .
            "--no-ipt-check-support",
        'fiu_injection_style' => 'enable_random name=posix/io/rw/*,probability=0.05',
        'fiu_iterations' => 10
    },

    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_new_calloc',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_new_calloc",
        'positive_output_matches' => [qr/Unable to allocate memory/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_new_strdup',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_new_strdup",
        'positive_output_matches' => [qr/Unable to allocate memory/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_rand_value_init',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_rand_value_init",
        'positive_output_matches' => [qr/FKO Context is not initialized/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_rand_value_read',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_rand_value_read",
        'positive_output_matches' => [qr/write bytes mismatch/]
    },

    ### rand tags
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_rand_value_calloc1',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_rand_value_calloc1",
        'positive_output_matches' => [qr/Unable to allocate memory/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_rand_value_calloc2',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_rand_value_calloc2",
        'positive_output_matches' => [qr/Unable to allocate memory/]
    },

    ### username tags
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_username_init',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_username_init",
        'positive_output_matches' => [qr/FKO Context is not initialized/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_username_strdup2',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_username_strdup2",
        'positive_output_matches' => [qr/Unable to allocate memory/]
    },

    ### append_b64 tags
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag append_b64_toobig',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag append_b64_toobig",
        'positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_ENCODE_MESSAGE_TOOBIG/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag append_b64_calloc',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag append_b64_calloc",
        'positive_output_matches' => [qr/Unable to allocate memory/]
    },

    ### fko_encode_spa_data tags
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_encode_spa_data_init',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_encode_spa_data_init",
        'positive_output_matches' => [qr/FKO Context is not initialized/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_encode_spa_data_valid',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_encode_spa_data_valid",
        'positive_output_matches' => [qr/Missing or incomplete SPA data/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_encode_spa_data_calloc',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_encode_spa_data_calloc",
        'positive_output_matches' => [qr/Unable to allocate memory/]
    },

    ### timestamp tags
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_timestamp_init',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_timestamp_init",
        'positive_output_matches' => [qr/FKO Context is not initialized/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_timestamp_val',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_timestamp_val",
        'positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL/]
    },

    ### digest type
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag set_spa_digest_type_init',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag set_spa_digest_type_init",
        'positive_output_matches' => [qr/FKO Context is not initialized/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag set_spa_digest_type_val',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag set_spa_digest_type_val",
        'positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL/]
    },

    ### set digest
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_spa_digest_init',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_spa_digest_init",
        'positive_output_matches' => [qr/FKO Context is not initialized/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_spa_digest_encoded',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_spa_digest_encoded",
        'positive_output_matches' => [qr/There is no encoded data to process/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag set_digest_toobig',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag set_digest_toobig",
        'positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_TOOBIG/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag set_digest_invalidtype',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag set_digest_invalidtype",
        'positive_output_matches' => [qr/Invalid digest type/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag set_digest_calloc',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag set_digest_calloc",
        'positive_output_matches' => [qr/Unable to allocate memory/]
    },

    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_spa_encryption_type_init',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_spa_encryption_type_init",
        'positive_output_matches' => [qr/FKO Context is not initialized/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_spa_encryption_type_val',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_spa_encryption_type_val",
        'positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_spa_encryption_mode_init',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_spa_encryption_mode_init",
        'positive_output_matches' => [qr/FKO Context is not initialized/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_spa_encryption_mode_val',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_spa_encryption_mode_val",
        'positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_ENCRYPT_MODE_VALIDFAIL/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_spa_message_type_init',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_spa_message_type_init",
        'positive_output_matches' => [qr/FKO Context is not initialized/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag fko_set_spa_message_type_val',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag fko_set_spa_message_type_val",
        'positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL/]
    },

    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag is_valid_pt_msg_len_val',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag is_valid_pt_msg_len_val",
        'positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_ENCRYPT_PTLEN_VALIDFAIL/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag zero_buf_err',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag zero_buf_err",
        'positive_output_matches' => [qr/Could not zero out sensitive data/]
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'client',
        'detail' => 'tag zero_free_err',
        'function' => \&fault_injection_tag,
        'cmdline'  => "$default_client_hmac_args " .
            "--fault-injection-tag zero_free_err",
        'positive_output_matches' => [qr/Could not zero out sensitive data/]
    },

    ### fwknopd injections
    ### username tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_username_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_username_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_username_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_username_val",
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### timestamp tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_timestamp_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_timestamp_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_timestamp_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_timestamp_val",
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### message type tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_message_type_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_message_type_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_message_type_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_message_type_val",
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### message tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_message_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_message_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_message_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_message_val",
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### encryption mode tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_set_spa_encryption_mode_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_set_spa_encryption_mode_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_set_spa_encryption_mode_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_set_spa_encryption_mode_val",
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### set hmac type tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_set_spa_hmac_type_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_set_spa_hmac_type_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_set_spa_hmac_type_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_set_spa_hmac_type_val",
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### nat access tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_nat_access_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_nat_access_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_nat_access_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_nat_access_val",
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### server auth tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_server_auth_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_server_auth_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_server_auth_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_server_auth_val",
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### raw digest type tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_raw_spa_digest_type_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_raw_spa_digest_type_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### digest type tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_digest_type_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_digest_type_init --test",
            ### --test above since tag only triggered when dumping context
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_digest_type_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_digest_type_val --test",
            ### --test above since tag only triggered when dumping context
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### digest tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_digest_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_digest_init --test",
            ### --test above since tag only triggered when dumping context
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_digest_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_digest_val --test",
            ### --test above since tag only triggered when dumping context
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### client timeout tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_client_timeout_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_client_timeout_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_spa_client_timeout_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_spa_client_timeout_val",
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### version tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_version_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_version_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_version_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_version_val",
        'server_positive_output_matches' => [qr/Args contain invalid data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### digest type tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag set_spa_digest_type_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag set_spa_digest_type_init",
        'server_positive_output_matches' => [qr/Error setting digest type for SPA data\: FKO Context/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag set_spa_digest_type_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag set_spa_digest_type_val",
        'server_positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### raw digest tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_set_raw_spa_digest_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_set_raw_spa_digest_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_get_raw_spa_digest_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_get_raw_spa_digest_init",
        'server_positive_output_matches' => [qr/FKO Context is not initialized/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### zero out buffer tags
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag zero_free_err',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag zero_free_err",
        'server_positive_output_matches' => [qr/Could not zero out sensitive data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag zero_buf_err',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag zero_buf_err",
        'server_positive_output_matches' => [qr/Could not zero out sensitive data/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag is_valid_encoded_msg_len_val',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag is_valid_encoded_msg_len_val",
        'server_positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_FUNCS_NEW_MSGLEN_VALIDFAIL/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_new_with_data_msg',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_new_with_data_msg",
        'server_positive_output_matches' => [qr/FKO_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fko_new_with_data_keylen',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fko_new_with_data_keylen",
        'server_positive_output_matches' => [qr/Invalid key length/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### fw_config_init
    {
        'category' => 'fault injection',
        'subcategory' => 'server',
        'detail' => 'tag fw_config_init',
        'function' => \&fault_injection_tag,
        'no_ip_check' => 1,
        'client_pkt_tries' => 1,
        'cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--fault-injection-tag fw_config_init",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

);
