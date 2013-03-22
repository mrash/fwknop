@perl_FKO_module = (
    ### perl module checks
    {
        'category' => 'perl FKO module',
        'subcategory' => 'compile/install',
        'detail'   => 'to: ./FKO',
        'function' => \&perl_fko_module_compile_install,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'FUZZING',
        'detail'   => 'generate invalid SPA pkts',
        'function' => \&perl_fko_module_assume_patches_generate_fuzzing_spa_packets,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'FUZZING',
        'detail'   => 'generate invalid encoded pkts',
        'function' => \&perl_fko_module_assume_patches_generate_fuzzing_encoding_spa_packets,
        'fatal'    => $NO
    },

    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'create/destroy FKO object',
        'function' => \&perl_fko_module_new_object,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'create/destroy 1000 FKO objects',
        'function' => \&perl_fko_module_new_objects_1000,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko version',
        'function' => \&perl_fko_module_version,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get random data',
        'function' => \&perl_fko_module_rand,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set username',
        'function' => \&perl_fko_module_user,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko timestamp',
        'function' => \&perl_fko_module_timestamp,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set msg types',
        'function' => \&perl_fko_module_msg_types,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set access msgs',
        'function' => \&perl_fko_module_access_msgs,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set NAT access msgs',
        'function' => \&perl_fko_module_nat_access_msgs,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set cmd msgs',
        'function' => \&perl_fko_module_cmd_msgs,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'basic ops',
        'detail'   => 'libfko get/set client timeout',
        'function' => \&perl_fko_module_client_timeout,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'encrypt/decrypt',
        'detail'   => 'libfko complete cycle',
        'function' => \&perl_fko_module_complete_cycle,
        'set_legacy_iv' => $NO,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'encrypt/decrypt',
        'detail'   => 'libfko complete cycle (lIV)',
        'function' => \&perl_fko_module_complete_cycle,
        'set_legacy_iv' => $YES,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'HMAC encrypt/decrypt',
        'detail'   => 'libfko complete cycle',
        'function' => \&perl_fko_module_complete_cycle_hmac,
        'set_legacy_iv' => $NO,
        'fatal'    => $NO
    },

    {
        'category' => 'perl FKO module',
        'subcategory' => 'encrypt/decrypt',
        'detail'   => 'truncated keys',
        'function' => \&perl_fko_module_rijndael_truncated_keys,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'encrypt/decrypt',
        'detail'   => 'complete cycle (mod reuse)',
        'function' => \&perl_fko_module_complete_cycle_module_reuse,
        'set_legacy_iv' => $NO,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'encrypt/decrypt',
        'detail'   => 'complete cycle (mod reuse, lIV)',
        'function' => \&perl_fko_module_complete_cycle_module_reuse,
        'set_legacy_iv' => $YES,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'fuzzing data',
        'detail'   => 'legacy IV REPLPKTS',
        'function' => \&perl_fko_module_full_fuzzing_packets,
        'set_legacy_iv' => $YES,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'fuzzing data',
        'detail'   => 'non-legacy IV REPLPKTS',
        'function' => \&perl_fko_module_full_fuzzing_packets,
        'set_legacy_iv' => $NO,
        'fatal'    => $NO
    },

    {
        'category' => 'perl FKO module',
        'subcategory' => 'compatibility',
        'detail'   => 'client FKO -> C server',
        'function' => \&perl_fko_module_client_compatibility,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'compatibility',
        'detail'   => 'FKO -> C invalid legacy IV',
        'function' => \&perl_fko_module_client_compatibility,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "$intf_str",
        'server_positive_output_matches' => [qr/Decryption failed/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'fatal'    => $NO
    },
    {
        'category' => 'perl FKO module',
        'subcategory' => 'compatibility',
        'detail'   => 'FKO -> C valid legacy IV',
        'function' => \&perl_fko_module_client_compatibility,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "$intf_str",
        'set_legacy_iv' => $YES,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
);
