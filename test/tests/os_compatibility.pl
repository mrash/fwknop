@os_compatibility = (

    {
        'category' => 'Rijndael',
        'subcategory' => 'client->server OS compatibility',
        'detail'   => 'v2.5 Ubuntu-12.04',
        'function' => \&os_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '97qvmEEOJyCJk6eLpTpqG+7nx4Is+Ruh2ppeaVMkWB/hLpUEE/Znah9RF5JCbB' .
            'lAZNE2O1w83mout+oyWSj4payd0yuWckikoZYjc7tSSgHIFikOhTm9CHi8ERe9' .
            'jLEYw1wvqE2B7Vvz7XyefNILZdHa+Vx5zYM0o',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client->server OS compatibility',
        'detail'   => 'v2.5 Ubuntu-13.04',
        'function' => \&os_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '/gNh7EXXyg23dcrYz0g+KaWJWvTwuPuP349YzrwcLVvVSc5RVJdakdx9Qv0xAWe' .
            'GsZJPmv2e1U31SMrdgF+o7/f2qRDH2hwPU8XLKS73rXpAhZKVAF/crt00HDmaH0' .
            'p+hc3ngPtmE/j0PKeUD+GM81YQPO9NdZu4s',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client->server OS compatibility',
        'detail'   => 'v2.5 FreeBSD-8.2',
        'function' => \&os_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '9oprfzL5On8uyH5qJ0JQGLGddfGMI8j9YSafjFth2hiJrYG75FqBJNVvnsvetTA' .
            '46kFmbdXHZCUx5iom9jOtpQnMvZJGex65vV4bSFdVwaoJ/ICkiRHbbzSTZo8qmp' .
            'FTLSYWVhTWQddj4j80Ne6GH0h3zXomg9fJU',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client->server OS compatibility',
        'detail'   => 'v2.5 OpenBSD-4.9',
        'function' => \&os_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '+HNnKhqILxDz1IhEeJnWIQF2v/7H7yZ3TZegUeNltMdUP7SYAHxWg8WD2N4LF3g' .
            'dejv3UxC/FRlHgJz4UeRkloFCQQ0tkQLx6MSoCQHKPlNxATKsfLL3UfHpKbhRG8' .
            'a8S9q8lojKxiWuLZU64h5LXjhH7rR7riyds',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client->server OS compatibility',
        'detail'   => 'v2.5 Ubuntu-12.04',
        'function' => \&os_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '97UwsN9v6iQxs9/hrSnbRKDF8byw+niI0PDx0AvuhLP2NmAaz4qktRjl1p7lUA' .
            'GBzLi+4o58wJCkHs3QUluHBcMAS6hqIT7qMc/aQlcJzNsQWEfPCkAE0m1zLnjG' .
            'GE3C9u943F+0csrZs+ysKKca+sVBcAKhsTNsMjT9HojVMdk+r9RhJqUa2JJz7f' .
            'ZIZauvBrygBVg0yh6o',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client->server OS compatibility',
        'detail'   => 'v2.5 Ubuntu-13.04',
        'function' => \&os_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '/+pXmgSat9BUrGQLUFFELlOSqVAHSzY/BhPC2eP/gYfW5OrLplejpwh7MYoU06G' .
            'PHRx4vqMBYjxzOcrWp0rFC1rrPzP16nFnRUo5P3jxg1FMjMLI48RrSwCcx8G1qk' .
            'mknUjmg4+8maPhus2x7YhoPTMfMZijWKOaMWhX1G0khDqFfGU8GuehpQdwuGdX/' .
            'oGZnheeQyczK4pY',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client->server OS compatibility',
        'detail'   => 'v2.5 FreeBSD-8.2',
        'function' => \&os_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '8au7bGF/FL3EwjMVtTQpAtrzW4JvYAlAtbuEHGdxYS0E0vo18t9dpKoYA/hCLMu' .
            'XqFYIH6zINNYUYjplvL9+zFeygIxiT9dm6PIjjossOIRRNOwdwbS8oeBzsckqMn' .
            'BDo3d0K5I4mhwuWVHyTZUg441+kfm7O8TesDhUoy2ftqTGR3+GHi52/NIVctEAp' .
            'WR6NZowCcHElB9E',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client->server OS compatibility',
        'detail'   => 'v2.5 OpenBSD-4.9',
        'function' => \&os_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '9LnU3Tlrn7tpcOxviTD5DHlXZ9T0Sj9R92yvm319zB1xzhMYuwB18C4qgScj5q' .
            'Vop4zyz0L1LQYMZ1/O3S2dqafGLIqSwk7j6YiH0ENVafQvuFVFG8ooeBRxFqzw' .
            'YnywR5R9Drrw+hMxpl40HDb1O07xN7WBOSvNgU2vi8MHT7MSZVh02PKRF8aReL' .
            'cQTD2sxRsn5tGfehC8',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
);
