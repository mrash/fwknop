@rijndael_fuzzing = (
    ### fuzzing tests
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'overly long port value',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A \
        # "tcp/`perl -e '{print "1"x"40"}'`" -a 127.0.0.2 -D 127.0.0.1 \
        # --get-key local_spa.key --verbose --verbose
        #
        # This problem was found by Fernando Arnaboldi of IOActive and exploits
        # a buffer overflow in the fwknopd servers prior to 2.0.3 from
        # authenticated clients.
        #
        'fuzzing_pkt' =>
            '+JzxeTGlc6lwwzbJSrYChKx8bonWBIPajwGfEtGOaoglcMLbTY/GGXo/nxqiN1LykFS' .
            'lDFXgrkyx2emJ7NGzYqQPUYZxLdZRocR9aRIptvXLLIPBcIpJASi/TUiJlw7CDFMcj0' .
            'ptSBJJUZi0tozpKHETp3AgqfzyOy5FNs38aZsV5/sDl3Pt+kF7fTZJ+YLbmYY4yCUz2' .
            'ZUYoCaJ7X78ULyJTi5eT7nug',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'overly long proto value',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A \
        # "tcp`perl -e '{print "A"x"28"}'`/1" -a 127.0.0.2 -D 127.0.0.1 \
        # --get-key local_spa.key --verbose --verbose
        #
        # This problem was found by Fernando Arnaboldi of IOActive and exploits
        # a buffer overflow in the fwknopd servers prior to 2.0.3 from
        # authenticated clients.
        #
        'fuzzing_pkt' =>
            '/im5MiJQmOdzqrdWXv+AjEtAm/HsLrdaTFcSw3ZskqpGOdDIrSCz3VXbFfv7qDkc5Y4' .
            'q/k1mRXl9SGzpug87U5dZSyCdAr30z7/2kUFEPTGOQBi/x+L1t1pvdkm4xg13t09ldm' .
            '5OD8KiV6qzqLOvN4ULJjvvJJWBZ9qvo/f2Q9Wf67g2KHiwS6EeCINAuMoUw/mNRQMa4' .
            'oGnOXu3/DeWHJAwtSeh7EAr4',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'overly long IP value',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A tcp/22 \
        # -a `perl -e '{print "1"x"136"}'`.0.0.1 -D 127.0.0.1 \
        # --get-key local_spa.key --verbose --verbose
        #
        # This problem was found by Fernando Arnaboldi of IOActive and exploits
        # a condition in which pre-2.0.3 fwknopd servers fail to properly validate
        # allow IP addresses from malicious authenticated clients.
        #
        'fuzzing_pkt' =>
            '93f2rhsXLmBoPicWvYTqrbp+6lNqvWDc8dzmX2s3settwjBGRAXm33TB9agibEphrBu' .
            '3d+7DEsivZLDS6Kz0JwdjX7t0J9c8es+DVNjlLnPtVNcxhs+2kUzimNrgysIXQRJ+GF' .
            'GbhdxiXCqdy1vWxWpdoaZmY/CeGIkpoFJFPbJhCRLLX25UMvMF2wXj02MpI4d3t1/6W' .
            'DM3taM3kZsiFv6HxFjAhIEuQ1oAg2OgRGXkDmT3jDNZMHUm0d4Ahm9LonG7RbOxq/B0' .
            'qUvY8lkymbwvjelVok7Lvlc06cRhN4zm32D4V05g0vQS3PlX9C+mgph9DeAPVX+D8iZ' .
            '8lGrxcPSfbCOW61k0MP+q1EhLZkc1qAm5g2+2cLNZcoBNEdh3yj8OTPZJyBVw',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'negative port value',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A \
        # tcp/-33 -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key \
        # --verbose --verbose
        #
        'fuzzing_pkt' =>
            '/weoc+pEuQknZo8ImWTQBB+/PwSJ2/TcrmFoSkxpRXX4+jlUxoJakHrioxh8rhLmAD9' .
            '8E4lMnq+EbM2XYdhs2alpZ5bovAFojMsYRWwr/BvRO4Um4Fmo9z9sY3DR477TXNYXBR' .
            'iGXWxSL4u+AWSSePK3qiiYoRQVw',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'null port value',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A tcp/ \
        # -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key \
        # --verbose --verbose
        #
        'fuzzing_pkt' =>
            '94nu7hvq6V/3A27GzjHwfPnPCQfs44ySlraIFYHOAqy5YqjkrBS67nH35tX55N1BrYZ' .
            '07zvcT03keUhLE1Uo7Wme1nE7BfTOG5stmIK1UQI85sL52//lDHu+xCqNcL7GUKbVRz' .
            'ekw+EUscVvUkrsRcVtSvOm+fCNo',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'long FKO protocol value (enc mode trigger)',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A tcp/22 \
        # -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key --verbose --verbose
        #
        # This problem was found by Fernando Arnaboldi of IOActive and is designed
        # to have fwknopd look for a mode decryption mode for a long Rijndael-
        # encrypted SPA packet
        #
        'fuzzing_pkt' =>
            '/ewH/k1XsDX+VQ8NlNvCZ4P2QOl/4IpJYXkq4TtAe3899OtApXJiTtPCuYW70XPuxge' .
            'MtFjc4UfslK/r9v+FYfyd3fIIHCz0Q0M4+nM3agTLmJj8nOxk6ZeBj82SDQWhHAxGdJ' .
            'IQALPve0ug4cuGxS3b4M+2Q/Av9i2tU3Lzlogw3sY0tk6wGf4zZk4UsviVXYpINniGT' .
            'RhYSIQ1dfdkng7hKiHMDaObYY1GFp4nxEt/QjasAwvE+7/iFyoKN+IRpGG4v4hGEPh2' .
            'vTDqmvfRuIHtgFD7NxZjt+m/jjcu0gkdWEoD4fenwGU35FlvchyM2AiAEw7yRzSABfn' .
            'R9d3sYZGMtyASw2O1vSluwIxUUnDop3gxEIhJEj8h+01pA3K+klSpALeY9EZgHqYC7E' .
            'ETuPS6dZ3764nWohtCY67JvNUX7TtNDNc2qrhrapdRP17+PT2Vh4s9m38V3WwVWC3uH' .
            'X/klLZcHIt+aRDV+uekw9GOKSgwFL2ekPpr3gXxigc3zrxel5hcsqLOpVUa4CP/0HkG' .
            'F0NPQvOT3ZvpeIJnirKP1ZX9gDFinqhuzL7oqktW61e1iwe7KZEdrZV0k2KZwyb8qU5' .
            'rPAEnw',
        'server_positive_output_matches' => [qr/No\sstanza\sencryption\smode\smatch/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'long FKO protocol value (Rijndael trigger)',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A tcp/22 \
        # -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key --verbose --verbose
        #
        # This problem was found by Fernando Arnaboldi of IOActive and is designed
        # to have fwknopd look for a mode decryption mode for a long Rijndael-
        # encrypted SPA packet
        #
        'fuzzing_pkt' =>
            '+YQNu4BFgiNeu8HeiBiNKriqCFSseALt9vJaKzkzK/OF4pjkJcvhGEOi7fEVXqn3VIdlGR' .
            'DmBul2I7H3z18U9E97bWGgT9NexKgEPCuekL18ZEPf5xR3JleNsNWatqYgAOkgN8ZWE69Q' .
            'qQUYYhxTvJHS6R+5JqFKB3A44hMXoICdYNkn9MAktHxk3PbbpQ+nA+jESwVCra2doAiLiM' .
            'ucvGIZZiTv0Mc1blFYIE2zqZ/C7ct1V+ukwSkUv0r87eA7uJhmlpThRsL0dN6iekJ6i87B' .
            'tE8QyuOXzOMftI11SUn/LwqD4RMdR21rvLrzR6ZB5eUX2UBpODyzX6n+PJJkTWCuFVT4z1' .
            'MKY',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
    },

    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'null proto value',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A /22 \
        # -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key \
        # --verbose --verbose
        #
        'fuzzing_pkt' =>
            '/JT14qxh9P4iy+CuUZahThaQjoEuL2zd46a+jL6sTrBZJSa6faUX4dH5fte/4ZJv+9f' .
            'd/diWYKAUvdQ4DydPGlR7mwQa2W+obKpqrsTBz7D4054z6ATAOGpCtifakEVl1XRc2+' .
            'hW04WpY8mdUNu9i+PrfPr7/KxqU',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'invalid NAT IP',
        'function' => \&fuzzer,
        ### this packet was generated with a modified fwknop client via the
        ### following command line:
        #
        # LD_LIBRARY_PATH=../lib/.libs  ../client/.libs/fwknop -A tcp/22 \
        # -a 127.0.0.2 -D 127.0.0.1 --get-key local_spa.key --verbose \
        # --verbose -N 999.1.1.1:22
        'fuzzing_pkt' =>
            '/v/kYVOqw+NCkg8CNEphPPvH3dOAECWjqiF+NNYnK7yKHer/Gy8wCVNa/Rr/Wnm' .
            'siApB3jrXEfyEY3yebJV+PHoYIYC3+4Trt2jxw0m+6iR231Ywhw1JetIPwsv7iQ' .
            'ATvSTpZ+qiaoN0PPfy0+7yM6KlaQIu7bfG5E2a6VJTqTZ1qYz3H7QaJfbAtOD8j' .
            'yEkDgP5+f49xrRA',
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging_nat'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
    },

    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'invalid SOURCE access.conf',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'fuzz_source'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'positive_output_matches' => [qr/Fatal\sinvalid/],
        'exec_err' => $YES,
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'invalid OPEN_PORTS access.conf',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'fuzz_open_ports'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'positive_output_matches' => [qr/Fatal\sinvalid/],
        'exec_err' => $YES,
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'invalid RESTRICT_PORTS access.conf',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'fuzz_restrict_ports'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'positive_output_matches' => [qr/Fatal\sinvalid/],
        'exec_err' => $YES,
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'non-base64 altered SPA data',
        'function' => \&altered_non_base64_spa_data,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'base64 altered SPA data',
        'function' => \&altered_base64_spa_data,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'appended data to SPA pkt',
        'function' => \&appended_spa_data,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'FUZZING',
        'detail'   => 'prepended data to SPA pkt',
        'function' => \&prepended_spa_data,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
    },
);
