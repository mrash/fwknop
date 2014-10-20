
@configure_args = (
    {
        'category' => 'configure args',
        'subcategory' => 'compile',
        'detail'   => '--enable-udp-server no libpcap usage',
        'function' => \&configure_args_udp_server_no_libpcap,
    },
);
