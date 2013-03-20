@python_fko = (
    {
        'category' => 'python fko extension',
        'subcategory' => 'compile/install',
        'detail'   => 'to: ./python_fko/',
        'function' => \&python_fko_compile_install,
        'fatal'    => $NO
    },
    {
        'category' => 'python fko extension',
        'subcategory' => 'basic exec',
        'detail'   => 'import and use fko',
        'function' => \&python_fko_basic_exec,
        'fatal'    => $NO
    },

);
