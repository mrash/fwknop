@cunit_tests = (
    {
        'category' => 'Cunit tests',
        'detail'   => 'fwknopd cunit tests',
        'function' => \&cunit_tests,
        'exec_err' => $NO,
        'cmdline' => " ../server/fwknopd_utests ",
        'negative_output_matches' => [qr/\.\.\.FAILED/],
    },
{
        'category' => 'Cunit tests',
        'detail'   => 'fwknop cunit tests',
        'function' => \&cunit_tests,
        'exec_err' => $NO,
        'cmdline' => " ../client/fwknop_utests ",
        'negative_output_matches' => [qr/\.\.\.FAILED/],
    },
{
        'category' => 'Cunit tests',
        'detail'   => 'fko cunit tests',
        'function' => \&cunit_tests,
        'exec_err' => $NO,
        'cmdline' => " ../lib/fko_utests ",
        'negative_output_matches' => [qr/\.\.\.FAILED/],
    },
);
