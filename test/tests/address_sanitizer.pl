@address_sanitizer = (
    ### this verifies that Google's Address Sanitizer is functioning properly
    ### if fwknop has been compiled with it.
    {
        'category' => 'ASAN',
        'subcategory' => 'Address Sanitizer',
        'detail'   => 'crash verification',
        'function' => \&asan_verification,
    },
);
