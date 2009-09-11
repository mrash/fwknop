BEGIN { $| = 1; print "1..41\n"; }
END {print "not ok 1\n" unless $loaded;}
use Crypt::Rijndael;
$loaded = 1;
print "ok 1\n";

$plaintext = chr(0) x 32;
for ($i=0; $i<32; $i++) {
  substr($plaintext, $i, 1)=chr($i);
}

$key = chr(0) x 32;
substr($key, 0, 1) = chr(1);

$ecb = new Crypt::Rijndael $key;

$crypted = $ecb->encrypt($plaintext);
print unpack("H*", $crypted) eq "f2258e225d794572393a6484cfced7cf925d1aa18366bcd93c33d104294c8a6f" ? "" : "not ", "ok 2\n";
print $ecb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 3\n";

$cbc = new Crypt::Rijndael $key, Crypt::Rijndael::MODE_CBC;
$crypted = $cbc->encrypt($plaintext);
print unpack("H*", $crypted) eq "f2258e225d794572393a6484cfced7cfb487a41f6b6286c00c9c8d80cb3ee9f8" ? "" : "not ", "ok 4\n";
$cbc = new Crypt::Rijndael $key, Crypt::Rijndael::MODE_CBC;
print $cbc->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 5\n";

$plaintext = chr(0) x 16;
$j = 0;
for ($i=0x00; $i<=0xff; $i += 0x11) {
  substr($plaintext, $j, 1) = chr($i);
  $j++;
}

$key = chr(0) x 32;
for ($i=0; $i<32; $i++) {
  substr($key, $i, 1) = chr($i);
}

# AES-256
$ecb = new Crypt::Rijndael $key;
$crypted = $ecb->encrypt($plaintext);
print unpack("H*", $crypted) eq "8ea2b7ca516745bfeafc49904b496089" ? "" : "not ", "ok 6\n";
print $ecb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 7\n";

# AES-192
$key = substr($key, 0, 24);
$ecb = new Crypt::Rijndael $key;
$crypted = $ecb->encrypt($plaintext);
print unpack("H*", $crypted) eq "dda97ca4864cdfe06eaf70a0ec0d7191" ? "" : "not ", "ok 8\n";
print $ecb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 9\n";

# AES-128
$key = substr($key, 0, 16);
$ecb = new Crypt::Rijndael $key;
$crypted = $ecb->encrypt($plaintext);
print unpack("H*", $crypted) eq "69c4e0d86a7b0430d8cdb78070b4c55a" ? "" : "not ", "ok 10\n";
print $ecb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 11\n";

# Modes of operation -- NIST paper tests

# ECB-AES-128
$ecb = new Crypt::Rijndael pack("H*", "2b7e151628aed2a6abf7158809cf4f3c");
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $ecb->encrypt($plaintext);
print unpack("H*", $crypted) eq "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4" ? "" : "not ", "ok 12\n";
print $ecb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 13\n";

# ECB-AES-192
$ecb = new Crypt::Rijndael pack("H*", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $ecb->encrypt($plaintext);
print unpack("H*", $crypted) eq "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e" ? "" : "not ", "ok 14\n";
print $ecb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 15\n";

# ECB-AES-256
$ecb = new Crypt::Rijndael pack("H*", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $ecb->encrypt($plaintext);
print unpack("H*", $crypted) eq "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7" ? "" : "not ", "ok 16\n";
print $ecb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 17\n";

# CBC-AES-128
$cbc = new Crypt::Rijndael pack("H*", "2b7e151628aed2a6abf7158809cf4f3c"), Crypt::Rijndael::MODE_CBC;
$cbc->set_iv(pack("H*", "000102030405060708090a0b0c0d0e0f"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $cbc->encrypt($plaintext);
print unpack("H*", $crypted) eq "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7" ? "" : "not ", "ok 18\n";
print $cbc->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 19\n";

# CBC-AES-192
$cbc = new Crypt::Rijndael pack("H*", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"), Crypt::Rijndael::MODE_CBC;
$cbc->set_iv(pack("H*", "000102030405060708090a0b0c0d0e0f"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $cbc->encrypt($plaintext);
print unpack("H*", $crypted) eq "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd" ? "" : "not ", "ok 20\n";
print $cbc->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 21\n";

# CBC-AES-192
$cbc = new Crypt::Rijndael pack("H*", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"), Crypt::Rijndael::MODE_CBC;
$cbc->set_iv(pack("H*", "000102030405060708090a0b0c0d0e0f"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $cbc->encrypt($plaintext);
print unpack("H*", $crypted) eq "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b" ? "" : "not ", "ok 22\n";
print $cbc->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 23\n";

# CFB128-AES-128
$cfb = new Crypt::Rijndael pack("H*", "2b7e151628aed2a6abf7158809cf4f3c"), Crypt::Rijndael::MODE_CFB;
$cfb->set_iv(pack("H*", "000102030405060708090a0b0c0d0e0f"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $cfb->encrypt($plaintext);
print unpack("H*", $crypted) eq "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6" ? "" : "not ", "ok 24\n";
print $cfb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 25\n";

# CFB128-AES-192
$cfb = new Crypt::Rijndael pack("H*", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"), Crypt::Rijndael::MODE_CFB;
$cfb->set_iv(pack("H*", "000102030405060708090a0b0c0d0e0f"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $cfb->encrypt($plaintext);
print unpack("H*", $crypted) eq "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff" ? "" : "not ", "ok 26\n";
print $cfb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 27\n";

# CFB128-AES-256
$cfb = new Crypt::Rijndael pack("H*", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"), Crypt::Rijndael::MODE_CFB;
$cfb->set_iv(pack("H*", "000102030405060708090a0b0c0d0e0f"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $cfb->encrypt($plaintext);
print unpack("H*", $crypted) eq "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471" ? "" : "not ", "ok 28\n";
print $cfb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 29\n";

# OFB-AES-128
$ofb = new Crypt::Rijndael pack("H*", "2b7e151628aed2a6abf7158809cf4f3c"), Crypt::Rijndael::MODE_OFB;
$ofb->set_iv(pack("H*", "000102030405060708090a0b0c0d0e0f"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $ofb->encrypt($plaintext);
print unpack("H*", $crypted) eq "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e" ? "" : "not ", "ok 30\n";
print $ofb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 31\n";

# OFB-AES-192
$ofb = new Crypt::Rijndael pack("H*", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"), Crypt::Rijndael::MODE_OFB;
$ofb->set_iv(pack("H*", "000102030405060708090a0b0c0d0e0f"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $ofb->encrypt($plaintext);
print unpack("H*", $crypted) eq "cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a" ? "" : "not ", "ok 32\n";
print $ofb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 33\n";

# OFB-AES-256
$ofb = new Crypt::Rijndael pack("H*", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"), Crypt::Rijndael::MODE_OFB;
$ofb->set_iv(pack("H*", "000102030405060708090a0b0c0d0e0f"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $ofb->encrypt($plaintext);
print unpack("H*", $crypted) eq "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484" ? "" : "not ", "ok 34\n";
print $ofb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 35\n";

# CTR-AES-128
$ctr = new Crypt::Rijndael pack("H*", "2b7e151628aed2a6abf7158809cf4f3c"), Crypt::Rijndael::MODE_CTR;
$ctr->set_iv(pack("H*", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $ctr->encrypt($plaintext);
print unpack("H*", $crypted) eq "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee" ? "" : "not ", "ok 36\n";
print $ctr->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 37\n";

# CTR-AES-192
$ctr = new Crypt::Rijndael pack("H*", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"), Crypt::Rijndael::MODE_CTR;
$ctr->set_iv(pack("H*", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $ctr->encrypt($plaintext);
print unpack("H*", $crypted) eq "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050" ? "" : "not ", "ok 38\n";
print $ctr->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 39\n";

# CTR-AES-256
$ctr = new Crypt::Rijndael pack("H*", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"), Crypt::Rijndael::MODE_CTR;
$ctr->set_iv(pack("H*", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
$plaintext = pack("H*", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
$crypted = $ctr->encrypt($plaintext);
print unpack("H*", $crypted) eq "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6" ? "" : "not ", "ok 40\n";
print $ctr->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 41\n";
