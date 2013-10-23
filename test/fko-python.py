#!/usr/bin/env python

#
# Import the Fko class and all constants.
#
from fko import *

def main():

    # Create an Fko instance with an empty context.
    #
    fko = Fko()

    # Set the HMAC digest algorithm
    #
    fko.hmac_type(FKO_HMAC_SHA512)

    # Set the SPA message (Note: Access request is default if not specified).
    #
    fko.spa_message("127.0.0.2,tcp/22")

    # Create the final SPA data message string.
    #
    fko.spa_data_final("testkey1", "testkey2")

    # print the spa message.
    #
    print "SPA packet data:", fko.spa_data()

    # Print some of the data:
    #
    print "Version:", fko.version()
    print "Timestamp:", fko.timestamp()
    print "Username:", fko.username()
    print "Digest Type (value):", fko.digest_type()
    print "Digest Type (string):", fko.digest_type_str()
    print "Digest:", fko.spa_digest()
    print "HMAC Type (value):", fko.hmac_type()
    print "HMAC Type (string):", fko.hmac_type_str()
    print "HMAC:", fko.get_spa_hmac()
    print "SPA Message:", fko.spa_message()

if __name__ == "__main__":
    main()
