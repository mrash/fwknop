#!/usr/bin/python

#
# Import the Fko class and all constants.
#
from fko import *

# Create an Fko instance with an empty context.
#
fko = Fko()

fko.hmac_type(FKO_HMAC_SHA512)

# Set the SPA message (Note: Access request is default if not specified).
#
fko.spa_message("0.0.0.0,tcp/22")

# Create the final SPA data message string.
#
fko.spa_data_final("testtest", "blah")

# print the spa message.
#
print fko.spa_data()

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
