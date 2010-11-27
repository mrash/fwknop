#
##############################################################################
#
# File:    fko.py
#
# Author:  Damien S. Stuart <dstuart@dstuart.org>
#
# Purpose: Module that provides a class that implements the functions for
#          managing fwknop Single Packet Authorization (SPA) via the fwknop
#          library (libfko).
#
##############################################################################
#
import _fko

# FKO Constants definitions
#
# Message types
FKO_COMMAND_MSG = 0
FKO_ACCESS_MSG = 1
FKO_NAT_ACCESS_MSG = 2
FKO_CLIENT_TIMEOUT_ACCESS_MSG = 3
FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG = 4
FKO_LOCAL_NAT_ACCESS_MSG = 5
FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG = 6

# Digest types
FKO_DIGEST_MD5 = 1
FKO_DIGEST_SHA1 = 2
FKO_DIGEST_SHA256 = 3
FKO_DIGEST_SHA384 = 4
FKO_DIGEST_SHA512 = 5

# Encryption types
FKO_ENCRYPTION_RIJNDAEL = 1
FKO_ENCRYPTION_GPG = 2

# FKO error codes
FKO_SUCCESS = 0
FKO_ERROR_CTX_NOT_INITIALIZED = 1
FKO_ERROR_MEMORY_ALLOCATION = 2
FKO_ERROR_FILESYSTEM_OPERATION = 3
FKO_ERROR_INVALID_DATA = 4
FKO_ERROR_DATA_TOO_LARGE = 5
FKO_ERROR_USERNAME_UNKNOWN = 6
FKO_ERROR_INCOMPLETE_SPA_DATA = 7
FKO_ERROR_MISSING_ENCODED_DATA = 8
FKO_ERROR_INVALID_DIGEST_TYPE = 9
FKO_ERROR_INVALID_ALLOW_IP = 10
FKO_ERROR_INVALID_SPA_COMMAND_MSG = 11
FKO_ERROR_INVALID_SPA_ACCESS_MSG = 12
FKO_ERROR_INVALID_SPA_NAT_ACCESS_MSG = 13
FKO_ERROR_INVALID_ENCRYPTION_TYPE = 14
FKO_ERROR_WRONG_ENCRYPTION_TYPE = 15
FKO_ERROR_DECRYPTION_SIZE = 16
FKO_ERROR_DECRYPTION_FAILURE = 17
FKO_ERROR_DIGEST_VERIFICATION_FAILED = 18
FKO_ERROR_UNSUPPORTED_FEATURE = 19
FKO_ERROR_UNKNOWN = 20
# Start GPGME-related errors
GPGME_ERR_START = 21
FKO_ERROR_MISSING_GPG_KEY_DATA = 22
FKO_ERROR_GPGME_NO_OPENPGP = 23
FKO_ERROR_GPGME_CONTEXT = 24
FKO_ERROR_GPGME_PLAINTEXT_DATA_OBJ = 25
FKO_ERROR_GPGME_SET_PROTOCOL = 26
FKO_ERROR_GPGME_CIPHER_DATA_OBJ = 27
FKO_ERROR_GPGME_BAD_PASSPHRASE = 28
FKO_ERROR_GPGME_ENCRYPT_SIGN = 29
FKO_ERROR_GPGME_CONTEXT_SIGNER_KEY = 30
FKO_ERROR_GPGME_SIGNER_KEYLIST_START = 31
FKO_ERROR_GPGME_SIGNER_KEY_NOT_FOUND = 32
FKO_ERROR_GPGME_SIGNER_KEY_AMBIGUOUS = 33
FKO_ERROR_GPGME_ADD_SIGNER = 34
FKO_ERROR_GPGME_CONTEXT_RECIPIENT_KEY = 35
FKO_ERROR_GPGME_RECIPIENT_KEYLIST_START = 36
FKO_ERROR_GPGME_RECIPIENT_KEY_NOT_FOUND = 37
FKO_ERROR_GPGME_RECIPIENT_KEY_AMBIGUOUS = 38
FKO_ERROR_GPGME_DECRYPT_FAILED = 39
FKO_ERROR_GPGME_DECRYPT_UNSUPPORTED_ALGORITHM = 40
FKO_ERROR_GPGME_BAD_GPG_EXE = 41
FKO_ERROR_GPGME_BAD_HOME_DIR = 42
FKO_ERROR_GPGME_SET_HOME_DIR = 43
FKO_ERROR_GPGME_NO_SIGNATURE = 44
FKO_ERROR_GPGME_BAD_SIGNATURE = 45
FKO_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED = 46
### End FKO Constants ###

class Fko:
    """This class wraps the Firewall KNock OPerator (fwknop) library,
       libfko.  It provides the functionality to manage and process
       Single Packet Authorization (SPA) data.

    """

    def __init__(self, spa_data=None, key=None):
        """Constructor for the Fko class.

        Creates and intitializes the fko context.

        If no arguments are given, and empty context is create with
        some default values.  See the libfko documentation for details
        on these defaults.

        If spa_data and key is supplied, the context is created, then
        the SPA data is decrypted using the key. If successful, the SPA
        data is parsed into the context's data structure.

        If spa_data is supplied without the key, then the encrypted data
        is stored in the context and can be decoded later (see libfko docs).

        """

        # If there is SPA data, attempt to process it. Otherwise, create
        # an empty context.
        #
        if(spa_data != None):
            self.ctx = _fko.init_ctx_with_data(spa_data, key)
        else:
            self.ctx = _fko.init_ctx()

    # Destructor to make sure the fko context is properly destroyed and
    # the memory it was using is released.
    #
    def __del__(self):
        _fko.destroy_ctx(self.ctx)

    ### FKO data functions and operations. ###

    def version(self):
        return _fko.get_version(self.ctx)

    def rand_value(self, val=None):
        if(val != None):
            _fko.set_rand_value(self.ctx, val)
        else:
            return _fko.get_rand_value(self.ctx)

    def username(self, val=None):
        if(val != None):
            _fko.set_username(self.ctx, val)
        else:
            return _fko.get_username(self.ctx)

    def timestamp(self, val=None):
        if(val != None):
            _fko.set_timestamp(self.ctx, val)
        else:
            return _fko.get_timestamp(self.ctx)

    def digest_type(self, val=None):
        if(val != None):
            _fko.set_spa_digest_type(self.ctx, val)
        else:
            return _fko.get_spa_digest_type(self.ctx)

    def encryption_type(self, val=None):
        if(val != None):
            _fko.set_spa_encryption_type(self.ctx, val)
        else:
            return _fko.get_spa_encryption_type(self.ctx)

    def message_type(self, val=None):
        if(val != None):
            _fko.set_spa_message_type(self.ctx, val)
        else:
            return _fko.get_spa_message_type(self.ctx)

    def spa_message(self, val=None):
        if(val != None):
            _fko.set_spa_message(self.ctx, val)
        else:
            return _fko.get_spa_message(self.ctx)

    def spa_nat_access(self, val=None):
        if(val != None):
            _fko.set_spa_nat_access(self.ctx, val)
        else:
            return _fko.get_spa_nat_access(self.ctx)

    def spa_server_auth(self, val=None):
        if(val != None):
            _fko.set_spa_server_auth(self.ctx, val)
        else:
            return _fko.get_spa_server_auth(self.ctx)

    def spa_client_timeout(self, val=None):
        if(val != None):
            _fko.set_spa_client_timeout(self.ctx, val)
        else:
            return _fko.get_spa_client_timeout(self.ctx)

    def spa_digest(self):
            return _fko.get_spa_digest(self.ctx)

    def gen_spa_digest(self):
        _fko.set_spa_digest(self.ctx)

    def spa_data(self, val=None):
        if(val != None):
            _fko.set_spa_data(self.ctx, val)
        else:
            return _fko.get_spa_data(self.ctx)

    def encoded_data(self):
        return _fko.get_encoded_data(self.ctx)

    def spa_data_final(self, key):
        _fko.spa_data_final(self.ctx, key)

    def gen_spa_data(self, key):
        _fko.spa_data_final(self.ctx, key)

    def encode_spa_data(self):
        _fko.encode_spa_data(self.ctx)

    def decode_spa_data(self):
        _fko.decode_spa_data(self.ctx)

    def encrypt_spa_data(self, key):
        _fko.encrypt_spa_data(self.ctx, key)

    def decrypt_spa_data(self, key):
        _fko.decrypt_spa_data(self.ctx, key)

    # GPG-related functions.

    def gpg_recipient(self, val=None):
        if(val != None):
            _fko.set_gpg_recipient(self.ctx, val)
        else:
            return _fko.get_gpg_recipient(self.ctx)

    def gpg_signer(self, val=None):
        if(val != None):
            _fko.set_gpg_signer(self.ctx, val)
        else:
            return _fko.get_gpg_signer(self.ctx)

    def gpg_home_dir(self, val=None):
        if(val != None):
            _fko.set_gpg_home_dir(self.ctx, val)
        else:
            return _fko.get_gpg_home_dir(self.ctx)

    def gpg_signature_verify(self, val=None):
        if(val != None):
            _fko.set_gpg_signature_verify(self.ctx, val)
        else:
            return _fko.get_gpg_signature_verify(self.ctx)

    def gpg_ignore_verify_error(self, val=None):
        if(val != None):
            _fko.set_gpg_ignore_verify_error(self.ctx, val)
        else:
            return _fko.get_gpg_ignore_verify_error(self.ctx)

    def gpg_exe(self, val=None):
        if(val != None):
            _fko.set_gpg_exe(self.ctx, val)
        else:
            return _fko.get_gpg_exe(self.ctx)

    def gpg_signature_id(self):
        return _fko.get_gpg_signature_id(self.ctx)

    def gpg_signature_fpr(self):
        return _fko.get_gpg_signature_fpr(self.ctx)

    def gpg_signature_summary(self):
        return _fko.get_gpg_signature_summary(self.ctx)

    def gpg_signature_status(self):
        return _fko.get_gpg_signature_status(self.ctx)

    def gpg_signature_id_match(self, val):
        if(_fko.gpg_signature_id_match(self.ctx) > 0):
            return True
        return False

    def gpg_signature_fpr_match(self, val):
        if(_fko.gpg_signature_fpr_match(self.ctx) > 0):
            return True
        return False

    # Error message string function.

    def errstr(self, val):
        return _fko.errstr(code)

    # FKO type lookup functions.

    def message_type_str(self, val=None):
        if val == None:
            val = _fko.get_spa_message_type(self.ctx)

        if val == FKO_COMMAND_MSG:
            mts = "Command Message"
        elif val == FKO_ACCESS_MSG:
            mts = "Access Message"
        elif val == FKO_NAT_ACCESS_MSG:
            mts = "NAT Access Message"
        elif val == FKO_CLIENT_TIMEOUT_ACCESS_MSG:
            mts = "Access Message with timeout"
        elif val == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG:
            mts = "NAT access Message with timeout"
        elif val == FKO_LOCAL_NAT_ACCESS_MSG:
            mts = "Local NAT Access Message"
        elif val == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG:
            mts = "Local NAT Access Message with timeout"
        else:
            mts = "Unknown message type"
        return mts

    def digest_type_str(self, val=None):
        if val == None:
            val = _fko.get_spa_digest_type(self.ctx)

        if val == FKO_DIGEST_MD5:
            dts = "MD5"
        elif val == FKO_DIGEST_SHA1:
            dts = "SHA1"
        elif val == FKO_DIGEST_SHA256:
            dts = "SHA256"
        elif val == FKO_DIGEST_SHA384:
            dts = "SHA384"
        elif val == FKO_DIGEST_SHA512:
            dts = "SHA512"
        else:
            dts = "Unknown digest type"
        return dts

    def encryption_type_str(self, val=None):
        if val == None:
            val = _fko.get_spa_encryption_type(self.ctx)

        if val == FKO_ENCRYPTION_RIJNDAEL:
            ets = "Rijndael (AES)"
        elif val == FKO_ENCRYPTION_GPG:
            ets = "GPG"
        else:
            ets = "Unknown encryption type"
        return ets

###EOF###
