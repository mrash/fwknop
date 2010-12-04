"""Wrapper functions for libfko.

The fko module provides a class that implements the functions for
managing fwknop Single Packet Authorization (SPA) via the fwknop
library (libfko).

You can find more detailed information in the libfko documention
(try "info libfko" if you have the standard GNU texinfo tools).

Example simple minimal fknop client:

    import fko
    import socket

    fko_port = 62201
    fko_host = "192.168.7.67"

    f = fko.Fko()
    f.spa_message('192.168.7.5,tcp/22')
    f.spa_data_final('put_pw_here')

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(f.spa_data(), (fko_host, fko_port))
    s.close()
"""
import _fko

# FKO Constants definitions

"""Message type constants
"""
FKO_COMMAND_MSG = 0
FKO_ACCESS_MSG = 1
FKO_NAT_ACCESS_MSG = 2
FKO_CLIENT_TIMEOUT_ACCESS_MSG = 3
FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG = 4
FKO_LOCAL_NAT_ACCESS_MSG = 5
FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG = 6

"""Digest type constants
"""
FKO_DIGEST_MD5 = 1
FKO_DIGEST_SHA1 = 2
FKO_DIGEST_SHA256 = 3
FKO_DIGEST_SHA384 = 4
FKO_DIGEST_SHA512 = 5

"""Encryption type constants
"""
FKO_ENCRYPTION_RIJNDAEL = 1
FKO_ENCRYPTION_GPG = 2

"""FKO error codes
"""
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
    """This class wraps the Firewall KNock OPerator (fwknop) library, libfko.

    It provides the functionality to manage and process
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
        if spa_data != None:
            self.ctx = _fko.init_ctx_with_data(spa_data, key)
        else:
            self.ctx = _fko.init_ctx()

    def __del__(self):
        """Destructor for Fko.

        Destroys the FKO context to clear the (possible sensitive) data
        and releases the resource allocated to the context.
        """
        _fko.destroy_ctx(self.ctx)

    ### FKO data functions and operations. ###

    def version(self):
        """Returns the fwknop version string.

        This version represents the supported fwknop SPA message format and
        features.  This has nothing to do with the version of this module.
        """
        return _fko.get_version(self.ctx)

    def rand_value(self, val=None):
        """Get or set the random value string of the SPA data.

        If setting the random value string, you must pass either a
        16-character decimal number (to set it to the given string), or
        an empty string ("")to have a new random value string generated
        by libfko.

        If a provided value is not a valid 16-character decimal string, the
        function will throw an fko.error exception.
        """
        if val != None:
            _fko.set_rand_value(self.ctx, val)
        else:
            return _fko.get_rand_value(self.ctx)

    def username(self, val=None):
        """Set or get the username field of the SPA data.

        If no argument is given, given, this function will return the
        current value.  Otherwise, the username value will be set to the
        name provided.

        If an empty string is given, libfko will attempt to determine and
        set the username by first looking for the environment variable
        "SPOOF_USER" and use its value if found.  Otherwise, it will try to
        determine the username itself using various system methods, then
        fallback to the environment variables "LOGNAME" or "USER". If none
        of those work, the function will throw an fko.error exception.

        Upon creation of a new Fko object, this value is automatically
        generated based on the libfko method described above.
        """
        if val != None:
            _fko.set_username(self.ctx, val)
        else:
            return _fko.get_username(self.ctx)

    def timestamp(self, val=None):
        """Gets or sets the timestamp value of the SPA data.

        If no argument is given, the current value is returned.

        If an argument is provided, it will represent an offset to be
        applied to the current timestamp value at the time this function
        was called.

        Upon creation of a new FKO object, this value is automatically
        generated based on the time of object creation.
        """
        if val != None:
            _fko.set_timestamp(self.ctx, val)
        else:
            return _fko.get_timestamp(self.ctx)

    def digest_type(self, val=None):
        """Gets or sets the digest type.

        If no argument is given, the current value is returned. Otherwise,
        digest type will be set to the given value.

        The digest type parameter is an integer value.  Constants have been
        defined to represent these values.  Currently, the supported digest
        types are:

            FKO_DIGEST_MD5    - The MD5 message digest.
            FKO_DIGEST_SHA1   - The SHA1 message digest.
            FKO_DIGEST_SHA256 - The SHA256 message digest (default).
            FKO_DIGEST_SHA384 - The SHA384 message digest.
            FKO_DIGEST_SHA512 - The SHA512 message digest.
        """
        if val != None:
            _fko.set_spa_digest_type(self.ctx, val)
        else:
            return _fko.get_spa_digest_type(self.ctx)

    def encryption_type(self, val=None):
        """Get or set the encryption type.
        If no argument is given, the current value is returned. Otherwise,
        encryption type will be set to the given value.

        The encryption type parameter is an integer value.  Constants have
        been defined to represent these values.  Currently, the only
        supported encryption types are:

        FKO_ENCRYPTION_RIJNDAEL
            AES - the default libfko encryption algorithm.
        FKO_ENCRYPTION_GPG
            GnuPG encryption (if supported by the underlying libfko
            implementation).
        """
        if val != None:
            _fko.set_spa_encryption_type(self.ctx, val)
        else:
            return _fko.get_spa_encryption_type(self.ctx)

    def message_type(self, val=None):
        """Get or set the SPA message type.

        If no argument is given, the current value is returned. Otherwise,
        message type will be set to the given value.

        The message type parameter is an integer value.  Constants have
        been defined to represent this values.  Currently, the supported
        digest types are:

        FKO_COMMAND_MSG
            A request to have the fwknop server execute the given command.
            The format for this type is: "<ip of requestor>:<command text>"

                For example: "192.168.1.2:uname -a"

        FKO_ACCESS_MSG
            A basic access request.  This is the most common type in use.
            The format for this type is: "<ip of
            requestor>:<protocol>/<port>".

                For example: "192.168.1.2:tcp/22"

        FKO_NAT_ACCESS_MSG
            An access request that also provide information for the fwknop
            server to create a Network Address Translation (NAT to an
            internal address. The format for this string is: "<internal
            ip>,<ext nat port>".

                For example: "10.10.1.2,9922"

        FKO_CLIENT_TIMEOUT_ACCESS_MSG
            This is an "FKO_ACCESS_REQUEST" with a timeout parameter for
            the fwknop server.  The timeout value is provided via the
            "client_timeout" data field.

        FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
            This is an "FKO_NAT_ACCESS_REQUEST" with a timeout parameter
            for the fwknop server.  The timeout value is provided via the
            "client_timeout" data field.

        FKO_LOCAL_NAT_ACCESS_MSG
            This is similar to the "FKO_NAT_ACCESS" request exept the NAT
            is to the local to the server (i.e. a service listening on
            127.0.0.1).

        FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCES_MSG
            This is an "FKO_LOCAL_NAT_ACCESS_REQUEST" with a timeout
            parameter for the fwknop server.  The timeout value is provided
            via the "client_timeout" data field.
        """
        if val != None:
            _fko.set_spa_message_type(self.ctx, val)
        else:
            return _fko.get_spa_message_type(self.ctx)

    def spa_message(self, val=None):
        """Get or set the SPA message string.

        If no argument is given, the current value is returned. Otherwise,
        SPA message string will be set to the given value.

        This is the string that represents the data for the message type
        as described in the spa_message_type section above.
        """
        if val != None:
            _fko.set_spa_message(self.ctx, val)
        else:
            return _fko.get_spa_message(self.ctx)

    def spa_nat_access(self, val=None):
        """Get or set the SPA nat access string.

        If no argument is given, the current value is returned. Otherwise,
        SPA nat access string will be set to the given value.
        """
        if val != None:
            _fko.set_spa_nat_access(self.ctx, val)
        else:
            return _fko.get_spa_nat_access(self.ctx)

    def spa_server_auth(self, val=None):
        """Get or set the SPA server auth string.

        If no argument is given, the current value is returned. Otherwise,
        the SPA server auth string will be set to the given value.
        """
        if val != None:
            _fko.set_spa_server_auth(self.ctx, val)
        else:
            return _fko.get_spa_server_auth(self.ctx)

    def spa_client_timeout(self, val=None):
        """Get or set the SPA message client timeout value.

        This is an integer value. If no argument is given, the current value
        is returned.  Otherwise, the SPA message client timeout value will
        be set to the given value.
        """
        if val != None:
            _fko.set_spa_client_timeout(self.ctx, val)
        else:
            return _fko.get_spa_client_timeout(self.ctx)

    def spa_digest(self):
        """Returns the digest associated with the current data (if available
        and set). This function is normally not called directly as it is
        called by other libfko functions during normal processing.
        """
        return _fko.get_spa_digest(self.ctx)

    def gen_spa_digest(self):
        """Recalculate the SPA data digest based on the current context's
        data. This function is normally not called directly as it is called
        by other libfko functions during normal processing.
        """
        _fko.set_spa_digest(self.ctx)

    def spa_data(self, val=None):
        """Get or set the SPA data string.

        If no argument is given, the current value is returned. This would
        be the final encrypted and encoded string of data that is suitable
        for sending to an fwkno server.

        If an argument is given, it is expected to be an existing encrypted
        and encoded SPA data string (perhaps data received by an fwknop
        server).  The provided data is stored in the object (the current
        context).

        Note: When data is provided via this function, it is not
              automatically decoded. You would need to call the 
              "decrypt_spa_data(key)" method to complete the
              decryption, decoding, and parsing process.
        """
        if val != None:
            _fko.set_spa_data(self.ctx, val)
        else:
            return _fko.get_spa_data(self.ctx)

    def encoded_data(self):
        """Returns the encoded SPA data as it would be just before the
        encryption step.  This is not generally useful unless you are
        debugging a data issue.
        """
        return _fko.get_encoded_data(self.ctx)

    def spa_data_final(self, key):
        """Perform final processing and generation of the SPA message data.

        This function is the final step in creating a complete encrypted
        SPA data string suitable for transmission to an fwknop server.  It
        does require all of the requisite SPA data fields be set. Otherwise,
        it will fail and throw an fko.error exception.
        """
        _fko.spa_data_final(self.ctx, key)

    def gen_spa_data(self, key):
        """Alias for "spa_data_final()".
        """
        _fko.spa_data_final(self.ctx, key)

    def encode_spa_data(self):
        """Encode the raw SPA data.

        Instructs libfko to perform the base64 encoding of those SPA data
        fields that need to be encoded, perform some data validation,
        compute and store the message digest hash for the SPA data.

        This function is normally not called directly as it is called by
        other libfko functions during normal processing (i.e during encypt
        and/or final functions.
        """
        _fko.encode_spa_data(self.ctx)

    def decode_spa_data(self):
        """Decode decrypted SPA data.

        This method hands of the data to the libfko decoding routines
        which performs the decoding, parsing, and validation of the SPA data
        that was just decrypted.

        This function is normally not called directly as it is called by
        other libfko functions during normal processing.
        """
        _fko.decode_spa_data(self.ctx)

    def encrypt_spa_data(self, key):
        """Encrypts the intermediate encoded SPA data stored in the context.

        The internal libfko encryption function will call the internal
        "encode_spa_data" if necessary.

        This function is normally not called directly as it is
        automatically called from the internal "fko_spa_data_final"
        function (which is wrapped by this module's "spa_data_final"
        function).
        """
        _fko.encrypt_spa_data(self.ctx, key)

    def decrypt_spa_data(self, key):
        """Decrypt, decode, and parse SPA message data.

        When given the correct key (passsword), this methoe decrypts,
        decodes, and parses the encrypted SPA data contained in the current
        context.  Once the data is decrypted, the libfko internal function
        will also call the libfko decode function to decode, parse,
        validate, and store the data fields in the context for later
        retrieval.

        Note: This function does not need to be called directly if
        encrypted SPA data and the key was passed to this module's
        constructor when the object was created, the constructor will
        decrypt and decode the data at that time.
        """
        _fko.decrypt_spa_data(self.ctx, key)

    # GPG-related functions.

    def gpg_recipient(self, val=None):
        """Get or set the gpg_recipient.

        This is the ID or email of the public GPG key of the intended
        recipient. In order for this function to work, the following
        conditions must be met:

           - The underlying libfko implementation must have GPG support.
           - The encryption_type must be set to "FKO_ENCRYPTION_GPG".
           - The specified GPG key must exist and be valid.

        If no argument is given, the current value is returned.  Otherwise,
        gpg_recipient will be set to the given value.
        """
        if val != None:
            _fko.set_gpg_recipient(self.ctx, val)
        else:
            return _fko.get_gpg_recipient(self.ctx)

    def gpg_signer(self, val=None):
        """Get or set the gpg_signer.

        This is the ID or email for the secret GPG key to be used to
        sign the encryped data. In order for this function to work, the
        following conditions must be met:

           - The underlying libfko implementation must have GPG support.
           - The encryption_type must be set to "FKO_ENCRYPTION_GPG".
           - The specified GPG key must exist and be valid.

        If no argument is given, the current value is returned.  Otherwise,
        gpg_signer will be set to the given value.
        """
        if val != None:
            _fko.set_gpg_signer(self.ctx, val)
        else:
            return _fko.get_gpg_signer(self.ctx)

    def gpg_home_dir(self, val=None):
        """Get or set the GPG home directory.

        This is the directory that holds the GPG keyrings, etc. In order
        for this function to work, the following conditions must be met:

           - The underlying libfko implementation must have GPG support.
           - The encryption_type must be set to "FKO_ENCRYPTION_GPG".
           - The specified GPG home directory must exist.

        If no argument is given, the current value is returned. Otherwise,
        gpg_home_dir will be set to the given value.
        """
        if val != None:
            _fko.set_gpg_home_dir(self.ctx, val)
        else:
            return _fko.get_gpg_home_dir(self.ctx)

    def gpg_signature_verify(self, val=None):
        """Get or set the GPG signature verification flag.

        If true (1), then GPG signatures are processed by libfko. This is
        the default behavior. If set to false (0), then libfko will not
        even look for or at any GPG signatures and will proceed with a
        decoding the SPA data.

        If no argument is given, the current value is returned.  Otherwise,
        the gpg_signature_verify flag will be set to the given value.
        """
        if val != None:
            _fko.set_gpg_signature_verify(self.ctx, val)
        else:
            return _fko.get_gpg_signature_verify(self.ctx)

    def gpg_ignore_verify_error(self, val=None):
        """Get or set the GPG signature ignore verification error flag.

        If true (1), then GPG signatures are processed and retained by
        libfko, but a bad signature will not prevent the decoding phase.
        The default is to not ignore errors.

        If no argument is given, the current value is returned. Otherwise,
        the gpg_ignore_verify_error flag will be set to the given value.
        """
        if val != None:
            _fko.set_gpg_ignore_verify_error(self.ctx, val)
        else:
            return _fko.get_gpg_ignore_verify_error(self.ctx)

    def gpg_exe(self, val=None):
        """Get or set the path the the GPG executable libfko should use.

        If no argument is given, the current value is returned. Otherwise,
        gpg_exe will be set to the given value.
        """
        if val != None:
            _fko.set_gpg_exe(self.ctx, val)
        else:
            return _fko.get_gpg_exe(self.ctx)

    def gpg_signature_id(self):
        """Get ID of the GPG signature from the last decryption operation.
        """
        return _fko.get_gpg_signature_id(self.ctx)

    def gpg_signature_fpr(self):
        """Get Fingerprint of the GPG signature from the last decryption
        operation.
        """
        return _fko.get_gpg_signature_fpr(self.ctx)

    def gpg_signature_summary(self):
        """Get GPGME signature summary value of the GPG signature from the
        last decryption operation. This value is a bitmask that hold
        additional information on the signature (see GPGME docs for more
        information).
        """
        return _fko.get_gpg_signature_summary(self.ctx)

    def gpg_signature_status(self):
        """Get error status of the GPG signature from the last decryption
        operation.  This value is a GPGME error code (see GPGME docs for
        more information).
        """
        return _fko.get_gpg_signature_status(self.ctx)

    def gpg_signature_id_match(self, val):
        """Compare the given ID with the id of the GPG signature of the
        last decryption operation.  If the ID's match, then a true value
        is returned. Otherwise false is returned.
        """
        if _fko.gpg_signature_id_match(self.ctx) > 0:
            return True
        return False

    def gpg_signature_fpr_match(self, val):
        """Compare the given fingerprint value with the fingerprint of the
        GPG signature of the last decryption operation.  If the ID's match,
        then a true value is returned. Otherwise false is returned.
        """
        if _fko.gpg_signature_fpr_match(self.ctx) > 0:
            return True
        return False

    # Error message string function.

    def errstr(self, val):
        """Returns the descriptive error message string for the
        given error code value.
        """
        return _fko.errstr(code)

    # FKO type lookup functions.

    def message_type_str(self, val=None):
        """Returns the message type string for the given value.
        """
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
        """Returns the digest type string for the given value.
        """
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
        """Returns the encryption type string for the given value.
        """
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
