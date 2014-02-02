##############################################################################
#
# File:    FKO.pm
#
# Author:  Damien S. Stuart <dstuart@dstuart.org>
#
# Purpose: The Firewall Knock Operator library (libfko) Perl module.
#
##############################################################################
#
package FKO;

use 5.008008;
use strict;
use warnings;
use Carp;
require Exporter;

our $VERSION = '2.0.1';

our @ISA = qw(Exporter);

# Our export tag arrays. These are defined in FKO_Constants.pl
#
our (
    @MSG_TYPES,
    @DIGEST_TYPES,
    @HMAC_DIGEST_TYPES,
    @ENCRYPTION_TYPES,
    @ENCRYPTION_MODES,
    @ERROR_CODES
);

# This holds the constants definitions and tag arrays.
#
require "FKO_Constants.pl";

our %EXPORT_TAGS = (
    'message_types'     => \@MSG_TYPES,
    'digest_types'      => \@DIGEST_TYPES,
    'hmac_digest_types' => \@HMAC_DIGEST_TYPES,
    'encryption_types'  => \@ENCRYPTION_TYPES,
    'encryption_modes'  => \@ENCRYPTION_MODES,
    'errors'            => \@ERROR_CODES,

    'types' => [
        @MSG_TYPES,
        @DIGEST_TYPES,
        @HMAC_DIGEST_TYPES,
        @ENCRYPTION_TYPES
    ],

    'all' => [
        @MSG_TYPES,
        @HMAC_DIGEST_TYPES,
        @ENCRYPTION_TYPES,
        @ENCRYPTION_MODES,
        @ERROR_CODES
    ]
);

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our $error_str;

require XSLoader;
XSLoader::load('FKO', $VERSION);

##############################################################################

# Constructor.
#
sub new {
    my $class     = shift;
    my $data      = shift;
    my $dc_pw     = shift;
    my $enc_mode  = shift;
    my $hmac_pw   = shift || '';
    my $hmac_type = shift;
    my $rand_mode = shift;
    my $res;

    my $ctx;

    # If data was passed, call _init_ctx_with_data.  If a password was
    # not defined, then pass 0.
    #
    if(defined($data) and $data) {
        if(defined($dc_pw) and $dc_pw) {
            $ctx = _init_ctx_with_data($data, $dc_pw, length($dc_pw),
                        $enc_mode, $hmac_pw, length($hmac_pw),
                        $hmac_type, $rand_mode);
        } else {
            $ctx = _init_ctx_with_data_only($data);
        }
    } else {
        $ctx = _init_ctx();
    }

    unless($ctx) {
        my $errstr = FKO::error_str();
        $error_str = "Unable initialize FKO context: $errstr\n";
        return undef;
    }

    bless {
        _ctx => $ctx,  # Gotta hang on to our context.
        _err => 0      # Place to hold the last error code.
    }, $class;
}

# The following methods wrap the libfko C functions.  Most of the get/set
# functions are rolled into a single method here such that if an argument
# is passed, it will set (and return) the value.  Otherwise, the current
# value is returned.

sub destroy {
    my $self = shift;

    return unless($self->{_ctx});

    FKO::_destroy_ctx($self->{_ctx});

    $self->{_ctx} = undef;
}

sub version {
    my $self = shift;
    my $val  = '';

    $self->{_err} = FKO::_version($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub errstr {
    my $self = shift;
    my $ec = shift;

    $ec = $self->{_err} if(!defined($ec));

    return FKO::_error_str($ec);
}

sub gpg_errstr {
    my $self = shift;
    return FKO::_gpg_error_str($self->{_ctx});
}

sub rand_value {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_rand_value($self->{_ctx}, $val || 0)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_rand_value($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub digest_type {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_digest_type($self->{_ctx}, $val)
        if(defined($val));

    $val = -1;
    $self->{_err} = FKO::_get_digest_type($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub hmac_type {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_hmac_type($self->{_ctx}, $val)
        if(defined($val));

    $val = -1;
    $self->{_err} = FKO::_get_hmac_type($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub encryption_type {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_encryption_type($self->{_ctx}, $val)
        if(defined($val));

    $val = -1;
    $self->{_err} = FKO::_get_encryption_type($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub encryption_mode {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_encryption_mode($self->{_ctx}, $val)
        if(defined($val));

    $val = -1;
    $self->{_err} = FKO::_get_encryption_mode($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub username {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_username($self->{_ctx}, $val || 0)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_username($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub spa_message_type {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_spa_message_type($self->{_ctx}, $val)
        if(defined($val));

    $val = -1;
    $self->{_err} = FKO::_get_spa_message_type($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub timestamp {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_timestamp($self->{_ctx}, $val)
        if(defined($val));

    $val = -1;
    $self->{_err} = FKO::_get_timestamp($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub spa_message {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_spa_message($self->{_ctx}, $val)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_spa_message($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub spa_nat_access {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_spa_nat_access($self->{_ctx}, $val)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_spa_nat_access($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub spa_server_auth {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_spa_server_auth($self->{_ctx}, $val)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_spa_server_auth($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub spa_client_timeout {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_spa_client_timeout($self->{_ctx}, $val)
        if(defined($val));

    $val = -1;
    $self->{_err} = FKO::_get_spa_client_timeout($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub spa_digest {
    my $self = shift;
    my $recompute = shift || 0;

    my $val = '';

    return FKO::_set_spa_digest($self->{_ctx})
        if($recompute);

    $self->{_err} = FKO::_get_spa_digest($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub spa_hmac {
    my $self = shift;
    my $recompute    = shift || 0;
    my $hmac_key     = shift || '';

    my $val = '';

    return FKO::_set_spa_hmac($self->{_ctx})
        if($recompute and $hmac_key);

    $self->{_err} = FKO::_get_spa_hmac($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub spa_data {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_spa_data($self->{_ctx}, $val)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_spa_data($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub gpg_recipient {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_gpg_recipient($self->{_ctx}, $val)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_gpg_recipient($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub gpg_signer {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_gpg_signer($self->{_ctx}, $val)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_gpg_signer($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub gpg_home_dir {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_gpg_home_dir($self->{_ctx}, $val)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_gpg_home_dir($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub gpg_signature_verify {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_gpg_signature_verify($self->{_ctx}, $val)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_gpg_signature_verify($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub gpg_ignore_verify_error {
    my $self = shift;
    my $val  = shift;

    return FKO::_set_gpg_ignore_verify_error($self->{_ctx}, $val)
        if(defined($val));

    $val = '';
    $self->{_err} = FKO::_get_gpg_ignore_verify_error($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub gpg_signature_id {
    my $self = shift;
    my $val  = '';

    $self->{_err} = FKO::_get_gpg_signature_id($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub gpg_signature_fpr {
    my $self = shift;
    my $val  = '';

    $self->{_err} = FKO::_get_gpg_signature_fpr($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub gpg_signature_summary {
    my $self = shift;
    my $val  = '';

    $self->{_err} = FKO::_get_gpg_signature_summary($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub gpg_signature_status {
    my $self = shift;
    my $val  = '';

    $self->{_err} = FKO::_get_gpg_signature_status($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub gpg_signature_id_match {
    my $self = shift;
    my $id   = shift || '';
    my $val  = '';

    $self->{_err} = FKO::_get_gpg_signature_id_match($self->{_ctx}, $id, $val);

    return($self->_check_return_val($val));
}

sub gpg_signature_fpr_match {
    my $self = shift;
    my $fpr  = shift || '';
    my $val  = '';

    $self->{_err} = FKO::_get_gpg_signature_fpr_match($self->{_ctx}, $fpr, $val);

    return($self->_check_return_val($val));
}

sub encoded_data {
    my $self = shift;
    my $val  = '';

    $self->{_err} = FKO::_get_encoded_data($self->{_ctx}, $val);

    return($self->_check_return_val($val));
}

sub spa_data_final {
    my $self     = shift;
    my $key      = shift || '';
    my $hmac_key = shift || '';

    return FKO::_spa_data_final($self->{_ctx}, $key, length($key), $hmac_key, length($hmac_key));
}

sub encrypt_spa_data {
    my $self    = shift;
    my $key     = shift || '';

    return FKO::_encrypt_spa_data($self->{_ctx}, $key, length($key));
}

sub decrypt_spa_data {
    my $self    = shift;
    my $key     = shift || '';

    return FKO::_decrypt_spa_data($self->{_ctx}, $key, length($key));
}

sub encode_spa_data {
    my $self = shift;
    return FKO::_encode_spa_data($self->{_ctx});
}

sub decode_spa_data {
    my $self = shift;
    return FKO::_decode_spa_data($self->{_ctx});
}

sub verify_hmac {
    my $self         = shift;
    my $hmac_key     = shift || '';

    return FKO::_verify_hmac($self->{_ctx}, $hmac_key, length($hmac_key));
}

sub set_spa_hmac {
    my $self         = shift;
    my $hmac_key     = shift || '';

    return FKO::_set_spa_hmac($self->{_ctx}, $hmac_key, length($hmac_key));
}

sub DESTROY {
    my $self = shift;
    FKO::_destroy_ctx($self->{_ctx}) if($self->{_ctx});
}

sub _check_return_val {
    my ($self, $val) = @_;
    return($self->{_err} == 0 ? $val : undef);
}

1;
__END__

=head1 NAME

FKO - Perl module wrapper for libfko

=head1 SYNOPSIS

  use FKO;

  # Create a new empty FKO object.
  #
  my $fko = FKO->new();

  if(!$fko) {
    die "Unable to create FKO object: $FKO::error_str\n";
  }

  # Override the username (default is current user).
  #
  my $err = $fko->username('joeuser');
  if($err) {
    die "Error setting username: ", $fko->errstr($err), "\n";
  }

  # Set the SPA message (see libfko docs for details).
  #
  $err = $fko->spa_message('1.2.3.4,tcp/22');
    # ..error checking, etc...

  $err = $fko->spa_data_final('mycryptkey', 'myhmackey');
    # ..error checking, etc...

  # Get the encrypted/authenticated/encoded SPA data.
  #
  my $spa_data = $fko->spa_data();

  ## Incoming SPA data ##

  # Create an FKO object to process incoming (or existing)
  # SPA data.
  #
  my $fko_in = FKO->new($enc_spa_data, 'mycryptkey',
        FKO::FKO_ENC_MODE_CBC, 'myhmackey', FKO::FKO_HMAC_SHA256)
    or die "Unable to create FKO object: $FKO::error_str\n";

  my $timestamp = $fko_in->timestamp();
  my $fko_user  = $fko_in->username();
  my $spa_msg   = $fko_in->spa_message();
  my $digest    = $fko_in->spa_digest();

  # Pull the digest type.
  my $digest_type = $fko_in->spa_digest_type();

  if($digest_type == FKO::FKO_DIGEST_SHA256) {
      # do something
  } elsif($digest_type == FKO::FKO_DIGEST_MD5) {
      # do something else
  }

=head1 DESCRIPTION

This module is essentially a Perl wrapper for the I<Firewall Knock Operator>
(fwknop) library, C<libfko>.  Fwknop is an open source implementation of
I<Single Packet Authorization> (I<SPA>) for access to networked resources
that are protected by a default-drop packet filter.

The original I<fwknop> is implemented in Perl.  The I<libfko> library is
an implementation of the I<fwknop> back-end data processing routines written
in C as part of the project to move all of I<fwknop> to C.

See the C<libfko> documentation for additional information on usage and the
functionality provided by C<libfko>.  More information on I<SPA> and I<fwknop>
can be found at http://www.cipherdyne.org/fwknop.

=head1 CONSTRUCTOR

=over

=item B<new( )>

=item B<new($spa_data, $password, $enc_type, $hmac_key, $hmac_type)>

The C<new> method creates the I<FKO> object.  With no arguments, it creates
creates and empty I<FKO> object ready to be popluated with data (i.e. create
a new SPA data packet to send).

You can also pass existing encoded/encrypted I<SPA> data, a decryption
password, and an HMAC key (along with associated encryption and HMAC modes) to
C<new>.  This will create a new object, authenticate, decrypt, and decode the
data, and store it within the object for later retrieval using the various
methods described below.

If there are any errors during the creation or decoding of the data I<new>
will return undef and the appropriate error message will be available in the
C<$FKO::error_str> variable.

Create an empty object:

    my $fko = FKO->new();

Create an object using existing data:

    my $fko = FKO->new($spa_data, 'decrypt_pw', FKO::FKO_ENC_MODE_CBC,
            'myhmackey', FKO::FKO_HMAC_SHA256);

=back

=head1 METHODS

=head2 Utility Methods

The utility methods are those that perform the non-data-set/get functions
like error messages, data processing, and clean-up.

=over

=item B<destroy( )>

The C<destroy> method is used when you are done with the I<FKO> object and its
data.  This method will make the appropriate I<libfko> calls to clean-up and
release resources used by the object.

Though C<destroy> will be called if the object goes out of scope, it is good
practice to clean up after yourself.  This is especially true if you are
processing multiple I<SPA> messages in a loop, etc.


=item B<errstr($err_code)>

This method returns the descriptive error message string for the given
error code value.

=item B<gpg_errstr( )>

If the previous I<FKO> error was from a GPG-related function, then calling
this method may return more detailed information from the GPG error handling
system.

=item B<spa_data_final($enc_key, $hmac_key)>

This function is the final step in creating a complete encrypted and
authenticated I<SPA> data string suitable for transmission to an fwknop server.
It does require all of the requisite I<SPA> data fields be set.  Otherwise it
will fail and return the appropriate error code.

=item B<encrypt_spa_data( )>

Encrypts the intermediate encoded I<SPA> data stored in the context. The
internal I<libfko> encryption function will call the internal
C<encode_spa_data> if necessary.

This function is normally not called directly as it is automatically called
from the internal C<fko_spa_data_final> function (which is wrapped by this
module's C<spa_data_final> function.

=item B<decrypt_spa_data( )>

When given the correct I<key> (passsword), this function decrypts, decodes,
and parses the encrypted I<SPA> data contained in the current context.
Once the data is decrypted, the I<libfko> internal function will also call
the I<libfko> decode function to decode, parse, validate, and store the data
fields in the context for later retrieval.

Note: This function does not need to be called directly if encrypted I<SPA>
data was passed to this module's constructor when the object was created as
the C<new> function will call decrypt and decode itself.

=item B<encode_spa_data( )>

Instructs I<libfko> to perform the base64 encoding of those I<SPA> data
fields that need to be encoded, perform some data validation, compute and
store the message digest hash for the I<SPA> data.

This function is normally not called directly as it is called by other
I<libfko> functions during normal processing (i.e during encypt and/or final
functions.

=item B<decode_spa_data( )>

This function hands of the data to the I<libfko> decoding routines which
perform the decoding, parsing, and validation of the I<SPA> data that was
just decrypted.

This function is normally not called directly as it is called by other
I<libfko> functions during normal processing.

=back

=head2 Working with SPA Data Types

There are a few data and method types supported by I<libfko>, along with a
few functions for getting and setting them.  Most of these I<types> are
represented using constants defined in the I<FKO> module.

=over

=item B<encryption_type( )>

=item B<encryption_type(FKO_ENCRYPTION_TYPE)>

Get or set the encryption type for the current context.  If no argument is
given, the current value is returned.  Otherwise the encryption type will be
set to the given value.

The encryption type parameter is an integer value.  Constants have been
defined to represent this value.  Currently, the only supported encryption
types are:

=over

=item * B<FKO_ENCRYPTION_RIJNDAEL>

The default I<libfko> encryption algorithm.

=item * B<FKO_ENCRYPTION_GPG>

GnuPG encryption (if supported by the underlying I<libfko> implementation).

=back

=item B<hmac_type( )>

=item B<hmac_type(FKO_HMAC_TYPE)>

Get or set the HMAC digest algorithm for the current context.  If no argument
is given, the current value is returned.  Otherwise the HMAC type will be set
to the given value.

The HMAC type parameter is an integer value.  Constants have been
defined to represent this value.  Currently, the supported HMAC types are:

=over

=item * B<FKO_HMAC_SHA256>

The default I<libfko> HMAC digest algorithm is SHA-256

=item * B<FKO_HMAC_MD5>

Use the MD5 digest algorithm (not recommended) to generate the HMAC.

=item * B<FKO_HMAC_SHA1>

Use the SHA-1 digest algorithm to generate the HMAC.

=item * B<FKO_HMAC_SHA512>

Use the SHA-512 digest algorithm to generate the HMAC.

=back


=item B<digest_type( )>

=item B<digest_type(FKO_DIGEST_TYPE)>

Get or set the digest type for the current context.  If no argument is
given, the current value is returned.  Otherwise digest type will be set
to the given value.

The digest type parameter is an integer value.  Constants have been
defined to represent this value.  Currently, the supported digest
types are:

=over

=item * B<FKO_DIGEST_MD5>

The MD5 message digest algorithm.

=item * B<FKO_DIGEST_SHA1>

The SHA1 message digest algorithm.

=item * B<FKO_DIGEST_SHA256>

The SHA256 message digest algorithm. This is the I<libfko> default.

=item * B<FKO_DIGEST_SHA384>

The SHA384 message digest algorithm. This is the I<libfko> default.

=item * B<FKO_DIGEST_SHA512>

The SHA512 message digest algorithm. This is the I<libfko> default.

=back

=item B<spa_message_type( )>

=item B<spa_message_type(FKO_MSG_TYPE)>

Get or set the I<SPA> message type.  If no argument is given, the current
value is returned.  Otherwise message type will be set to the given value.

The message type parameter is an integer value.  Constants have been
defined to represent this value.  Currently, the supported digest
types are:

=over

=item * B<FKO_COMMAND_MSG>

A request to have the fwknop server execute the given command.  The format
for this type is: C<< <ip of requestor>:<command text> >>

For example:
    "192.168.1.2:uname -a"

=item * B<FKO_ACCESS_MSG>

A basic access request.  This is the most common type in use. The format
for this type is: C<< <ip of requestor>:<protocol>/<port> >>.

For example:
    "192.168.1.2:tcp/22"

=item * B<FKO_NAT_ACCESS_MSG>

An access request that also provide information for the fwknop server to
create a Network Address Translation (NAT to an internal address. The format
for this string is: C<< <internal ip>,<ext nat port> >>.

For example:
    "10.10.1.2,9922"

=item * B<FKO_CLIENT_TIMEOUT_ACCESS_MSG>

This is an C<FKO_ACCESS_REQUEST> with a timeout parameter for the fwknop
server.  The timeout value is provided via the C<client_timeout> data field.

=item * B<FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG>

This is an C<FKO_NAT_ACCESS_REQUEST> with a timeout parameter for the fwknop
server.  The timeout value is provided via the C<client_timeout> data field.

=item * B<FKO_LOCAL_NAT_ACCESS_MSG>

This is similar to the C<FKO_NAT_ACCESS> request exept the NAT is to the
local to the server (i.e. a service listening on 127.0.0.1).

=item * B<FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCES_MSG>

This is an C<FKO_LOCAL_NAT_ACCESS_REQUEST> with a timeout parameter for the
fwknop server.  The timeout value is provided via the C<client_timeout> data
field.

=back

=back

=head2 Working With SPA Data

The I<SPA> data methods are used for setting or retrieving the various I<SPA>
data field values.  Some of these simply return a read-only value, while
others are used to set or get values.

B<Note:> The following methods are presented roughly in the order their
respective data values appear in an I<fwknop> I<SPA> message.  Many of these
have reasonable default values at creation and are not typically used in
most circumstances.

=over

=item B<rand_value( )>

=item B<rand_value($new_value)>

Get or set the random value portion of the I<SPA> data. If setting the
random value, you must pass either a 16-character decimal number (to
set it to the given number), or the value C<0> to have a new random value
generated by I<libfko>.

If a provided value is not a valid 16-character decimal string, the function
will return the C<FKO_ERROR_INVALID_DATA> error code.

Upon creation of a new I<FKO> object, this value is automatically generated.

=item B<username( )>

=item B<username($username)>

Set or get the username field of the I<SPA> data. If no argument is given,
given, this function will return the current value.  Otherwise, the username
value will be set to the name provided.

If a value of C<0> is given, I<libfko> will attempt to determine and set the
username by first looking for the environment variable C<SPOOF_USER> and use
its value if found.  Otherwise, it will try to determine the username
itself using various system methods, then fallback to the environment
variables C<LOGNAME> or C<USER>. If none of those work, the function will
return the C<FKO_ERROR_USERNAME_UNKNOWN> error code.

Upon creation of a new I<FKO> object, this value is automatically generated
based on the I<libfko> method described above.

=item B<timestamp( )>

=item B<timestamp($offset)>

Gets or sets the timestamp value of the SPA data.  If no argument is given,
the current value is returned.

If an argument is provided, it will represent an offset to be applied to the
current timestamp value at the time this function was called.

Upon creation of a new I<FKO> object, this value is automatically generated
based on the time of object creation.

=item B<version( )>

Returns the I<fwknop> version string.  This version represents the supported
I<fwknop> I<SPA> message format and features.  This has nothing to do with
the version of this module.

=item B<spa_message( )>

=item B<spa_message($spa_msg)>

Get or set the I<SPA> message string.  If no argument is given, the current
value is returned.  Otherwise I<SPA> message string will be set to the given
value.


=item B<spa_nat_access( )>

=item B<spa_nat_access($nat_access)>

Get or set the I<SPA> nat access string.  If no argument is given, the
current value is returned.  Otherwise I<SPA> nat access string will be set
to the given value.

=item B<spa_server_auth( )>

=item B<spa_server_auth($server_auth)>

Get or set the I<SPA> server auth string.  If no argument is given, the
current value is returned.  Otherwise I<SPA> server auth string will be set
to the given value.

=item B<spa_client_timeout( )>

=item B<spa_client_timeout($new_timeout)>

Get or set the I<SPA> message client timeout value.  This is an integer
value. If no argument is given, the current value is returned.  Otherwise
I<SPA> message client timeout value will be set to the given value.

=item B<spa_digest( )>

=item B<spa_digest(1)>

When called with no argument, the C<spa_digest> function returns the digest
associated with the current data (if available).  If a true value (i.e. C<1>)
is given as the argument, it will force a recompute of the digest based on
the data and the configured I<digest_type>.

This function is normally not called directly as it is called by other
I<libfko> functions during normal processing.

=item B<encoded_data( )>

Returns the encoded I<SPA> data as it would be just before the encryption
step.  This is not generally useful unless you are debugging a data issue.

=item B<spa_data( )>

=item B<spa_data($spa_data)>

Get or set the I<SPA> data string.  If no argument is given, the current
value is returned.  This would be the final encrypted and encoded string
of data that is suitable for sending to an I<fwkno> server.

If an argument is given, it is expected to be an existing encrypted and
encoded I<SPA> data string (perhaps data received by an I<fwknop> server).
The provided data is stored in the object (the current context).

Note: When data is provided via this function, it is not automatically
decoded. You would need to call C<decrypt_spa_data($pw)> to complete the
decryption, decoding, and parsing process.

=item B<gpg_recipient( )>

=item B<gpg_recipient($gpg_id)>

Get or set the gpg_recipient.  This is the ID or email of the public GPG key
of the intended recipient.  In order for this function to work, the following
condition must be met:

=over

=item * The underlying I<libfko> implementation nust have GPG support.

=item * The I<encryption_type> must be set to C<FKO_ENCRYPTION_GPG>.

=item * The specified GPG key must exist and be valid.

=back

If no argument is given, the current value is returned.  Otherwise,
gpg_recipient will be set to the given value.

=item B<gpg_signer( )>

=item B<gpg_signer($gpg_id)>

Get or set the gpg_signer.  This is the ID or email for the secret GPG key
to be used to sign the encryped data.  In order for this function to work,
the following condition must be met:

=over

=item * The underlying I<libfko> implementation nust have GPG support.

=item * The I<encryption_type> must be set to C<FKO_ENCRYPTION_GPG>.

=item * The specified GPG key must exist and be valid.

=back

If no argument is given, the current value is returned.  Otherwise,
gpg_signer will be set to the given value.

=item B<gpg_home_dir( )>

=item B<gpg_home_dir($new_dir)>

Get or set the GPG home directory.  This is the directory that holds the
GPG keyrings, etc. In order for this function to work, the following
condition must be met:

=over

=item * The underlying I<libfko> implementation nust have GPG support.

=item * The I<encryption_type> must be set to C<FKO_ENCRYPTION_GPG>.

=item * The specified GPG home directory must exist.

=back

If no argument is given, the current value is returned.  Otherwise,
gpg_home_dir will be set to the given value.

=back

=head3 GPG Signature Verification

By default libfko will attempt to verify GPG signatures when decrypting
GPG-encrypted data.  If the signature is missing, expired, revoked, or 
otherwise bad, the decoding operation will fail.

The following functions are provided to process GPG key information, or
manage how libfko deals with GPG signatures.  Like the other GPG-related
functions, these also have the following prerequisites:

=over

=item * The underlying I<libfko> implementation nust have GPG support.

=item * The I<encryption_type> must be set to C<FKO_ENCRYPTION_GPG>.

=back

=over

=item B<gpg_signature_verify( )>

=item B<gpg_signature_verify($bool)>

Get or set the GPG signature verification flag.  If true (1), then GPG
signatures are processed by libfko.  This is the default behavior.  If
set to false (0), then libfko will not even look for or at any GPG
signatures and will proceed with a decoding the SPA data.

If no argument is given, the current value is returned.  Otherwise,
the gpg_signature_verify flag will be set to the given value.

=item B<gpg_ignore_verify_error( )>

=item B<gpg_ignore_verify_error($bool)>

Get or set the GPG signature ignore verification error flag.  If true (1),
then GPG signatures are processed and retained by libfko, but a bad signature
will not prevent the decoding phase.  The default is to not ignore errors.

If no argument is given, the current value is returned.  Otherwise,
the gpg_ignore_verify_error flag will be set to the given value.

=item B<gpg_signature_id( )>

Get ID of the GPG signature from the last decryption operation.

=item B<gpg_signature_fpr( )>

Get Fingerprint of the GPG signature from the last decryption operation.

=item B<gpg_signature_summary( )>

Get GPGME signature summary value of the GPG signature from the last
decryption operation. This value is a bitmask that hold additional 
information on the signature (see GPGME docs for more information).

=item B<gpg_signature_status( )>

Get error status of the GPG signature from the last decryption operation.
This value is a GPGME error code (see GPGME docs for more information).

=item B<gpg_signature_id_match($id)>

Compare the given ID with the id of the GPG signature of the last decryption
operation.  If the ID's match, then a true value is returned. Otherwise
false is returned. 

=item B<gpg_signature_fpr_match($id)>

Compare the given fingerprint value with the fingerprint of the GPG signature
of the last decryption operation.  If the ID's match, then a true value is
returned. Otherwise false is returned. 

=back

=head1 SEE ALSO

L<Perl>, the C<libfko> manual.

Additional information on the Firewall Knock Operater (I<fwknop>) can
be found at http://www.cipherdyne.org/fwknop.

=head1 AUTHOR

Damien S. Stuart, E<lt>dstuart@dstuart.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Damien S. Stuart

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

###EOF###
