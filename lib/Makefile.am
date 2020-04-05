lib_LTLIBRARIES     = libfko.la

libfko_source_files = \
    base64.c base64.h cipher_funcs.c cipher_funcs.h digest.c digest.h \
    fko_client_timeout.c fko_common.h fko_digest.c fko_encode.c \
    fko_decode.c fko_encryption.c fko_error.c fko_funcs.c fko_message.c \
    fko_message.h fko_nat_access.c fko_rand_value.c fko_server_auth.c \
    fko.h fko_limits.h fko_timestamp.c fko_hmac.c hmac.c hmac.h \
    fko_user.c fko_user.h md5.c md5.h rijndael.c rijndael.h sha1.c \
    sha1.h sha2.c sha2.h sha3.c sha3.h fko_context.h fko_state.h \
    gpgme_funcs.c gpgme_funcs.h fko_dump.c

libfko_la_LDFLAGS = -version-info 3:0:1 $(GPGME_LIBS) -export-symbols-regex '^fko_' $(GPGME_LIBS) -no-undefined
if WANT_C_UNIT_TESTS
noinst_PROGRAMS     = fko_utests
fko_utests_SOURCES  = fko_utests.c $(libfko_source_files)
fko_utests_CPPFLAGS = -I $(top_builddir)/lib -I $(top_builddir)/common $(GPGME_CFLAGS)
fko_utests_LDADD    = $(top_builddir)/lib/libfko.la 
fko_utests_LIBS     = $(top_builddir)/common/libfko_util.la
fko_utests_LDFLAGS  = -lcunit
else
if USE_MINGW
libfko_la_LDFLAGS  += -lwsock32 -lws2_32
endif
endif

libfko_la_SOURCES  = $(libfko_source_files)
libfko_la_LIBADD = $(top_builddir)/gnulib/libgnu.la $(top_builddir)/common/libfko_util.la

libfko_la_CPPFLAGS = -I $(top_builddir)/gnulib -I $(top_srcdir)/gnulib -I $(top_srcdir)/common  $(GPGME_CFLAGS)

include_HEADERS     = fko.h

clean-local:
	rm -f fko_utests *.gcno *.gcda
