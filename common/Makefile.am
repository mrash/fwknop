AUTOMAKE_OPTIONS = subdir-objects

noinst_LTLIBRARIES         	= libfko_util.la

libfko_util_source_files 	= strlcpy.c strlcat.c fko_util.c fko_util.h

if WANT_C_UNIT_TESTS
libfko_util_source_files += cunit_common.c cunit_common.h
endif

libfko_util_la_SOURCES    	= $(libfko_util_source_files)
libfko_util_la_LDFLAGS = -no-undefined

if USE_MINGW
EXTRA_libfko_util_la_SOURCES = ../win32/getlogin.c ../win32/getlogin.h
libfko_util_la_LDFLAGS += -lwsock32 -lws2_32
endif

libfko_util_la_CPPFLAGS =  -I $(top_srcdir)/common -I $(top_srcdir)/lib $(GPGME_CFLAGS)

EXTRA_DIST = common.h netinet_common.h cunit_common.h cunit_common.c

clean-local:
	rm -f *.gcno *.gcda
