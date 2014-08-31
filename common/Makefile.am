AUTOMAKE_OPTIONS = subdir-objects

noinst_LIBRARIES         	= libfko_util.a

libfko_util_source_files 	= ../lib/cunit_common.c cunit_common.h ../lib/strlcpy.c ../lib/strlcat.c ../lib/fko_util.c ../lib/fko_util.h 

libfko_util_a_SOURCES    	= $(libfko_util_source_files)

AM_CPPFLAGS         		= $(GPGME_CFLAGS) -I $(top_srcdir)/common

EXTRA_DIST = common.h netinet_common.h
