sbin_PROGRAMS 		= fwknopd

fwknopd_SOURCES 	= fwknopd.c fwknopd.h config_init.c config_init.h \
                  	  fwknopd_common.h utils.c utils.h

fwknopd_LDADD 		= $(top_builddir)/lib/libfko.la

if HAVE_LIBPCAP
  fwknopd_LDADD		+= -lpcap
endif

fwknopd_CPPFLAGS 	= -I $(top_srcdir)/lib -I $(top_srcdir)/common -DSYSCONFDIR=\"$(sysconfdir)\"

fwknopddir 			= @sysconfdir@/fwknop
dist_fwknopd_DATA 	= fwknopd.conf

