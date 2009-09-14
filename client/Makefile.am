bin_PROGRAMS        = fwknop

fwknop_SOURCES      = fwknop.c fwknop.h config_init.c config_init.h \
                      fwknop_common.h spa_comm.c spa_comm.h utils.c utils.h \
                      http_resolve_host.c getpasswd.c getpasswd.h

fwknop_CPPFLAGS     = -I $(top_srcdir)/lib -I $(top_srcdir)/common

fwknop_LDADD        = $(top_builddir)/lib/libfko.la

dist_man_MANS       = fwknop.8
