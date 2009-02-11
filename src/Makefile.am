bin_PROGRAMS = fwknop

fwknop_SOURCES = fwknop.c fwknop.h config_init.c config_init.h \
                 fwknop_common.h spa_comm.c spa_comm.h utils.c utils.h \
                 getpasswd.c getpasswd.h

fwknop_LDADD = $(top_builddir)/fko/libfko.la
fwknop_CPPFLAGS = -I $(top_srcdir)/fko
