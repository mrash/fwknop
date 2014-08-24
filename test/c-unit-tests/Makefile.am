bin_PROGRAMS        = fko_utests

fko_utests_SOURCES  = fko_utests.c \
						$(top_srcdir)/client/config_init.c config_init.h \
						fwknop_common.h  \
						$(top_srcdir)/client/spa_comm.c spa_comm.h  \
						$(top_srcdir)/client/utils.c utils.h \
						$(top_srcdir)/client/http_resolve_host.c  \
						$(top_srcdir)/client/getpasswd.c getpasswd.h cmd_opts.h \
						$(top_srcdir)/client/log_msg.c log_msg.h

fko_utests_CPPFLAGS = -I $(top_srcdir)/lib -I $(top_srcdir)/common -I $(top_srcdir)/client

fko_utests_LDADD    = $(top_builddir)/lib/libfko.la $(top_builddir)/common/libfko_util.a

fko_utests_LDFLAGS  = -lcunit