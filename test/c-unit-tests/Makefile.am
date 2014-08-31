bin_PROGRAMS        = fwknop_utests fwknopd_utests

fwknop_utests_SOURCES  = fwknop_utests.c fwknop_common.h \
			$(top_srcdir)/client/config_init.c config_init.h \
			$(top_srcdir)/client/spa_comm.c spa_comm.h  \
			$(top_srcdir)/client/utils.c utils.h \
			$(top_srcdir)/client/http_resolve_host.c  \
			$(top_srcdir)/client/getpasswd.c getpasswd.h cmd_opts.h \
			$(top_srcdir)/client/log_msg.c log_msg.h

fwknop_utests_CPPFLAGS = -I $(top_srcdir)/lib -I $(top_srcdir)/common -I $(top_srcdir)/client

fwknop_utests_LDADD    = $(top_builddir)/lib/libfko.la $(top_builddir)/common/libfko_util.a

fwknop_utests_LDFLAGS  = -lcunit

fwknopd_utests_SOURCES   = fwknopd_utests.c fwknopd.h $(top_srcdir)/server/config_init.c config_init.h \
                    fwknopd_common.h $(top_srcdir)/server/incoming_spa.c incoming_spa.h \
                    $(top_srcdir)/server/pcap_capture.c pcap_capture.h $(top_srcdir)/server/process_packet.c \
                    process_packet.h $(top_srcdir)/server/log_msg.c log_msg.h $(top_srcdir)/server/utils.c utils.h \
                    $(top_srcdir)/server/sig_handler.c sig_handler.h $(top_srcdir)/server/replay_cache.c replay_cache.h \
                    $(top_srcdir)/server/access.c access.h $(top_srcdir)/server/fwknopd_errors.c fwknopd_errors.h \
                    $(top_srcdir)/server/tcp_server.c tcp_server.h $(top_srcdir)/server/extcmd.c extcmd.h \
                    $(top_srcdir)/server/fw_util.c fw_util.h $(top_srcdir)/server/fw_util_ipf.c fw_util_ipf.h \
                    $(top_srcdir)/server/fw_util_iptables.c fw_util_iptables.h \
                    $(top_srcdir)/server/fw_util_ipfw.c fw_util_ipfw.h \
                    $(top_srcdir)/server/fw_util_pf.c fw_util_pf.h cmd_opts.h \
					common.h	
			
fwknopd_utests_CPPFLAGS = -I $(top_srcdir)/lib -I $(top_srcdir)/common -I $(top_srcdir)/server -DSYSCONFDIR=\"$(sysconfdir)\" -DSYSRUNDIR=\"$(localstatedir)\"

fwknopd_utests_LDADD    = $(top_builddir)/lib/libfko.la $(top_builddir)/common/libfko_util.a

fwknopd_utests_LDFLAGS  = -lcunit -lpcap