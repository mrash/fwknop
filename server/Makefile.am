sbin_PROGRAMS       = fwknopd

BASE_SOURCE_FILES   = fwknopd.h config_init.c config_init.h \
                      fwknopd_common.h incoming_spa.c incoming_spa.h \
                      pcap_capture.c pcap_capture.h process_packet.c \
                      process_packet.h log_msg.c log_msg.h utils.c utils.h \
                      sig_handler.c sig_handler.h replay_cache.c replay_cache.h \
                      access.c access.h fwknopd_errors.c fwknopd_errors.h \
                      tcp_server.c tcp_server.h udp_server.c udp_server.h \
                      fw_util.c fw_util.h fw_util_ipf.c fw_util_ipf.h \
                      fw_util_firewalld.c fw_util_firewalld.h \
                      fw_util_iptables.c fw_util_iptables.h \
                      fw_util_ipfw.c fw_util_ipfw.h \
                      fw_util_pf.c fw_util_pf.h cmd_opts.h \
                      extcmd.c extcmd.h cmd_cycle.c cmd_cycle.h

fwknopd_SOURCES   = fwknopd.c $(BASE_SOURCE_FILES)

if NFQ_CAPTURE
    fwknopd_SOURCES += nfq_capture.c nfq_capture.h
endif

fwknopd_LDADD     = $(top_builddir)/lib/libfko.la $(top_builddir)/common/libfko_util.la $(top_builddir)/gnulib/libgnu.la

if WANT_C_UNIT_TESTS
    noinst_PROGRAMS         = fwknopd_utests
    fwknopd_utests_SOURCES  = fwknopd_utests.c $(BASE_SOURCE_FILES)
    fwknopd_utests_CPPFLAGS = -I$(top_builddir)/gnulib -I$(top_srcdir)/gnulib -I $(top_builddir)/lib -I $(top_builddir)/common $(GPGME_CFLAGS) -DSYSCONFDIR=\"$(sysconfdir)\" -DSYSRUNDIR=\"$(localstatedir)\"
    fwknopd_utests_LDADD    = $(top_builddir)/lib/libfko.la $(top_builddir)/common/libfko_util.a
    fwknopd_utests_LDFLAGS  = -lcunit $(GPGME_LIBS)

if NFQ_CAPTURE
    fwknopd_utests_LDFLAGS += -lnetfilter_queue -lnfnetlink
else
if !UDP_SERVER
    fwknopd_utests_LDFLAGS += -lpcap
endif
endif

endif

if NFQ_CAPTURE
    fwknopd_LDADD += -lnetfilter_queue -lnfnetlink
else
if !UDP_SERVER
    fwknopd_LDADD += -lpcap
endif
endif


if !CONFIG_FILE_CACHE
if USE_NDBM
    fwknopd_LDADD += -lndbm
else
    fwknopd_LDADD += -lgdbm
endif
endif

fwknopd_CPPFLAGS  = -I$(top_builddir)/gnulib -I$(top_srcdir)/gnulib -I $(top_srcdir)/lib -I $(top_srcdir)/common -DSYSCONFDIR=\"$(sysconfdir)\" -DSYSRUNDIR=\"$(localstatedir)\"

fwknopddir        = @sysconfdir@/fwknop

dist_man_MANS     = fwknopd.8

dist_fwknopd_DATA = fwknopd.conf.inst access.conf.inst

EXTRA_DIST        = fwknopd.8.in

fwknopd.8: $(top_srcdir)/server/fwknopd.8.in
	$(SED) \
		-e 's|[@]prefix@|$(prefix)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]datarootdir@|$(datarootdir)|g' \
		-e 's|[@]bindir@|$(bindir)|g' \
		-e 's|[@]sbindir@|$(sbindir)|g' \
		-e 's|[@]localstatedir@|$(localstatedir)|g' \
		< $(top_srcdir)/server/fwknopd.8.in > "$@"

clean-local:
	rm -f fwknopd.8 fwknopd_utests *.gcno *.gcda
