sbin_PROGRAMS    = fwknopd

fwknopd_SOURCES   = fwknopd.c fwknopd.h config_init.c config_init.h \
                    fwknopd_common.h incoming_spa.c incoming_spa.h \
                    pcap_capture.c pcap_capture.h process_packet.c \
                    process_packet.h log_msg.c log_msg.h utils.c utils.h \
                    sig_handler.c sig_handler.h replay_dbm.c replay_dbm.h \
                    access.c access.h fw_util.c fw_util.h extcmd.c extcmd.h \
                    tcp_server.c tcp_server.h

fwknopd_LDADD     = $(top_builddir)/lib/libfko.la -lpcap
if USE_NDBM
    fwknopd_LDADD += -lndbm
else
    fwknopd_LDADD += -lgdbm
endif

fwknopd_CPPFLAGS  = -I $(top_srcdir)/lib -I $(top_srcdir)/common -DSYSCONFDIR=\"$(sysconfdir)\" -DSYSRUNDIR=\"$(localstatedir)\"

fwknopddir        = @sysconfdir@/fwknop

dist_man_MANS     = fwknopd.8

dist_fwknopd_DATA = fwknopd.conf access.conf

EXTRA_DIST        = fwknopd.8.in

fwknopd.8: fwknopd.8.in
	$(SED) \
		-e 's|[@]prefix@|$(prefix)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]datarootdir@|$(datarootdir)|g' \
		-e 's|[@]bindir@|$(bindir)|g' \
		-e 's|[@]sbindir@|$(sbindir)|g' \
		-e 's|[@]localstatedir@|$(localstatedir)|g' \
		< "$<" > "$@"

clean-local:
	rm -f fwknopd.8

