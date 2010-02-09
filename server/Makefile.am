sbin_PROGRAMS       = fwknopd

fwknopd_SOURCES     = fwknopd.c fwknopd.h config_init.c config_init.h \
                      fwknopd_common.h incoming_spa.c incoming_spa.h \
                      pcap_capture.c pcap_capture.h process_packet.c \
                      process_packet.h log_msg.c log_msg.h utils.c utils.h \
                      sig_handler.c sig_handler.h replay_dbm.c replay_dbm.h \
                      access.c access.h

fwknopd_LDADD       = $(top_builddir)/lib/libfko.la

fwknopd_CPPFLAGS    = -I $(top_srcdir)/lib -I $(top_srcdir)/common -DSYSCONFDIR=\"$(sysconfdir)\" -DSYSRUNDIR=\"$(localstatedir)\"

fwknopddir          = @sysconfdir@/fwknop

dist_man_MANS		= fwknopd.8

dist_fwknopd_DATA   = fwknopd.conf access.conf

