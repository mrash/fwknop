#bin_PROGRAMS        = fwknop_utests fwknopd_utests fko_utests
#
#fwknop_utests_SOURCES  = fwknop_utests.c \
#            ../../client/config_init.c \
#            ../../client/spa_comm.c \
#            ../../client/utils.c \
#            ../../client/http_resolve_host.c  \
#            ../../client/getpasswd.c \
#            ../../client/log_msg.c
#
#fwknop_utests_CPPFLAGS = -I ../../lib -I ../../common -I ../../client
#
#fwknop_utests_LDADD    = ../../lib/libfko.la ../../common/libfko_util.a
#
#fwknop_utests_LDFLAGS  = -lcunit
#
#fwknopd_utests_SOURCES   = fwknopd_utests.c \
#              ../../server/config_init.c \
#              ../../server/incoming_spa.c \
#              ../../server/pcap_capture.c \
#              ../../server/process_packet.c \
#              ../../server/log_msg.c \
#              ../../server/utils.c \
#              ../../server/sig_handler.c \
#              ../../server/replay_cache.c \
#              ../../server/access.c\
#              ../../server/fwknopd_errors.c \
#              ../../server/tcp_server.c \
#              ../../server/extcmd.c \
#              ../../server/fw_util.c \
#              ../../server/fw_util_ipf.c \
#              ../../server/fw_util_ipfw.c \
#              ../../server/fw_util_pf.c \
#              ../../server/fw_util_iptables.c \
#              ../../server/fw_util_firewalld.c
#
#fwknopd_utests_CPPFLAGS = -I ../../lib -I ../../common -I ../../server -DSYSCONFDIR=\"$(sysconfdir)\" -DSYSRUNDIR=\"$(localstatedir)\"
#
#fwknopd_utests_LDADD    = $(top_builddir)/lib/libfko.la $(top_builddir)/common/libfko_util.a
#
#fwknopd_utests_LDFLAGS  = -lcunit -lpcap
#
#fko_utests_SOURCES  = fko_utests.c \
#            ../../lib/base64.c \
#            ../../lib/cipher_funcs.c \
#            ../../lib/digest.c \
#            ../../lib/fko_client_timeout.c \
#            ../../lib/fko_digest.c \
#            ../../lib/fko_encode.c \
#            ../../lib/fko_decode.c \
#            ../../lib/fko_encryption.c \
#            ../../lib/fko_error.c \
#            ../../lib/fko_funcs.c \
#            ../../lib/fko_message.c \
#            ../../lib/fko_nat_access.c \
#            ../../lib/fko_rand_value.c \
#            ../../lib/fko_server_auth.c \
#            ../../lib/fko_timestamp.c \
#            ../../lib/fko_hmac.c \
#            ../../lib/hmac.c \
#            ../../lib/fko_user.c \
#            ../../lib/md5.c \
#            ../../lib/rijndael.c \
#            ../../lib/sha1.c \
#            ../../lib/sha2.c \
#            ../../lib/strlcpy.c \
#            ../../lib/strlcat.c \
#            ../../lib/fko_util.c \
#            ../../lib/gpgme_funcs.c \
#            ../../common/cunit_common.c
#    
#fko_utests_CPPFLAGS = -I ../../lib -I ../../common $(GPGME_CFLAGS)
#
#fko_utests_LDFLAGS  = -lcunit $(GPGME_LIBS)
