ACLOCAL_AMFLAGS = -I m4

if WANT_CLIENT
  CLIENT_DIR = client
endif

if WANT_SERVER
  SERVER_DIR = server
endif

SUBDIRS = \
    lib \
    common \
    $(CLIENT_DIR) \
    $(SERVER_DIR) \
    doc

EXTRA_DIST = \
    android/COPYING \
    android/Application.mk \
    android/README \
    android/project/src/com/max2idea/android/fwknop/R.java \
    android/project/src/com/max2idea/android/fwknop/Fwknop.java \
    android/project/build.xml \
    android/project/default.properties \
    android/project/res/values/strings.xml \
    android/project/res/drawable-hdpi/icon.png \
    android/project/res/drawable-mdpi/icon.png \
    android/project/res/drawable-ldpi/icon.png \
    android/project/res/drawable/lock_64x64.png \
    android/project/res/drawable/lock_32x32.png \
    android/project/res/drawable/lock_128x128.png \
    android/project/res/layout/main.xml \
    android/project/nbproject/project.properties \
    android/project/nbproject/project.xml \
    android/project/nbproject/build-impl.xml \
    android/project/nbproject/private/private.properties \
    android/project/nbproject/private/private.xml \
    android/project/nbproject/private/config.properties \
    android/project/nbproject/genfiles.properties \
    android/project/build.properties \
    android/project/AndroidManifest.xml \
    android/project/jni/fwknop/fwknop_client.c \
    android/project/jni/fwknop/fwknop_client.h \
    android/project/jni/fwknop/send_spa_packet.c \
    android/project/jni/config.h \
    android/project/jni/libfwknop/README \
    android/project/jni/libfwknop/get_libfko_files.sh \
    android/project/jni/logutils.h \
    android/project/jni/Android.mk \
    ChangeLog \
    ChangeLog.git \
    CREDITS \
    todo.org \
    extras/upstart/fwknop.conf \
    extras/fwknop.init.debian \
    extras/fwknop.init.openwrt \
    extras/fwknop.init.redhat \
    extras/myip/myip.c \
    extras/openwrt/README.openwrt \
    extras/openwrt/package/fwknop/Makefile \
    extras/openwrt/package/fwknop/files/fwknopd.init \
    extras/openwrt/package/gpgme/Makefile \
    extras/fwknop-launcher/fwknop-launcher-lsof.pl \
    extras/fwknop-launcher/fwknop-launcher.conf \
    fwknop.spec \
    iphone/main.m \
    iphone/Fwknop.xcodeproj \
    iphone/Fwknop.xcodeproj/project.pbxproj \
    iphone/Fwknop.xcodeproj/dev.pbxuser \
    iphone/Fwknop.xcodeproj/dev.mode1v3 \
    iphone/lock_57x57.png \
    iphone/Fwknop.pch \
    iphone/README \
    iphone/Info.plist \
    iphone/COPYING \
    iphone/Classes \
    iphone/Classes/MyAppDelegate.h \
    iphone/Classes/fwknop \
    iphone/Classes/fwknop/send_spa_packet.c \
    iphone/Classes/fwknop/fwknop_client.c \
    iphone/Classes/fwknop/fwknop_client.h \
    iphone/Classes/FwknopController.m \
    iphone/Classes/config.h \
    iphone/Classes/FwknopController.h \
    iphone/Classes/bridge_fwknop.h \
    iphone/Classes/MyAppDelegate.m \
    iphone/Classes/libfwknop \
    iphone/Classes/libfwknop/README \
    iphone/Classes/libfwknop/config.h \
    iphone/Classes/libfwknop/fko_common.b \
    iphone/Classes/libfwknop/get_libfko_files.sh \
    iphone/Classes/bridge_fwknop.c \
    iphone/Classes/logutils.h \
    perl/FKO/README \
    perl/FKO/inc/Devel/CheckLib.pm \
    perl/FKO/MANIFEST \
    perl/FKO/ppport.h \
    perl/FKO/FKO.xs \
    perl/FKO/t/03_errors.t \
    perl/FKO/t/02_functions.t \
    perl/FKO/t/01_constants.t \
    perl/FKO/t/00_init.t \
    perl/FKO/Makefile.PL \
    perl/FKO/typemap \
    perl/FKO/lib/FKO.pm \
    perl/FKO/lib/FKO_Constants.pl \
    perl/FKO/Changes \
    python/README \
    python/setup.py \
    python/fkomodule.c \
    python/fko.py \
    test/conf/client-gpg/pubring.gpg \
    test/conf/client-gpg/secring.gpg \
    test/conf/client-gpg/trustdb.gpg \
    test/conf/client-gpg-no-pw/pubring.gpg \
    test/conf/client-gpg-no-pw/secring.gpg \
    test/conf/client-gpg-no-pw/trustdb.gpg \
    test/conf/server-gpg/pubring.gpg \
    test/conf/server-gpg/secring.gpg \
    test/conf/server-gpg/trustdb.gpg \
    test/conf/server-gpg-no-pw/pubring.gpg \
    test/conf/server-gpg-no-pw/secring.gpg \
    test/conf/server-gpg-no-pw/trustdb.gpg \
    test/conf/default_access.conf \
    test/conf/default_fwknopd.conf \
    test/conf/dual_key_usage_access.conf \
    test/conf/expired_epoch_stanza_access.conf \
    test/conf/expired_stanza_access.conf \
    test/conf/force_nat_access.conf \
    test/conf/future_expired_stanza_access.conf \
    test/conf/gpg_access.conf \
    test/conf/gpg_no_pw_access.conf \
    test/conf/invalid_expire_access.conf \
    test/conf/ip_source_match_access.conf \
    test/conf/mismatch_open_ports_access.conf \
    test/conf/mismatch_user_access.conf \
    test/conf/multi_gpg_access.conf \
    test/conf/multi_source_match_access.conf \
    test/conf/multi_stanzas_access.conf \
    test/conf/multi_stanzas_with_broken_keys.conf \
    test/conf/nat_fwknopd.conf \
    test/conf/ipfw_active_expire_equal_fwknopd.conf \
    test/conf/no_multi_source_match_access.conf \
    test/conf/no_source_match_access.conf \
    test/conf/no_subnet_source_match_access.conf \
    test/conf/open_ports_access.conf \
    test/conf/override_fwknopd.conf \
    test/conf/require_src_access.conf \
    test/conf/require_user_access.conf \
    test/conf/subnet_source_match_access.conf \
    test/conf/local_nat_fwknopd.conf \
    test/conf/disable_aging_fwknopd.conf \
    test/conf/disable_aging_nat_fwknopd.conf \
    test/conf/fuzzing_source_access.conf \
    test/conf/fuzzing_open_ports_access.conf \
    test/conf/fuzzing_restrict_ports_access.conf \
    test/conf/tcp_pcap_filter_fwknopd.conf \
    test/conf/icmp_pcap_filter_fwknopd.conf \
    test/conf/tcp_server_fwknopd.conf \
    test/fuzzing/patches/enable_perl_fko_bogus_packets.patch \
    test/fuzzing/patches/encoding_rm_colon1.patch \
    test/fuzzing/patches/encoding_rm_colon2.patch \
    test/fuzzing/patches/encoding_rm_colon3.patch \
    test/fuzzing/patches/encoding_rm_colon4.patch \
    test/fuzzing/patches/encoding_rm_colon5.patch \
    test/fuzzing/patches/extra_timestamp_digit.patch \
    test/fuzzing/patches/invalid_access_format.patch \
    test/fuzzing/patches/invalid_long_proto_define_enc_mode_trigger.patch \
    test/fuzzing/patches/invalid_long_proto_define_rijndael_trigger.patch \
    test/fuzzing/patches/long_ip.patch \
    test/fuzzing/patches/non_b64_user_char.patch \
    test/fuzzing/fuzzing_spa_packets \
    test/hardening-check \
    test/local_spa.key \
    test/test-fwknop.pl \
    VERSION \
    win32/config.h \
    win32/fwknop-client.vcproj \
    win32/getopt.c \
    win32/getopt1.c \
    win32/getopt.h \
    win32/getlogin.c \
    win32/getlogin.h \
    win32/libfko.sln \
    win32/libfko.vcproj

# Make dist makes the man pages to put them in the distribution.  We
# do not want that. They will be remade after configure and make is
# later.  This is bit of a kludge, but seems to work (until I find a
# better way).   --DSS
#
dist-hook:
	rm -f $(distdir)/client/fwknop.8
	rm -f $(distdir)/server/fwknopd.8

uninstall-local:
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf; then \
		rm -f $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf; \
	fi
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf.inst; then \
		rm -f $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf.inst; \
	fi
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/access.conf; then \
		rm -f $(DESTDIR)$(sysconfdir)/fwknop/access.conf; \
	fi
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/access.conf.inst; then \
		rm -f $(DESTDIR)$(sysconfdir)/fwknop/access.conf.inst; \
	fi

install-exec-hook:
	if test -d $(DESTDIR)$(sysconfdir)/fwknop; then \
		chmod 700 $(DESTDIR)$(sysconfdir)/fwknop; \
	fi
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf; then :; \
	else \
		if test -f $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf.inst; then \
			mv $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf.inst $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf; \
		fi \
	fi
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/access.conf; then :; \
	else \
		if test -f $(DESTDIR)$(sysconfdir)/fwknop/access.conf.inst; then \
			mv $(DESTDIR)$(sysconfdir)/fwknop/access.conf.inst $(DESTDIR)$(sysconfdir)/fwknop/access.conf; \
		fi \
	fi
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf; then \
		chmod 600 $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf; \
	fi
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/access.conf; then \
		chmod 600 $(DESTDIR)$(sysconfdir)/fwknop/access.conf; \
	fi
