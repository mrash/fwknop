ACLOCAL_AMFLAGS = -I m4

if WANT_CLIENT
  CLIENT_DIR = client
endif

if WANT_SERVER
  SERVER_DIR = server
endif

if WANT_C_UNIT_TESTS
    C_UNIT_TESTS_DIR = test/c-unit-tests
endif

SUBDIRS = \
    lib \
    common \
    $(CLIENT_DIR) \
    $(SERVER_DIR) \
    $(C_UNIT_TESTS_DIR) \
    doc

EXTRA_DIST = \
    android/COPYING \
    android/Application.mk \
    android/README \
    android/project/src/com/max2idea/android/fwknop/Fwknop.java \
    android/project/project.properties \
    android/project/sdk.paths \
    android/project/ant.properties \
    android/project/build.xml \
    android/project/custom_rules.xml \
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
    android/project/AndroidManifest.xml \
    android/project/jni/fwknop/fwknop_client.c \
    android/project/jni/fwknop/fwknop_client.h \
    android/project/jni/fwknop/get_libfko_header.sh \
    android/project/jni/fwknop/send_spa_packet.c \
    android/project/jni/config.h \
    android/project/jni/libfwknop/README \
    android/project/jni/libfwknop/get_libfko_files.sh \
    android/project/jni/logutils.h \
    android/project/jni/Android.mk \
    ChangeLog \
    ChangeLog.git \
    CREDITS \
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
    extras/apparmor/usr.sbin.fwknopd \
    extras/apparmor/configure_args.sh \
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
    m4/gpgme.m4 \
    perl/FKO/README \
    perl/FKO/inc/Devel/CheckLib.pm \
    perl/FKO/MANIFEST \
    perl/FKO/ppport.h \
    perl/FKO/FKO.xs \
    perl/FKO/t/fuzzing_spa_packets \
    perl/FKO/t/04_fuzzing.t \
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
    test/conf/gpg_dirs_orig.tar.gz \
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
    test/conf/hmac_android_access.conf \
    test/conf/android_access.conf \
    test/conf/android_legacy_iv_access.conf \
    test/conf/base64_key_access.conf \
    test/conf/cfb_mode_access.conf \
    test/conf/cmd_access.conf \
    test/conf/cmd_setuid_access.conf \
    test/conf/cmd_giduid_access.conf \
    test/conf/ctr_mode_access.conf \
    test/conf/default_access.conf \
    test/conf/default_fwknopd.conf \
    test/conf/portrange_fwknopd.conf \
    test/conf/ipt_custom_input_chain_fwknopd.conf \
    test/conf/firewd_custom_input_chain_fwknopd.conf \
    test/conf/ipt_custom_nat_chain_fwknopd.conf \
    test/conf/firewd_custom_nat_chain_fwknopd.conf \
    test/conf/gpg_invalid_exe_access.conf \
    test/conf/disable_aging_fwknopd.conf \
    test/conf/disable_aging_nat_fwknopd.conf \
    test/conf/dual_key_usage_access.conf \
    test/conf/dual_key_legacy_iv_access.conf \
    test/conf/ecb_mode_access.conf \
    test/conf/expired_epoch_stanza_access.conf \
    test/conf/expired_stanza_access.conf \
    test/conf/force_nat_access.conf \
    test/conf/future_expired_stanza_access.conf \
    test/conf/fuzzing_open_ports_access.conf \
    test/conf/fuzzing_restrict_ports_access.conf \
    test/conf/fuzzing_source_access.conf \
    test/conf/hmac_fuzzing_access.conf \
    test/conf/gpg_access.conf \
    test/conf/gpg_hmac_access.conf \
    test/conf/gpg_no_pw_access.conf \
    test/conf/gpg_no_pw_hmac_access.conf \
    test/conf/gpg_no_pw_hmac_clientdir_access.conf \
    test/conf/gpg_no_pw_hmac_serverdir_access.conf \
    test/conf/gpg_no_pw_fpr_access.conf \
    test/conf/gpg_no_pw_bad_fpr_access.conf \
    test/conf/gpg_no_pw_no_fpr_access.conf \
    test/conf/gpg_no_sig_no_fpr_access.conf \
    test/conf/gpg_no_sig_verify_access.conf \
    test/conf/gpg_invalid_sig_id_access.conf \
    test/conf/fwknoprc_gpg_invalid_exe \
    test/conf/fwknoprc_hmac_defaults \
    test/conf/fwknoprc_hmac_time_offset_mins \
    test/conf/fwknoprc_hmac_time_offset_hours \
    test/conf/fwknoprc_hmac_time_offset_days \
    test/conf/fwknoprc_hmac_http_resolve \
    test/conf/fwknoprc_hmac_https_resolve \
    test/conf/fwknoprc_hmac_http_only_resolve \
    test/conf/fwknoprc_gpg_hmac_sha512_key \
    test/conf/gpg_hmac_sha512_access.conf \
    test/conf/fwknoprc_hmac_sha512_base64_key \
    test/conf/gpg_no_pw_hmac_sha512_access.conf \
    test/conf/ipt_no_flush_init_fwknopd.conf \
    test/conf/ipt_no_flush_exit_fwknopd.conf \
    test/conf/ipt_no_flush_init_or_exit_fwknopd.conf \
    test/conf/firewd_no_flush_init_fwknopd.conf \
    test/conf/firewd_no_flush_exit_fwknopd.conf \
    test/conf/firewd_no_flush_init_or_exit_fwknopd.conf \
    test/conf/hmac_access.conf \
    test/conf/hmac_cmd_access.conf \
    test/conf/hmac_cmd_setuid_access.conf \
    test/conf/hmac_cmd_giduid_access.conf \
    test/conf/hmac_get_key_access.conf \
    test/conf/hmac_no_b64_access.conf \
    test/conf/hmac_equal_keys_access.conf \
    test/conf/hmac_dual_key_usage_access.conf \
    test/conf/hmac_invalid_type_access.conf \
    test/conf/hmac_md5_access.conf \
    test/conf/hmac_md5_short_key_access.conf \
    test/conf/hmac_md5_long_key_access.conf \
    test/conf/hmac_sha1_access.conf \
    test/conf/hmac_sha1_short_key_access.conf \
    test/conf/hmac_sha1_long_key_access.conf \
    test/conf/hmac_sha256_access.conf \
    test/conf/hmac_sha256_short_key_access.conf \
    test/conf/hmac_sha256_long_key_access.conf \
    test/conf/hmac_sha384_access.conf \
    test/conf/hmac_sha384_short_key_access.conf \
    test/conf/hmac_sha384_long_key_access.conf \
    test/conf/hmac_sha512_access.conf \
    test/conf/hmac_sha512_short_key_access.conf \
    test/conf/hmac_sha512_short_key2_access.conf \
    test/conf/hmac_sha512_long_key_access.conf \
    test/conf/hmac_simple_keys_access.conf \
    test/conf/hmac_sha256_open_ports_access.conf \
    test/conf/hmac_force_nat_access.conf \
    test/conf/hmac_force_snat_access.conf \
    test/conf/hmac_force_masq_access.conf \
    test/conf/hmac_no_b64_cygwin_access.conf \
    test/conf/multi_pkts.pcap \
    test/conf/fwknoprc_default_hmac_base64_key \
    test/conf/fwknoprc_hmac_nat_rand_base64_key \
    test/conf/fwknoprc_hmac_spoof_src_base64_key \
    test/conf/fwknoprc_hmac_key2 \
    test/conf/fwknoprc_gpg_hmac_key \
    test/conf/fwknoprc_hmac_equal_keys \
    test/conf/fwknoprc_hmac_invalid_type \
    test/conf/fwknoprc_hmac_md5_key \
    test/conf/fwknoprc_hmac_md5_long_key \
    test/conf/fwknoprc_hmac_md5_short_key \
    test/conf/fwknoprc_hmac_sha1_key \
    test/conf/fwknoprc_hmac_sha1_long_key \
    test/conf/fwknoprc_hmac_sha1_short_key \
    test/conf/fwknoprc_hmac_sha256_key \
    test/conf/fwknoprc_hmac_sha256_long_key \
    test/conf/fwknoprc_hmac_sha256_short_key \
    test/conf/fwknoprc_hmac_sha384_key \
    test/conf/fwknoprc_hmac_sha384_long_key \
    test/conf/fwknoprc_hmac_sha384_short_key \
    test/conf/fwknoprc_hmac_sha512_key \
    test/conf/fwknoprc_hmac_sha512_short_key \
    test/conf/fwknoprc_hmac_sha512_long_key \
    test/conf/fwknoprc_hmac_simple_keys \
    test/conf/hmac_sha256_digest1_mismatch_access.conf \
    test/conf/hmac_sha256_digest3_mismatch_access.conf \
    test/conf/hmac_sha256_digest2_mismatch_access.conf \
    test/conf/hmac_sha256_digest4_mismatch_access.conf \
    test/conf/fwknoprc_rand_port_hmac_base64_key \
    test/conf/fwknoprc_invalid_base64_key \
    test/conf/fwknoprc_named_key \
    test/conf/fwknoprc_with_default_base64_key \
    test/conf/fwknoprc_with_default_key \
    test/conf/fwknoprc_with_named_key \
    test/conf/fwknoprc_gpg_args_hmac_key \
    test/conf/fwknoprc_gpg_args_no_pw_hmac_key \
    test/conf/fwknoprc_gpg_signing_pw \
    test/conf/fwknoprc_named_gpg_signing_pw \
    test/conf/fwknoprc_stanza_list \
    test/conf/icmp_pcap_filter_fwknopd.conf \
    test/conf/invalid_expire_access.conf \
    test/conf/invalid_source_access.conf \
    test/conf/ipt_output_chain_fwknopd.conf \
    test/conf/firewd_output_chain_fwknopd.conf \
    test/conf/invalid_ipt_input_chain_fwknopd.conf \
    test/conf/invalid_ipt_input_chain_2_fwknopd.conf \
    test/conf/invalid_ipt_input_chain_3_fwknopd.conf \
    test/conf/invalid_ipt_input_chain_4_fwknopd.conf \
    test/conf/invalid_ipt_input_chain_5_fwknopd.conf \
    test/conf/invalid_ipt_input_chain_6_fwknopd.conf \
    test/conf/invalid_firewd_input_chain_fwknopd.conf \
    test/conf/invalid_firewd_input_chain_2_fwknopd.conf \
    test/conf/invalid_firewd_input_chain_3_fwknopd.conf \
    test/conf/invalid_firewd_input_chain_4_fwknopd.conf \
    test/conf/invalid_firewd_input_chain_5_fwknopd.conf \
    test/conf/invalid_firewd_input_chain_6_fwknopd.conf \
    test/conf/invalid_run_dir_path_fwknopd.conf \
    test/conf/ipfw_active_expire_equal_fwknopd.conf \
    test/conf/ip_source_match_access.conf \
    test/conf/legacy_iv_access.conf \
    test/conf/legacy_iv_long_key_access.conf \
    test/conf/legacy_iv_long_key2_access.conf \
    test/conf/ipt_local_nat_fwknopd.conf \
    test/conf/firewd_local_nat_fwknopd.conf \
    test/conf/mismatch_open_ports_access.conf \
    test/conf/mismatch_user_access.conf \
    test/conf/multi_gpg_access.conf \
    test/conf/multi_gpg_no_pw_access.conf \
    test/conf/multi_source_match_access.conf \
    test/conf/multi_stanzas_access.conf \
    test/conf/multi_stanzas_with_broken_keys.conf \
    test/conf/ipt_nat_fwknopd.conf \
    test/conf/firewd_nat_fwknopd.conf \
    test/conf/no_multi_source_match_access.conf \
    test/conf/no_source_match_access.conf \
    test/conf/no_subnet_source_match_access.conf \
    test/conf/ofb_mode_access.conf \
    test/conf/open_ports_access.conf \
    test/conf/override_fwknopd.conf \
    test/conf/override2_fwknopd.conf \
    test/conf/override_no_digest_tracking_fwknopd.conf \
    test/conf/var_expansion_fwknopd.conf \
    test/conf/var_expansion_invalid_fwknopd.conf \
    test/conf/require_src_access.conf \
    test/conf/require_user_access.conf \
    test/conf/subnet_source_match_access.conf \
    test/conf/tcp_pcap_filter_fwknopd.conf \
    test/conf/tcp_server_fwknopd.conf \
    test/conf/udp_server_fwknopd.conf \
    test/conf/spa_over_http_fwknopd.conf \
    test/conf/spa_over_http.pcap \
    test/conf/ipt_snat_fwknopd.conf \
    test/conf/firewd_snat_fwknopd.conf \
    test/conf/ipt_snat_no_translate_ip_fwknopd.conf \
    test/conf/firewd_snat_no_translate_ip_fwknopd.conf \
    test/conf/destination_rule_fwknopd.conf \
    test/conf/hmac_spa_destination_access.conf \
    test/conf/hmac_spa_destination2_access.conf \
    test/conf/hmac_spa_destination3_access.conf \
    test/conf/hmac_spa_destination4_access.conf \
    test/conf/hmac_spa_destination5_access.conf \
    test/conf/spa_replay.pcap \
    test/conf/fcs_spa.pcap \
    test/fko-wrapper/Makefile \
    test/fko-wrapper/fko_wrapper.c \
    test/fko-wrapper/fko_basic.c \
    test/fko-wrapper/run.sh \
    test/fko-wrapper/run_valgrind.sh \
    test/spa_fuzzing.py \
    test/fuzzing/patches/enable_perl_fko_bogus_packets.patch \
    test/fuzzing/patches/encoding_append_b64_modified_byte_eq.patch \
    test/fuzzing/patches/encoding_append_b64_modified_byte.patch \
    test/fuzzing/patches/encoding_extra_colon1.patch \
    test/fuzzing/patches/encoding_extra_colon2.patch \
    test/fuzzing/patches/encoding_extra_colon3.patch \
    test/fuzzing/patches/encoding_non_b64_access_msg.patch \
    test/fuzzing/patches/encoding_non_digit_rand_val.patch \
    test/fuzzing/patches/encoding_rm_colon1.patch \
    test/fuzzing/patches/encoding_rm_colon2.patch \
    test/fuzzing/patches/encoding_rm_colon3.patch \
    test/fuzzing/patches/encoding_rm_colon4.patch \
    test/fuzzing/patches/encoding_rm_colon5.patch \
    test/fuzzing/patches/encoding_strip_eq_return.patch \
    test/fuzzing/patches/extra_timestamp_digit.patch \
    test/fuzzing/patches/invalid_access_format.patch \
    test/fuzzing/patches/invalid_long_proto_define_enc_mode_trigger.patch \
    test/fuzzing/patches/invalid_long_proto_define_rijndael_trigger.patch \
    test/fuzzing/patches/long_ip.patch \
    test/fuzzing/patches/non_b64_user_char.patch \
    test/misc/freebsd_rc.conf \
    test/misc/pf.rules \
    test/misc/pf.sh \
    test/afl/compile/afl-compile-code-coverage.sh \
    test/afl/compile/afl-compile-no-enable-arg.sh \
    test/afl/compile/afl-compile.sh \
    test/afl/compile/afl-gen-code-coverage.sh \
    test/afl/doc/AFL_status_screen.png \
    test/afl/README \
    test/afl/fuzzing-wrappers/client-rc.sh \
    test/afl/fuzzing-wrappers/fcns \
    test/afl/fuzzing-wrappers/helpers/fwknop-rc-hangs.sh \
    test/afl/fuzzing-wrappers/helpers/fwknop-rc-test.sh \
    test/afl/fuzzing-wrappers/helpers/fwknopd-digest-cache.sh \
    test/afl/fuzzing-wrappers/helpers/fwknopd-parse-access-hangs.sh \
    test/afl/fuzzing-wrappers/helpers/fwknopd-parse-access.sh \
    test/afl/fuzzing-wrappers/helpers/fwknopd-parse-conf-hangs.sh \
    test/afl/fuzzing-wrappers/helpers/fwknopd-parse-conf.sh \
    test/afl/fuzzing-wrappers/helpers/fwknopd-stdin-hangs.sh \
    test/afl/fuzzing-wrappers/helpers/fwknopd-stdin-test.sh \
    test/afl/fuzzing-wrappers/helpers/fwknopd-enc-pkt-file.sh \
    test/afl/fuzzing-wrappers/server-access.sh \
    test/afl/fuzzing-wrappers/server-conf.sh \
    test/afl/fuzzing-wrappers/server-digest-cache.sh \
    test/afl/fuzzing-wrappers/spa-pkts.sh \
    test/afl/fuzzing-wrappers/server-enc-pkts.sh \
    test/afl/test-cases/client-rc/fwknoprc \
    test/afl/test-cases/server-access/access.conf \
    test/afl/test-cases/server-conf/fwknopd.conf \
    test/afl/test-cases/spa-pkts/spa.start \
    test/afl/test-cases/spa-pkts/spa2.start \
    test/afl/test-cases/spa-pkts/spa3.start \
    test/afl/test-cases/enc-pkts/spa.enc \
    test/tests/build_security.pl \
    test/tests/preliminaries.pl \
    test/tests/code_structure.pl \
    test/tests/configure_args.pl \
    test/tests/basic_operations.pl \
    test/tests/rijndael_hmac.pl \
    test/tests/rijndael_hmac_fuzzing.pl \
    test/tests/rijndael_hmac_cmd_exec.pl \
    test/tests/rijndael_backwards_compatibility.pl \
    test/tests/os_compatibility.pl \
    test/tests/fault_injection.pl \
    test/tests/afl_fuzzing.pl \
    test/tests/gpg_hmac.pl \
    test/tests/gpg_no_pw.pl \
    test/tests/gpg_no_pw_hmac.pl \
    test/tests/gpg.pl \
    test/tests/rijndael_fuzzing.pl \
    test/tests/perl_FKO_module.pl \
    test/tests/python_fko.pl \
    test/tests/rijndael_replay_attacks.pl \
    test/tests/rijndael.pl \
    test/tests/rijndael_cmd_exec.pl \
    test/hardening-check \
    test/local_spa.key \
    test/invalid.key \
    test/invalid2.key \
    test/invalid3.key \
    test/long_spa.key \
    test/invalid.args \
    test/test-fwknop.pl \
    test/generate_cores.sh \
    test/fko-python.py \
    test/run-test-suite.sh \
    test/valgrind_suppressions \
    test/configure_max_coverage.sh \
    test/rm-coverage-files.sh \
    test/gen-coverage-report.sh \
    test/init-lcov.sh \
    test/lcov.env \
    test/configure_max_coverage.sh \
    test/README \
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
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf.inst; then \
		chmod 600 $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf.inst; \
	fi
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/access.conf.inst; then \
		chmod 600 $(DESTDIR)$(sysconfdir)/fwknop/access.conf.inst; \
	fi
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf; then \
		chmod 600 $(DESTDIR)$(sysconfdir)/fwknop/fwknopd.conf; \
	fi
	if test -f $(DESTDIR)$(sysconfdir)/fwknop/access.conf; then \
		chmod 600 $(DESTDIR)$(sysconfdir)/fwknop/access.conf; \
	fi
