bin_PROGRAMS        = fwknop

fwknop_SOURCES      = fwknop.c fwknop.h config_init.c config_init.h \
                      fwknop_common.h spa_comm.c spa_comm.h utils.c utils.h \
                      http_resolve_host.c getpasswd.c getpasswd.h

fwknop_CPPFLAGS     = -I $(top_srcdir)/lib -I $(top_srcdir)/common

fwknop_LDADD        = $(top_builddir)/lib/libfko.la

dist_man_MANS       = fwknop.8

EXTRA_DIST          = fwknop.8.in

fwknop.8: fwknop.8.in
	$(SED) \
		-e 's|[@]prefix@|$(prefix)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]datarootdir@|$(datarootdir)|g' \
		-e 's|[@]bindir@|$(bindir)|g' \
		-e 's|[@]sbindir@|$(sbindir)|g' \
		-e 's|[@]localstatedir@|$(localstatedir)|g' \
		< "$<" > "$@"

clean-local:
	rm -f fwknop.8

