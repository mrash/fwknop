
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
	extras \
    fwknop.spec \
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

