
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
    android/project/assets \
    android/project/AndroidManifest.xml \
    android/project/jni/fwknop/fwknop_client.c \
    android/project/jni/fwknop/fwknop_client.h \
    android/project/jni/fwknop/send_spa_packet.c \
    android/project/jni/config.h \
    android/project/jni/libfwknop/README \
    android/project/jni/libfwknop/get_libfko_files.sh \
    android/project/jni/logutils.h \
    android/project/jni/Android.mk \
    extras/fwknop.init.debian \
    extras/fwknop.init.openwrt \
    extras/fwknop.init.redhat \
    extras/openwrt/README.openwrt \
    extras/openwrt/package/fwknop/Makefile \
    extras/openwrt/package/fwknop/files/fwknopd.init \
    extras/openwrt/package/gpgme/Makefile \
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
	python/README \
	python/setup.py \
	python/fkomodule.c \
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

