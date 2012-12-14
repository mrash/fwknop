# $OpenBSD$

COMMENT=		Single Packet Authorization and Port Knocking

VERSION=		2.0.3
DISTNAME=		fwknop-${VERSION}
EXTRACT_SUFX=		.tar.bz2
CATEGORIES=		net security mystuff

MAINTAINER=		Vlad Glagolev <stealth@sourcemage.org>

HOMEPAGE=		http://www.cipherdyne.org/fwknop/

MASTER_SITES=		http://www.cipherdyne.org/fwknop/download/

SHARED_LIBS+=		fko	0.3

# GPL
PERMIT_PACKAGE_CDROM=	Yes
PERMIT_PACKAGE_FTP=	Yes
PERMIT_DISTFILES_CDROM=	Yes
PERMIT_DISTFILES_FTP=	Yes

WANTLIB=		c pcap iconv intl
WANTLIB+=		gpg-error gpgme assuan
WANTLIB+=		gdbm

CONFIGURE_STYLE=	gnu
USE_GMAKE=		Yes
USE_GROFF=		Yes

# fixes GDBM detection
CONFIGURE_ENV=		LDFLAGS="-L${LOCALBASE}/lib" \
			CFLAGS="-I${LOCALBASE}/include"

CONFIGURE_ARGS+=	--localstatedir='$${DESTDIR}/var' \
			--enable-client \
			--enable-server \
			--enable-digest-cache \
			--disable-file-cache \
			--with-gpgme

LIB_DEPENDS+=		databases/gdbm
LIB_DEPENDS+=		security/gpgme

.include <bsd.port.mk>
