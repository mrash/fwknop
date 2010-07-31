#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gpgme
PKG_VERSION:=1.1.8
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.dstuart.org/gpgme/
PKG_MD5SUM:=c4045e6533bd78cbf952ed9597dbdd7c

include $(INCLUDE_DIR)/package.mk

PKG_INSTALL=1

define Package/gpgme
  SECTION:=libs
  CATEGORY:=Libraries
  DEPENDS:=+gnupg
  TITLE:=GPGME - GnuPG Made Easy
  URL:=http://www.gnupg.org/
endef

define Package/gpgme/description
	GnuPG Made Easy (GPGME) is a C language library that allows to add
	support for cryptography to a program.  It is designed to make access
	to public key crypto engines like GnuPG or GpgSM easier for
	applications.  GPGME provides a high-level crypto API for encryption,
	decryption, signing, signature verification and key management.
endef

TARGET_CFLAGS += $(FPIC)

define Build/Configure
	$(call Build/Configure/Default, \
		--with-gpg=/usr/bin/gpg \
		--without-gpgsm \
		--without-gpgconf \
		--enable-shared \
		--enable-static \
		--disable-rpath \
	)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(2)/bin $(1)/usr/bin
	$(INSTALL_BIN) \
		$(PKG_INSTALL_DIR)/usr/bin/gpgme-config \
		$(2)/bin/
	$(SED) \
		's,^\(prefix\|exec_prefix\)=.*,\1=$(STAGING_DIR)/usr,g' \
		$(2)/bin/gpgme-config
	ln -sf $(STAGING_DIR)/host/bin/gpgme-config $(1)/usr/bin/gpgme-config

	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DATA) \
		$(PKG_INSTALL_DIR)/usr/include/gpgme.h \
		$(1)/usr/include/

	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) \
		$(PKG_INSTALL_DIR)/usr/lib/libgpgme.{la,a,so*} \
		$(1)/usr/lib/

	$(INSTALL_DIR) $(1)/usr/share/aclocal
	$(INSTALL_DATA) \
		$(PKG_INSTALL_DIR)/usr/share/aclocal/gpgme.m4 \
		$(1)/usr/share/aclocal/
endef

define Package/gpgme/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libgpgme.so.* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,gpgme))
