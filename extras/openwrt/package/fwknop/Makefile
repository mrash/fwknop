include $(TOPDIR)/rules.mk

PKG_NAME:=fwknopd
PKG_VERSION:=2.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/fwknop-$(PKG_VERSION)
PKG_SOURCE:=fwknop-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.cipherdyne.org/fwknop/download
PKG_MD5SUM:=c78252216fa9627cacf61b453da915a8
PKG_CAT:=zcat
include $(INCLUDE_DIR)/package.mk

define Package/fwknopd
       SECTION:=net
       CATEGORY:=Network
       DEFAULT:=n
       TITLE:=Firewall Knock Operator Daemon
       URL:=http://http://www.cipherdyne.org/fwknop/
       MAINTAINER:=Jonathan Bennett <jbscience87@gmail.com>
       DEPENDS:=+libpcap +iptables
endef

define Package/fwknopd/description
       Firewall Knock Operator Daemon
       Fwknop implements an authorization scheme known as Single Packet
       Authorization (SPA) for Linux systems running iptables.  This mechanism
       requires only a single encrypted and non-replayed packet to communicate
       various pieces of information including desired access through an iptables
       policy. The main application of this program is to use iptables in a
       default-drop stance to protect services such as SSH with an additional
       layer of security in order to make the exploitation of vulnerabilities
       (both 0-day and unpatched code) much more difficult.
endef

define Package/Conffiles
       fwknopd.conf
endef

CONFIGURE_ARGS += \
       --disable-client \
       --without-gpgme \
       --with-iptables=/usr/sbin/iptables



define Package/fwknopd/install
       $(INSTALL_DIR) $(1)/usr/sbin
       $(INSTALL_DIR) $(1)/etc/fwknop
       $(INSTALL_DIR) $(1)/etc/init.d
       $(INSTALL_DIR) $(1)/usr/lib
       $(INSTALL_BIN) $(PKG_BUILD_DIR)/extras/fwknop.init.openwrt $(1)/etc/init.d/fwknopd
       $(INSTALL_BIN) $(PKG_BUILD_DIR)/server/.libs/fwknopd $(1)/usr/sbin/
       $(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/.libs/libfko.so.0.0.2 $(1)/usr/lib/libfko.so.0
       $(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/.libs/libfko.so.0.0.2 $(1)/usr/lib/libfko.so.0.0.2
       $(INSTALL_CONF) $(PKG_BUILD_DIR)/server/fwknopd.conf $(1)/etc/fwknop/
       $(INSTALL_CONF) $(PKG_BUILD_DIR)/server/access.conf $(1)/etc/fwknop/

endef

$(eval $(call BuildPackage,fwknopd))
#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=fwknop
PKG_VERSION:=2.0.0rc1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.dstuart.org/fwknop/
PKG_MD5SUM:=86c41edbe78bd15e6e5e351741cb26dd

include $(INCLUDE_DIR)/package.mk

PKG_INSTALL=1

define Package/fwknop
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+gpgme +libgdbm +libpcap +iptables
  TITLE:=Firewall KNock OPerator - fwknop
  URL:=http://www.cipherdyne.org/fwknop
endef

define Package/fwknop/description
	Fwknop implements an authorization scheme known as Single Packet
	Authorization (SPA) for Linux systems running iptables.  This mechanism
	requires only a single encrypted and non-replayed packet to communicate
	various pieces of information including desired access through an iptables
	policy. The main application of this program is to use iptables in a
	default-drop stance to protect services such as SSH with an additional
	layer of security in order to make the exploitation of vulnerabilities
	(both 0-day and unpatched code) much more difficult.
endef

TARGET_CFLAGS += $(FPIC)

define Build/Configure
	$(call Build/Configure/Default, \
		--enable-shared \
		--enable-static \
		--with-gpgme \
		--with-gpg=/usr/bin/gpg \
		--with-iptables=/usr/sbin/iptables \
		--with-sh=/bin/sh \
	)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DATA) \
		$(PKG_INSTALL_DIR)/usr/include/fko.h \
		$(1)/usr/include/

	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) \
		$(PKG_INSTALL_DIR)/usr/lib/libfko.{la,a,so*} \
		$(1)/usr/lib/
endef

define Package/fwknop/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libfko.so.* $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/fwknop $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/fwknopd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/fwknop
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/etc/fwknop/fwknopd.conf $(1)/etc/fwknop/
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/etc/fwknop/access.conf $(1)/etc/fwknop/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwknopd.init $(1)/etc/init.d/fwknopd
endef

$(eval $(call BuildPackage,fwknop))
