#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=acd
PKG_RELEASE:=1

PKG_LICENSE:=GPLv2 GPLv2+
PKG_LICENSE_FILES:=

include $(INCLUDE_DIR)/package.mk

define Package/acd
  SECTION:=utils
  CATEGORY:=Base system
  DEPENDS:=+libubox +libblobmsg-json +libjson-c +libuci +libubus
  TITLE:=morewifi heartbeat daemon
endef

define Package/acd/description
 This package contains an daemon to heartbeat with morewifi cloud server
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/acd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/acd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/acd.init $(1)/etc/init.d/acd
	$(INSTALL_DIR) $(1)/usr/share/
	$(INSTALL_BIN) ./src/apc.sp $(1)/usr/share/
endef

$(eval $(call BuildPackage,acd))
