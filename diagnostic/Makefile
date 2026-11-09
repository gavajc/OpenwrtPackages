include $(TOPDIR)/rules.mk

PKG_NAME:=diagnostic
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_BUILD_DEPENDS:=boost

# --- Git Remote Repository Integration ---
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/gavajc/diagnostic.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=System Diagnostic Telemetry Daemon (C++)
  DEPENDS:=+libuci +libubox +libatomic +libstdcpp +libpthread +libopenssl
  MAINTAINER:=Juan Carlos García <gavajc@gmail.com>
endef

define Package/$(PKG_NAME)/description
  Highly optimized C++17 system diagnostic daemon driven by remote Git.
endef

# OpenWrt automatically clones Git and runs your repository's Makefile
define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/diagnostic $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/diagnostic.init $(1)/etc/init.d/diagnostic
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/diagnostic.config $(1)/etc/config/diagnostic
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
