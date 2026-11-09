include $(TOPDIR)/rules.mk

PKG_NAME:=sysdiagnostic
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Tu Nombre <tu@email.com>
PKG_LICENSE:=GPL-2.0-or-later

include $(INCLUDE_DIR)/package.mk

define Package/sysdiagnostic
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=System Diagnostic Daemon for procd
  # Dependencies ensure Python 3, ubus, and uci extensions are present
  DEPENDS:=+python3-light +python3-uci +python3-ubus +python3-codecs
endef

define Package/sysdiagnostic/description
  A lightweight, kernel-poll driven system telemetry and diagnostic daemon 
  integrated with procd and remote API logging.
endef

define Build/Compile
	# Nothing to compile as this consists purely of python and shell scripts
endef

define Package/sysdiagnostic/install
	# 1. Install the executable daemon command into system binaries (0755)
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/sysdiagnostic_main.py $(1)/usr/sbin/sysdiagnostic

	# 2. Install the private utility library package (0755 directory, 0755 files)
	$(INSTALL_DIR) $(1)/usr/share/sysdiagnostic
	$(INSTALL_BIN) ./files/sysdiagnostic_collector.py $(1)/usr/share/sysdiagnostic/

	# 3. Install procd init.d monitoring service script (0755)
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/sysdiagnostic.init $(1)/etc/init.d/sysdiagnostic

	# 4. Install default UCI configuration profile structure (0644)
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/sysdiagnostic.config $(1)/etc/config/sysdiagnostic
endef

$(eval $(call BuildPackage,sysdiagnostic))

