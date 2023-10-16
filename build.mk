PKGCONF = pkg-config

CD := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CFLAGS += -O3 -pipe -g -rdynamic
CFLAGS += -Werror -Wextra -Wall

#############################
DPDK_VER=23.07
DPDK_DIR = $(CD)/dpdk
DPDK_SRC_DIR = $(DPDK_DIR)/dpdk-$(DPDK_VER)
DPDK_INSTALL_DIR = $(DPDK_DIR)/install
DPDK_PKG_CONFIG_PATH=$(DPDK_INSTALL_DIR)/lib/x86_64-linux-gnu/pkgconfig
DPDK_PKG_CONFIG_FILE=$(DPDK_PKG_CONFIG_PATH)/libdpdk.pc
CFLAGS += $(shell PKG_CONFIG_PATH=$(DPDK_PKG_CONFIG_PATH) $(PKGCONF) --cflags libdpdk)
LDFLAGS += $(shell PKG_CONFIG_PATH=$(DPDK_PKG_CONFIG_PATH) $(PKGCONF) --libs libdpdk)
#############################

IOSUB_DEP = $(DPDK_PKG_CONFIG_FILE)

$(DPDK_SRC_DIR).tar.xz:
	wget -P $(DPDK_DIR) https://fast.dpdk.org/rel/dpdk-$(DPDK_VER).tar.xz

$(DPDK_SRC_DIR): $(DPDK_SRC_DIR).tar.xz
	tar xvf $< -C $(DPDK_DIR)

$(DPDK_PKG_CONFIG_FILE): $(DPDK_SRC_DIR)
	meson --prefix=$(DPDK_INSTALL_DIR) --libdir=lib/x86_64-linux-gnu $(DPDK_SRC_DIR)/build $(DPDK_SRC_DIR)
	ninja -C $(DPDK_SRC_DIR)/build
	ninja -C $(DPDK_SRC_DIR)/build install
