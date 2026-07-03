#!/bin/bash
# M2: configure + build NetworkManager 1.44.2 for the EpinAnonymOS musl target.
# crypto=null (no gnutls/nss), NM's own netlink (no libnl), internal DHCP, keyfile settings.
# Everything not needed for WPA2-PSK WiFi + nmcli is disabled to shrink the build surface.
set -e
ROOT=/home/bruns/Documents/EpinAnonymOS
MUSL=$ROOT/deps/musl/install
SYSROOT=$ROOT/deps/gtk-stack/sysroot
CROSS=$ROOT/deps/gtk-stack/stamps/meson-cross.ini
NM=$ROOT/deps/nm-build/NetworkManager-1.44.2

export PKG_CONFIG_LIBDIR="$SYSROOT/lib/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$SYSROOT"
export PATH="$ROOT/deps/.host-tools/bin:$PATH"   # project-local meson/ninja

cd "$NM"
rm -rf build-epin

meson setup build-epin \
  --cross-file "$CROSS" \
  --prefix=/usr \
  --sysconfdir=/etc \
  --localstatedir=/var \
  -Dcrypto=null \
  -Dsession_tracking=no \
  -Dsession_tracking_consolekit=false \
  -Dsuspend_resume=upower \
  -Dpolkit=false \
  -Dselinux=false \
  -Dsystemd_journal=false \
  -Dsystemdsystemunitdir=no \
  -Dlibaudit=no \
  -Dwext=true \
  -Dwifi=true \
  -Diwd=false \
  -Dppp=false \
  -Dmodem_manager=false \
  -Dofono=false \
  -Dconcheck=false \
  -Dteamdctl=false \
  -Dovs=false \
  -Dnmcli=true \
  -Dnmtui=false \
  -Dnm_cloud_setup=false \
  -Dbluez5_dun=false \
  -Debpf=false \
  -Difcfg_rh=false \
  -Difupdown=false \
  -Dintrospection=false \
  -Dvapi=false \
  -Ddocs=false \
  -Dtests=no \
  -Dfirewalld_zone=false \
  -Dlibpsl=false \
  -Dqt=false \
  -Dreadline=libreadline \
  -Dconfig_dhcp_default=internal \
  -Dconfig_wifi_backend_default=wpa_supplicant \
  2>&1 | tail -40
