#!/bin/sh
# EpinAnonymOS WiFi/DHCP diagnostic. Captures the whole layer-2 -> IP pipeline in
# one shot so we stop guessing. Prints to the terminal AND to /run/wifi-diag.log
# (mirrored into the Logs app: SUPER+L). Read the VERDICT block at the bottom.
OUT=/run/wifi-diag.log
{
  echo "======== wifi-diag ========"

  echo "--- [1] lease marker /run/wifi/dhcp-ok (the IP, if DHCP succeeded) ---"
  if [ -e /run/wifi/dhcp-ok ]; then cat /run/wifi/dhcp-ok; LEASE=1; else echo "(absent -> NO lease)"; LEASE=0; fi

  echo "--- [2] DHCP processes (launcher vs actual udhcpc) ---"
  PS=$(ps w 2>/dev/null || ps 2>/dev/null)
  echo "$PS" | grep -iE 'udhcpc-launch|udhcpc|busybox-dyn|wpa|nm-launch' | grep -v grep || echo "(none running)"
  echo "$PS" | grep -q 'busybox-dyn' && UDHCPC=1 || UDHCPC=0
  echo "$PS" | grep -q 'udhcpc-launch' && LAUNCH=1 || LAUNCH=0

  echo "--- [3] launcher gate: /sys/class/net/wlan0 (line 42 waits on this) ---"
  ls -d /sys/class/net/wlan0 2>&1
  [ -e /sys/class/net/wlan0 ] && SYSFS=1 || SYSFS=0
  echo "operstate: $(cat /sys/class/net/wlan0/operstate 2>&1)  carrier: $(cat /sys/class/net/wlan0/carrier 2>&1)"

  echo "--- [4] wifi-menu state /run/wifi/networks (state=100 => lease landed) ---"
  head -n 8 /run/wifi/networks 2>&1

  echo "--- [5] net-provider socket /run/hos-net.sock (LKL owns wlan0) ---"
  ls -l /run/hos-net.sock 2>&1

  echo "--- [6] DHCP lines still in the klog ring (may be evicted by spam) ---"
  grep -iE 'udhcp|DISCOVER|OFFER|REQUEST|bound|renew|lease|deconfig' /run/klog 2>/dev/null | tail -n 15 || echo "(none / no /run/klog)"

  echo "======== VERDICT ========"
  if [ "$LEASE" = 1 ]; then
    echo "HAVE A LEASE -> DHCP worked. 'not connecting' is ROUTING/DNS, not DHCP."
  elif [ "$UDHCPC" = 1 ]; then
    echo "udhcpc RUNNING but NO lease -> DISCOVER->ACK not completing through the LKL."
  elif [ "$LAUNCH" = 1 ] && [ "$SYSFS" = 0 ]; then
    echo "launcher STUCK on missing /sys/class/net/wlan0 -> it never execs udhcpc (line 42 spin)."
  elif [ "$LAUNCH" = 1 ]; then
    echo "launcher alive, wlan0 sysfs present, but udhcpc not exec'd yet -> execve failing or mid-wait."
  else
    echo "NEITHER launcher NOR udhcpc running -> maybeSpawnUdhcpc gate skipped it (kernel side)."
  fi
} 2>&1 | tee "$OUT"
echo ">>> also saved to $OUT (Logs app: SUPER+L, Tab to it)"
