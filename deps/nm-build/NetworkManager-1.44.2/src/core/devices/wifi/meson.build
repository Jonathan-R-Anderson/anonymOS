# SPDX-License-Identifier: LGPL-2.1-or-later

iwd_sources = files()
if enable_iwd
  iwd_sources += files(
    'nm-device-iwd.c',
    'nm-device-iwd-p2p.c',
    'nm-iwd-manager.c',
  )
endif

libnm_device_plugin_wifi_static = static_library(
  'nm-device-plugin-wifi-static',
  sources: files(
    'nm-device-olpc-mesh.c',
    'nm-device-wifi-p2p.c',
    'nm-device-wifi.c',
    'nm-wifi-ap.c',
    'nm-wifi-common.c',
    'nm-wifi-p2p-peer.c',
    'nm-wifi-utils.c',
  ) + iwd_sources,
  dependencies: [
    core_plugin_dep,
  ],
)

libnm_device_plugin_wifi_static_dep = declare_dependency(
  link_with: libnm_device_plugin_wifi_static,
)

# EpinAnonymOS: the wifi factory as a static lib so it can be linked INTO the daemon as an
# internal factory (_ADD_INTERNAL).  Our custom ELF loader mis-links GObject type inheritance
# across the dlopen/BIND_LOCAL plugin boundary (NMDeviceWifi loses NMDevice's "interface"
# property), so the external-plugin path is unusable — link wifi in statically instead.
libnm_device_factory_wifi_internal = static_library(
  'nm-device-factory-wifi-internal',
  sources: files('nm-wifi-factory.c'),
  dependencies: [
    core_plugin_dep,
    libnm_device_plugin_wifi_static_dep,
  ],
)

libnm_device_plugin_wifi = shared_module(
  'nm-device-plugin-wifi',
  sources: files(
    'nm-wifi-factory.c',
  ),
  dependencies: [
    core_plugin_dep,
    libnm_device_plugin_wifi_static_dep
  ],
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_device_plugin_wifi

test(
  'check-local-devices-wifi',
  check_exports,
  args: [libnm_device_plugin_wifi.full_path(), linker_script_devices],
)

if enable_tests
  test_unit = 'test-devices-wifi'

  exe = executable(
    test_unit,
    'tests/' + test_unit + '.c',
    dependencies: [
      libNetworkManagerTest_dep,
      libnm_device_plugin_wifi_static_dep,
    ],
    c_args: test_c_flags,
  )

  test(
    test_unit,
    test_script,
    args: test_args + [exe.full_path()],
    timeout: default_test_timeout,
  )
endif
