# Minimal CMake package config for hwdata.
# hwdata ships only a pkg-config file upstream; aquamarine's CMake does
# find_package(hwdata) and, when found, reads the pnp.ids location from the
# hwdata.pc `pkgdatadir` variable via pkg_get_variable(). This shim lets that
# (correct) code path win instead of falling back to the host /usr/share path.
set(hwdata_FOUND TRUE)
