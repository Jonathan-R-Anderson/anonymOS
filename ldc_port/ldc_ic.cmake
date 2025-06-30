# Configure LDC to build for Internet Computer OS
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(LDC_TARGET_TRIPLE "x86_64-myic-none")
set(CMAKE_SYSROOT "${CMAKE_CURRENT_LIST_DIR}/sysroot")
set(CMAKE_C_COMPILER clang)
set(CMAKE_EXE_LINKER_FLAGS "-static -nostdlib -Wl,--script=${CMAKE_CURRENT_LIST_DIR}/ic.ld")

# Use our minimal libc
add_library(myiclibc STATIC ${CMAKE_CURRENT_LIST_DIR}/libc.c)
set_property(TARGET myiclibc PROPERTY LINKER_LANGUAGE C)

# Example usage:
# add_executable(hello hello.d)
# target_link_libraries(hello PRIVATE myiclibc)
