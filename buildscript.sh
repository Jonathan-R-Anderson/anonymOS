export TARGET=x86_64-unknown-elf
export SYSROOT=$HOME/sysroots/$TARGET

cmake -S llvm-project/compiler-rt/builtins -B build-builtins -G Ninja \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_ASM_COMPILER=clang \
  -DCMAKE_AR=llvm-ar \
  -DCMAKE_RANLIB=llvm-ranlib \
  -DCMAKE_C_COMPILER_TARGET=$TARGET \
  -DCMAKE_ASM_COMPILER_TARGET=$TARGET \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCOMPILER_RT_BAREMETAL_BUILD=ON \
  -DCOMPILER_RT_BUILD_BUILTINS=ON \
  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
  -DCMAKE_INSTALL_PREFIX=$SYSROOT/usr

ninja -C build-builtins
ninja -C build-builtins install
