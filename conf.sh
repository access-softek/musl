export CC=/usr/bin/clang

TARGET=aarch64-linux-gnu
export CFLAGS="-O0 --target=$TARGET -mcpu=cortex-a78c  -DMUSL_EXPERIMENTAL_PAC"
export LDFLAGS="--target=$TARGET -fuse-ld=lld"
./configure --enable-debug --host=$TARGET
