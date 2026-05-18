#!/bin/bash
# Build script for OH-2026-IPC-006 Target-Compile PoC
# Compiles real sensor_agent_proxy.c from source, links test driver
set -e

SRC=~/data/test-repos/sensors_sensor_lite
OHOS=~/data/openharmony-data/repos
SEC=$OHOS/device_soc_hisilicon/ws63v100/sdk/open_source/libboundscheck
STUBS=~/data/ohos-build-toolkit/stubs

INCLUDES="-I $SRC/frameworks/include \
  -I $SRC/interfaces/kits/native/include \
  -I $SRC/services/include \
  -I $OHOS/systemabilitymgr_samgr_lite/interfaces/kits/samgr \
  -I $OHOS/systemabilitymgr_samgr_lite/interfaces/kits/registry \
  -I $OHOS/communication_ipc/interfaces/innerkits/c/ipc/include \
  -I $OHOS/commonlibrary_utils_lite/include \
  -I $OHOS/hiviewdfx_hilog_lite/interfaces/native/innerkits/hilog \
  -I $SEC/include"

FLAGS="-fsanitize=address -fno-omit-frame-pointer -O0 -g"

# 1. Compile real sensor_agent_proxy.c (with -Dstatic= to expose globals for test)
gcc -c $FLAGS -Dstatic= $INCLUDES $SRC/frameworks/src/sensor_agent_proxy.c -o /tmp/sensor_agent_proxy.o

# 2. Compile stubs
gcc -c $FLAGS $INCLUDES $STUBS/ohos_stubs.c -o /tmp/ohos_stubs.o
gcc -c $FLAGS $INCLUDES sensor_extra_stubs.c -o /tmp/sensor_extra_stubs.o

# 3. Compile securec
gcc -c -O0 -g -I $SEC/include $SEC/src/memcpy_s.c -o /tmp/memcpy_s.o
gcc -c -O0 -g -I $SEC/include $SEC/src/securecutil.c -o /tmp/securecutil.o

# 4. Compile test driver
gcc -c $FLAGS $INCLUDES poc.c -o /tmp/test_ipc006.o

# 5. Link
gcc -fsanitize=address -o /tmp/poc_ipc006 \
  /tmp/test_ipc006.o /tmp/sensor_agent_proxy.o /tmp/ohos_stubs.o /tmp/sensor_extra_stubs.o \
  /tmp/memcpy_s.o /tmp/securecutil.o -lpthread

echo "Build complete. Run: /tmp/poc_ipc006"
