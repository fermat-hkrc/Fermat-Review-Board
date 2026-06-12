#!/bin/bash
# Build script for CURL-2026-TIMER-002 PoC
# Requires: clang with MemorySanitizer, libcurl

set -e

echo "=== Building CURL-2026-TIMER-002 PoC ==="
echo

# Check if clang is available
if ! command -v clang &> /dev/null; then
    echo "WARNING: clang not found, falling back to gcc"
    echo "MemorySanitizer detection requires clang"
    echo

    if ! pkg-config --exists libcurl; then
        echo "ERROR: libcurl development files not found"
        echo "Install with: sudo apt-get install libcurl4-openssl-dev"
        exit 1
    fi

    CFLAGS=$(pkg-config --cflags libcurl)
    LDFLAGS=$(pkg-config --libs libcurl)

    echo "Compiling with gcc (no sanitizers)..."
    gcc -Wall -Wextra -O0 -g $CFLAGS poc.c $LDFLAGS -o poc
    echo
    echo "Build successful!"
    echo "Run: ./poc"
    echo
    echo "Note: To detect uninitialized read, rebuild with clang + MSan:"
    echo "  clang -fsanitize=memory -fsanitize-memory-track-origins \\"
    echo "        -fno-omit-frame-pointer -O1 -g poc.c -lcurl -o poc-msan"
    exit 0
fi

# Check if libcurl is available
if ! pkg-config --exists libcurl; then
    echo "ERROR: libcurl development files not found"
    echo "Install with:"
    echo "  Ubuntu/Debian: sudo apt-get install libcurl4-openssl-dev"
    echo "  RHEL/CentOS:   sudo yum install libcurl-devel"
    echo "  macOS:         brew install curl"
    exit 1
fi

CFLAGS=$(pkg-config --cflags libcurl)
LDFLAGS=$(pkg-config --libs libcurl)

echo "Compiling with MemorySanitizer..."
clang -fsanitize=memory -fsanitize-memory-track-origins \
      -fno-omit-frame-pointer -O1 -g \
      $CFLAGS poc.c $LDFLAGS -o poc-msan 2>&1 | head -20

if [ $? -ne 0 ]; then
    echo
    echo "MemorySanitizer build failed (likely libcurl not instrumented)"
    echo "Building normal version instead..."
    gcc -Wall -Wextra -O0 -g $CFLAGS poc.c $LDFLAGS -o poc
    echo
    echo "Build successful!"
    echo "Run: ./poc"
    echo
    echo "Note: Full detection requires libcurl compiled with MSan"
else
    echo
    echo "Build successful!"
    echo "Run: ./poc-msan --msan"
fi
