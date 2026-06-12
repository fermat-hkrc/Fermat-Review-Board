#!/bin/bash
# Build script for CURL-2026-TIMER-001 PoC
# Requires: libcurl development files

set -e

echo "=== Building CURL-2026-TIMER-001 PoC ==="
echo

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

echo "Compiling poc.c..."
gcc -Wall -Wextra -O0 -g $CFLAGS poc.c $LDFLAGS -o poc

echo
echo "Build successful!"
echo "Run: ./poc"
