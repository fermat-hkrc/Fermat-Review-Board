#!/bin/bash
# Build script for tarzip.c TOCTOU PoC (target-compile)
#
# Usage: ./build.sh <tee_client_source_path>
# Example: ./build.sh ~/data/test-repos/tee_client

set -e
TARGET="${1:?Usage: $0 <tee_client_source_path>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TMPDIR=$(mktemp -d /tmp/fermat_tarzip_XXXXXX)
trap "rm -rf $TMPDIR" EXIT

echo "[*] Creating stubs for tee_client dependencies..."

# Stub: securec.h (snprintf_s, memset_s)
cat > "$TMPDIR/securec.h" << 'EOF'
#ifndef SECUREC_H
#define SECUREC_H
#include <string.h>
#include <stdio.h>
typedef int errno_t;
static inline errno_t memset_s(void *d, size_t ds, int c, size_t n) {
    if (!d || n > ds) return 1;
    memset(d, c, n); return 0;
}
#define snprintf_s(buf, bufsz, count, fmt, ...) snprintf(buf, bufsz, fmt, ##__VA_ARGS__)
#endif
EOF

# Stub: tee_log.h
cat > "$TMPDIR/tee_log.h" << 'EOF'
#ifndef TEE_LOG_H
#define TEE_LOG_H
#include <stdio.h>
#define PUBLIC "s"
#define tloge(fmt, ...) fprintf(stderr, "[E] " fmt, ##__VA_ARGS__)
#define tlogw(fmt, ...) fprintf(stderr, "[W] " fmt, ##__VA_ARGS__)
#define tlogd(fmt, ...) do {} while(0)
#endif
EOF

# Stub: tlogcat.h
cat > "$TMPDIR/tlogcat.h" << 'EOF'
#ifndef TLOGCAT_H
#define TLOGCAT_H
#define LOG_FILE_INDEX_MAX 3
#endif
EOF

# Stub: tarzip.h
cat > "$TMPDIR/tarzip.h" << 'EOF'
#ifndef TARZIP_H
#define TARZIP_H
#include <stdint.h>
#include <sys/types.h>
void TarZipFiles(uint32_t nameCount, const char **inputNames,
                 const char *outputName, gid_t pathGroup);
#endif
EOF

# Stub: tee_file.h — the VULNERABLE function (open without O_NOFOLLOW)
# Instrumented to detect when symlink is followed
cat > "$TMPDIR/tee_file.h" << 'EOF'
#ifndef TEE_FILE_H
#define TEE_FILE_H
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>

/* Global flag set by instrumented tee_open when race is detected */
extern volatile int g_tee_open_race_detected;
extern const char *g_expected_target_path;

/* This is the real tee_open implementation: plain open() without O_NOFOLLOW.
 * Instrumented to detect when the opened file differs from what lstat saw. */
static inline int32_t tee_open(const char *path, int flags, unsigned int mode) {
    struct stat lst, fst;
    /* Snapshot before open: what does lstat see NOW? */
    int have_lstat = (lstat(path, &lst) == 0);

    int fd = open(path, flags, mode);

    /* After open: compare what we got vs what lstat last saw */
    if (fd >= 0 && have_lstat && g_expected_target_path) {
        if (fstat(fd, &fst) == 0) {
            struct stat target_st;
            if (stat(g_expected_target_path, &target_st) == 0) {
                if (fst.st_ino == target_st.st_ino && fst.st_dev == target_st.st_dev) {
                    /* We opened the TARGET file, not the bait! Race won! */
                    g_tee_open_race_detected = 1;
                    fprintf(stderr, "[+] tee_open FOLLOWED SYMLINK to target!\n");
                }
            }
        }
    }
    return fd;
}
static inline void tee_close(int32_t *fd) {
    if (fd && *fd >= 0) { close(*fd); *fd = -1; }
}
#endif
EOF

echo "[*] Locating tarzip.c in $TARGET ..."
TARZIP_SRC="$TARGET/services/tlogcat/src/tarzip.c"
if [ ! -f "$TARZIP_SRC" ]; then
    # Flat layout (source extracted directly)
    TARZIP_SRC="$TARGET/tarzip.c"
fi
if [ ! -f "$TARZIP_SRC" ]; then
    echo "[!] Cannot find tarzip.c in $TARGET"
    exit 1
fi

echo "[*] Compiling real tarzip.c from $TARZIP_SRC ..."
clang -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$TMPDIR" \
    "$TARZIP_SRC" \
    -o "$TMPDIR/tarzip.o"

echo "[*] Compiling PoC driver ..."
clang -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$TMPDIR" \
    "$SCRIPT_DIR/poc.c" \
    -o "$TMPDIR/poc.o"

echo "[*] Linking ..."
clang -O0 -fsanitize=address -fno-omit-frame-pointer \
    -o "$TMPDIR/poc_bin" \
    "$TMPDIR/tarzip.o" \
    "$TMPDIR/poc.o" \
    -lz -lpthread

echo "[*] Running PoC ..."
"$TMPDIR/poc_bin"
RET=$?
echo "[*] Exit code: $RET"
exit $RET
