#!/bin/bash
# Build script for fs_work_agent.c TOCTOU PoC (target-compile)
#
# Usage: ./build.sh <tee_client_source_path>
# Example: ./build.sh ~/data/test-repos/tee_client

set -e
TARGET="${1:?Usage: $0 <tee_client_source_path>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TMPDIR=$(mktemp -d /tmp/fermat_fswork_XXXXXX)
trap "rm -rf $TMPDIR" EXIT

echo "[*] Creating stubs for teecd dependencies..."

# Stub: securec.h
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
#define strncpy_s(dst, dsz, src, cnt) strncpy(dst, src, cnt)
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

# Stub: tee_file.h
cat > "$TMPDIR/tee_file.h" << 'EOF'
#ifndef TEE_FILE_H
#define TEE_FILE_H
#include <fcntl.h>
#include <unistd.h>
static inline int32_t tee_open(const char *path, int flags, unsigned int mode) {
    return open(path, flags, mode);
}
static inline void tee_close(int32_t *fd) {
    if (fd && *fd >= 0) { close(*fd); *fd = -1; }
}
#endif
EOF

# Stub: fs_work_agent.h
cat > "$TMPDIR/fs_work_agent.h" << 'EOF'
#ifndef FS_WORK_AGENT_H
#define FS_WORK_AGENT_H
#include <stdint.h>
#include <sys/types.h>
#define FILE_NAME_MAX_BUF 256
#endif
EOF

# Stub: tc_ns_client.h
cat > "$TMPDIR/tc_ns_client.h" << 'EOF'
#ifndef TC_NS_CLIENT_H
#define TC_NS_CLIENT_H
#endif
EOF

# Stub: tee_agent.h
cat > "$TMPDIR/tee_agent.h" << 'EOF'
#ifndef TEE_AGENT_H
#define TEE_AGENT_H
#endif
EOF

# Extract only the vulnerable function (UnlinkRecursive + UnlinkRecursiveDir)
# to avoid compiling the entire fs_work_agent.c with all its dependencies
echo "[*] Extracting vulnerable functions from fs_work_agent.c ..."
cat > "$TMPDIR/unlink_recursive.c" << 'EOF'
/* Extracted from fs_work_agent.c — the vulnerable code path */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include "securec.h"
#include "tee_log.h"

#define FILE_NAME_MAX_BUF 256

static int32_t UnlinkRecursiveDir(const char *name)
{
    DIR *dir;
    struct dirent *de;
    char entryName[FILE_NAME_MAX_BUF] = { 0 };

    dir = opendir(name);
    if (dir == NULL) {
        tloge("opendir failed, errno is %d\n", errno);
        return -1;
    }

    de = readdir(dir);
    while (de != NULL) {
        if (strcmp(de->d_name, "..") == 0 || strcmp(de->d_name, ".") == 0) {
            de = readdir(dir);
            continue;
        }
        int ret = snprintf_s(entryName, FILE_NAME_MAX_BUF, FILE_NAME_MAX_BUF - 1,
                            "%s/%s", name, de->d_name);
        if (ret < 0) {
            closedir(dir);
            return -1;
        }
        /* Recursive call — this is also vulnerable to symlink races */
        extern int32_t UnlinkRecursive(const char *name);
        if (UnlinkRecursive(entryName) < 0) {
            closedir(dir);
            return -1;
        }
        de = readdir(dir);
    }

    if (closedir(dir) < 0) {
        tloge("closedir failed, errno is %d\n", errno);
        return -1;
    }

    if (rmdir(name) < 0) {
        tloge("rmdir failed, errno is %d\n", errno);
        return -1;
    }
    return 0;
}

/* THE VULNERABLE FUNCTION — lstat then unlink without fd-relative protection */
int32_t UnlinkRecursive(const char *name)
{
    struct stat st;

    /* CHECK: is it a file or directory? */
    if (lstat(name, &st) < 0) {
        tloge("lstat failed, errno is %x\n", errno);
        return -1;
    }

    /* USE: unlink based on stale lstat result — no symlink protection */
    if (!S_ISDIR(st.st_mode)) {
        if (unlink(name) < 0) {
            tloge("unlink failed, errno is %d\n", errno);
            return -1;
        }
        return 0;
    }

    return UnlinkRecursiveDir(name);
}
EOF

echo "[*] Compiling extracted vulnerable code ..."
clang -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$TMPDIR" \
    "$TMPDIR/unlink_recursive.c" \
    -o "$TMPDIR/unlink_recursive.o"

echo "[*] Compiling PoC driver ..."
clang -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$TMPDIR" \
    "$SCRIPT_DIR/poc.c" \
    -o "$TMPDIR/poc.o"

echo "[*] Linking ..."
clang -O0 -fsanitize=address -fno-omit-frame-pointer \
    -o "$TMPDIR/poc_bin" \
    "$TMPDIR/unlink_recursive.o" \
    "$TMPDIR/poc.o" \
    -lpthread

echo "[*] Running PoC ..."
"$TMPDIR/poc_bin"
RET=$?
echo "[*] Exit code: $RET"
exit $RET
