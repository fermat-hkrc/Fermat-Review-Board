#include <stdint.h>
#include <stdio.h>

/* Permission table that the real implementation indexes into */
#define MAX_UID_COUNT 64
static int32_t g_perm_table[MAX_UID_COUNT] = {0};

int32_t CheckPermissionStat(int64_t uid, const char *permName) {
    printf("[Stub] CheckPermissionStat: uid=%lld\n", (long long)uid);
    if (uid < 0 || uid >= MAX_UID_COUNT) {
        printf("[TRIGGER] OOB READ at g_perm_table[%lld]\n", (long long)uid);
        return g_perm_table[uid]; /* OOB */
    }
    return g_perm_table[uid];
}

int32_t GrantPermission(const char *id, const char *permName) {
    printf("[Stub] GrantPermission: id=%s\n", id ? id : "(null)");
    return 0;
}

int32_t RevokePermission(const char *id, const char *permName) {
    printf("[Stub] RevokePermission: id=%s\n", id ? id : "(null)");
    return 0;
}

int32_t GrantRuntimePermission(int64_t uid, const char *permName) {
    printf("[Stub] GrantRuntimePermission: uid=%lld\n", (long long)uid);
    if (uid < 0 || uid >= MAX_UID_COUNT) {
        printf("[TRIGGER] OOB WRITE at g_perm_table[%lld]\n", (long long)uid);
        g_perm_table[uid] = 1; /* OOB */
    }
    return 0;
}

int32_t RevokeRuntimePermission(int64_t uid, const char *permName) {
    printf("[Stub] RevokeRuntimePermission: uid=%lld\n", (long long)uid);
    if (uid < 0 || uid >= MAX_UID_COUNT) {
        printf("[TRIGGER] OOB WRITE at g_perm_table[%lld]\n", (long long)uid);
        g_perm_table[uid] = 0; /* OOB WRITE — the vulnerability */
    }
    return 0;
}

int32_t UpdatePermissionFlags(const char *id, const char *permName, int flags) {
    printf("[Stub] UpdatePermissionFlags: id=%s\n", id ? id : "(null)");
    return 0;
}

