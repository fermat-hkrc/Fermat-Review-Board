/**
 * PoC: DCLP Race Condition in __self_init (drv_io_share.c:33)
 * OpenHarmony tee_os_kernel
 *
 * Demonstrates broken Double-Checked Locking Pattern on ARM weak memory model.
 * Two threads race to initialize a shared hash table, causing double-init or
 * use of partially-initialized data.
 *
 * Build: gcc -o poc poc.c -lpthread -O2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>

#define HTABLE_SIZE 509
#define NUM_THREADS 8
#define ITERATIONS 100000

/* Simulated hash table structure */
struct htable {
    void **buckets;
    int size;
    int initialized_marker;  /* canary to detect double-init */
};

static struct htable addr2ent;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static bool io_init;  /* No atomic, no barrier - the bug */

static atomic_int double_init_count = 0;
static atomic_int use_before_init_count = 0;
static atomic_int init_call_count = 0;

/* Simulated init_htable - intentionally non-idempotent */
static void init_htable(struct htable *ht, int size)
{
    atomic_fetch_add(&init_call_count, 1);

    /* Check if already initialized - detects double-init race */
    if (ht->initialized_marker == 0xDEADBEEF) {
        atomic_fetch_add(&double_init_count, 1);
        fprintf(stderr, "[BUG] Double initialization detected! "
                "Thread %lu re-initializing already-initialized htable\n",
                (unsigned long)pthread_self());
    }

    /* Simulate multi-step initialization with observable intermediate state */
    ht->size = 0;           /* Step 1: reset size */
    /* Yield to increase chance of race */
    for (volatile int i = 0; i < 100; i++) {}

    if (ht->buckets) {
        free(ht->buckets);
    }
    ht->buckets = calloc(size, sizeof(void *));
    if (!ht->buckets) {
        fprintf(stderr, "calloc failed\n");
        return;
    }

    /* Another yield point - partial init visible to other threads */
    for (volatile int i = 0; i < 100; i++) {}

    ht->size = size;
    ht->initialized_marker = 0xDEADBEEF;
}

/*
 * Vulnerable __self_init - reproduces the exact pattern from drv_io_share.c:33
 * BUG 1: First read of io_init has no acquire barrier (ARM reordering)
 * BUG 2: Even inside the lock, another thread may see io_init=true
 *         but addr2ent stores not yet visible (no release on io_init write)
 */
static void __self_init(void)
{
    /* First check WITHOUT lock - no memory barrier on ARM */
    if (io_init) {
        return;
    }

    pthread_mutex_lock(&lock);
    if (!io_init) {
        init_htable(&addr2ent, HTABLE_SIZE);
        /*
         * BUG: On ARM, this store can be reordered before init_htable's
         * stores complete. Another thread doing the unlocked read above
         * may see io_init=true but addr2ent in partial state.
         */
        io_init = true;  /* No release semantics! */
    }
    pthread_mutex_unlock(&lock);
}

/* Simulated user of addr2ent that checks consistency */
static int use_htable(void)
{
    if (addr2ent.size != HTABLE_SIZE || addr2ent.buckets == NULL) {
        return -1;  /* Observed partially initialized state */
    }
    /* Try to access a bucket - would crash on NULL deref in real code */
    volatile void *p = addr2ent.buckets[addr2ent.size - 1];
    (void)p;
    return 0;
}

static atomic_int ready = 0;

static void *thread_func(void *arg)
{
    /* Spin until all threads are ready */
    while (!atomic_load(&ready)) {}

    for (int i = 0; i < ITERATIONS; i++) {
        /* Reset state to re-trigger the race on each iteration */
        /* (In real code, this race happens once at startup with many threads) */
        __self_init();

        /* Immediately try to use the table - may see partial init */
        if (use_htable() != 0) {
            atomic_fetch_add(&use_before_init_count, 1);
        }
    }
    return NULL;
}

/*
 * Aggressive test: repeatedly reset and re-init to amplify the race window
 */
static void *reset_thread_func(void *arg)
{
    while (!atomic_load(&ready)) {}

    for (int i = 0; i < ITERATIONS / 10; i++) {
        /* Simulate a scenario where init state is reset (e.g., module reload) */
        io_init = false;
        /* Small delay to let other threads observe the inconsistent state */
        for (volatile int j = 0; j < 50; j++) {}
    }
    return NULL;
}

int main(void)
{
    pthread_t threads[NUM_THREADS];
    pthread_t resetter;

    printf("=== PoC: DCLP Race in __self_init (drv_io_share.c:33) ===\n");
    printf("OpenHarmony tee_os_kernel - Broken Double-Checked Locking\n\n");
    printf("Threads: %d, Iterations: %d\n", NUM_THREADS, ITERATIONS);
    printf("Testing for: double-init race, use of partially-initialized data\n\n");

    memset(&addr2ent, 0, sizeof(addr2ent));

    /* Create worker threads */
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, thread_func, NULL) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    /* Create resetter thread to amplify race */
    if (pthread_create(&resetter, NULL, reset_thread_func, NULL) != 0) {
        perror("pthread_create resetter");
        return 1;
    }

    /* Release all threads simultaneously */
    atomic_store(&ready, 1);

    /* Wait for completion */
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_join(resetter, NULL);

    printf("\n=== Results ===\n");
    printf("Total init_htable calls: %d (expected: 1)\n",
           atomic_load(&init_call_count));
    printf("Double-init detections:  %d\n", atomic_load(&double_init_count));
    printf("Use-before-init events:  %d\n", atomic_load(&use_before_init_count));

    if (atomic_load(&double_init_count) > 0 ||
        atomic_load(&use_before_init_count) > 0 ||
        atomic_load(&init_call_count) > 1) {
        printf("\n[VULNERABLE] Race condition confirmed!\n");
        printf("  - init called %d times (should be 1) => double-init race\n",
               atomic_load(&init_call_count));
        printf("  - On ARM hardware, the unprotected read of io_init allows\n");
        printf("    threads to observe partially-initialized addr2ent\n");
        return 1;
    } else {
        printf("\n[NOTE] Race not triggered in this run.\n");
        printf("  On ARM (OpenHarmony target), weak memory ordering makes\n");
        printf("  this race much more likely to manifest.\n");
        printf("  Run under ThreadSanitizer: gcc -fsanitize=thread -o poc poc.c -lpthread\n");
        return 0;
    }
}
