# PoC Report: Use-After-Free in get_proc_node (proc_node.c:246)

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Component | OpenHarmony tee_os_kernel |
| File | proc_node.c:246 |
| Function | `get_proc_node()` |
| Type | Use-After-Free (CWE-416) |
| Impact | Arbitrary code execution in TEE kernel context |
| Severity | Critical |
| Platform | All (not architecture-dependent) |

## Root Cause

`get_proc_node()` looks up a `proc_node` by badge under `proc_nodes_lock`, then releases the lock and returns the raw pointer. No reference count is taken. The caller receives a pointer to memory that can be freed by any other thread at any time (via TA exit triggering `free_proc_node_resource` + `free(proc)`).

The window between `pthread_mutex_unlock` and the caller's dereference is the UAF window. On a multi-core system, another core can complete the free before the first core's next instruction.

## Trigger Path

1. TA-A calls an IPC operation that internally calls `get_proc_node(badge_B)`.
2. `get_proc_node` finds the node, releases the lock, returns the pointer.
3. TA-B exits concurrently, triggering `free_proc_node_resource(proc)` + `free(proc)`.
4. TA-A dereferences the returned pointer -> accesses freed heap memory.
5. If attacker controls the freed slot (heap spray), they control the data TA-A reads.

## Build Environment

```
Compiler: gcc (any version)
Flags:    gcc -o poc poc.c -lpthread -O2
ASan:     gcc -fsanitize=address -o poc poc.c -lpthread -O2 (recommended)
```

## Reproduction Steps

1. Compile: `gcc -o poc poc.c -lpthread -O2`
2. Run: `./poc`
3. Observe "[UAF]" messages indicating freed memory was accessed.
4. For guaranteed detection: `gcc -fsanitize=address -o poc poc.c -lpthread && ./poc`
5. ASan will report `heap-use-after-free` with full stack traces.

## Expected Output

```
=== PoC: Use-After-Free in get_proc_node (proc_node.c:246) ===
...
[UAF] Thread 1234: accessed freed proc_node! canary=0xDEADDEAD (expected 0xCAFEBABE)
...
[VULNERABLE] Use-After-Free confirmed!
```

## Real-World Attack Scenario

1. Malicious TA-A establishes a session, obtaining a known badge value.
2. TA-A triggers code path that calls `get_proc_node(target_badge)`.
3. Collaborating TA-B (or same TA via another thread) triggers the target TA's exit.
4. TA-B sprays the heap with controlled data sized to match `sizeof(struct proc_node)`.
5. TA-A's dangling pointer now points to attacker-controlled data.
6. Depending on how the caller uses the returned `proc_node`:
   - If it reads function pointers -> code execution in TEE kernel.
   - If it reads session keys -> cryptographic material leakage.
   - If it writes to fields -> arbitrary write primitive in TEE kernel heap.

This breaks TEE isolation completely, allowing a malicious TA to compromise the secure world.

## Fix Recommendation

Add reference counting to `proc_node` and only release the reference when the caller is done:

```c
struct proc_node *get_proc_node(badge_t client_badge)
{
    struct proc_node *proc = NULL;
    struct hlist_head *buckets;

    pthread_mutex_lock(&proc_nodes_lock);
    buckets = htable_get_bucket(&badge2proc, client_badge);

    for_each_in_hlist (proc, hash_node, buckets) {
        if (client_badge == proc->badge) {
            atomic_fetch_add(&proc->refcount, 1);  /* Take reference under lock */
            pthread_mutex_unlock(&proc_nodes_lock);
            return proc;
        }
    }
    pthread_mutex_unlock(&proc_nodes_lock);
    return NULL;
}

void put_proc_node(struct proc_node *proc)
{
    if (atomic_fetch_sub(&proc->refcount, 1) == 1) {
        /* Last reference - safe to free */
        free_proc_node_resource(proc);
        free(proc);
    }
}
```
