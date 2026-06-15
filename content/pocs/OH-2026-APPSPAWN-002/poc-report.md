# PoC Report: appspawn CheckAndCreateSandboxFile() TOCTOU → Arbitrary chown

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Component | OpenHarmony appspawn |
| File | `base/startup/appspawn/modules/sandbox/modern/appspawn_sandbox.c` |
| Function | `CheckAndCreateSandboxFile()` (line 342) + `CreateDemandSrc()` (line 358) |
| CWE | CWE-367 (TOCTOU), CWE-59 (Improper Link Resolution) |
| Severity | HIGH |
| Impact | Arbitrary file ownership change → privilege escalation |

## Root Cause

`DoSandboxPathNodeMount()` calls `CheckAndCreateSandboxFile()` which creates a file, then immediately calls `CreateDemandSrc()` which calls `chown()` on the same path. `chown()` follows symlinks by default.

```c
// Step 1: CheckAndCreateSandboxFile creates the file
void CheckAndCreateSandboxFile(const char *file) {
    if (access(file, F_OK) == 0) return;  // already exists
    MakeDirRec(file, FILE_MODE, 0);
    int fd = open(file, O_CREAT, FILE_MODE);
    close(fd);   // ← file exists, fd released
}

// Step 2: CreateDemandSrc chowns it (follows symlinks!)
void CreateDemandSrc(...) {
    CheckAndCreateSandboxFile(args->originPath);
    // ← RACE WINDOW: file can be replaced with symlink here
    chown(args->originPath, uid, gid);   // follows symlinks!
    chmod(args->originPath, mode);        // also follows symlinks!
}
```

## Trigger Path (Full Call Chain)

```
AppSpawnChild()
  → SetAppSandboxProperty()
    → DoSandboxPathNodeMount(context, section, sandboxNode, operation)
      → CheckAndCreateSandboxFile(args.destinationPath)   [line 560]
      → CreateDemandSrc(context, sandboxNode, &args)      [line 568]
        → CheckAndCreateSandboxFile(args->originPath)     [line 361]
        → chown(args->originPath, uid, gid)               [line 370] ← VULN
        → chmod(args->originPath, mode)                   [line 375] ← VULN
```

The `args->originPath` is derived from sandbox config + app bundle name via `GetRealSrcPath()` which uses `<variablePackageName>` substitution.

## Build Environment

- **OS**: Linux (any)
- **Compiler**: GCC
- **Dependencies**: pthreads, inotify
- **Build command**: `gcc -o poc poc.c -lpthread -O2`

## Reproduction Steps

1. Compile: `gcc -o poc poc.c -lpthread -O2`
2. Run: `./poc`
3. Observe inotify-detected file creation and symlink replacement attempt
4. Note: Race window on fast local system is narrow. On real OpenHarmony device with IPC overhead and scheduler preemption, the window between `close(fd)` in CheckAndCreateSandboxFile and `chown()` in CreateDemandSrc is significantly wider.

## Real-World Attack Scenario

1. Malicious app A is installed and has write access to its own sandbox data directory
2. App A identifies paths that appspawn will use as `createDemand` sources for other apps
3. App A sets up an inotify watch on the parent directory of the demand path
4. When a victim app B is spawned, appspawn creates the demand file
5. App A's inotify fires; App A immediately replaces the file with a symlink to `/data/service/el1/public/deviceauth/hcgroup.dat` (or any sensitive file)
6. appspawn's `chown()` follows the symlink and changes ownership of the sensitive file to App B's uid
7. App B (controlled by attacker) can now read/write the previously protected file

## Key Insight

The `chown()` call uses the uid/gid from `sandboxNode->demandInfo` or the app's DAC info — meaning the target file's ownership gets changed to the spawned app's identity. If the attacker controls App B, they gain read/write access to any file whose ownership was changed.

## Fix Recommendation

1. Use `lchown()` instead of `chown()` to avoid following symlinks
2. Better: open with `O_NOFOLLOW | O_PATH`, then use `fchownat(fd, "", ..., AT_EMPTY_PATH)`
3. Verify the file is a regular file (not symlink) before chown:

```c
void CreateDemandSrc(...) {
    CheckAndCreateSandboxFile(args->originPath);
    struct stat st;
    if (lstat(args->originPath, &st) != 0 || !S_ISREG(st.st_mode)) {
        APPSPAWN_LOGE("demand path is not a regular file");
        return;
    }
    // Use lchown or fd-based approach
    int fd = open(args->originPath, O_PATH | O_NOFOLLOW);
    fchownat(fd, "", uid, gid, AT_EMPTY_PATH);
    close(fd);
}
```
