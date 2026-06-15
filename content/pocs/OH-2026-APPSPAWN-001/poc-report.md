# PoC Report: appspawn ReadFile() TOCTOU — Sandbox Config Injection

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Component | OpenHarmony appspawn |
| File | `base/startup/appspawn/util/src/appspawn_utils.c` |
| Function | `ReadFile()` (line 238) |
| CWE | CWE-367 (Time-of-check Time-of-use Race Condition) |
| Severity | HIGH |
| Impact | Sandbox configuration injection → potential sandbox escape |

## Root Cause

`ReadFile()` performs a two-step file access without holding a file descriptor:

```c
char *ReadFile(const char *fileName) {
    struct stat fileStat;
    stat(fileName, &fileStat);          // Step 1: get file size
    // ← RACE WINDOW: file content can change here
    fd = fopen(fileName, "r");          // Step 2: open file
    buffer = malloc(fileStat.st_size + 1);
    fread(buffer, fileStat.st_size, 1, fd);  // reads stale-size bytes
}
```

Between `stat()` and `fopen()`, the file content can be replaced. If the replacement has the same size, all checks pass but the read content is attacker-controlled.

## Trigger Path (Full Call Chain)

```
ParseJsonConfig("etc/sandbox", sandboxName, ...)     [sandbox_load.c:782]
  → GetJsonObjFromFile(path)                         [appspawn_utils.c:272]
    → ReadFile(jsonPath)                             [appspawn_utils.c:275]
      → stat(fileName, &fileStat)                   ← validates size
      → fopen(fileName, "r")                        ← opens (potentially different content)
      → fread(buffer, fileStat.st_size, 1, fd)      ← reads attacker content
  → cJSON_Parse(buffer)                             ← parses as sandbox config
```

Also triggered via:
- `LoadAppSandboxConfigCJson()` → `GetJsonObjFromFile(appPath)` in sandbox_common.cpp
- `DoDlopenLibs` via `ParseJsonConfig("etc/appspawn", ...)` in ace_adapter.cpp

## Build Environment

- **OS**: Linux (any)
- **Compiler**: GCC
- **Dependencies**: pthreads
- **Build command**: `gcc -o poc poc.c -lpthread -O2`

## Reproduction Steps

1. Compile: `gcc -o poc poc.c -lpthread -O2`
2. Run: `./poc`
3. Observe race win message showing malicious JSON was read

## PoC Output

```
=== appspawn ReadFile() TOCTOU PoC ===
Target: OpenHarmony appspawn util/src/appspawn_utils.c:ReadFile()
Bug: stat() then fopen() without holding fd - content can change
Impact: Malicious sandbox config injection via content swap

[!] RACE WON at attempt 113!
[!] Expected: {"sandbox":"safe"}
[!] Got:      {"sandbox":"evil",
[!] appspawn would parse malicious JSON config!

[+] PoC SUCCESS: Demonstrated TOCTOU in ReadFile()
[+] In real scenario: attacker injects malicious sandbox config
[+] Effect: sandbox escape or mount manipulation during app spawn
```

## Real-World Attack Scenario

1. A malicious app has write access to a directory that `ParseJsonConfig` scans (via `GetCfgFiles()`)
2. The attacker continuously writes malicious sandbox config JSON (same file size as legitimate)
3. During app spawn, `ReadFile()` is called on the config file
4. If the race succeeds, appspawn loads attacker-controlled sandbox mount rules
5. The spawned app gains mounts that bypass sandbox isolation (e.g., mounting `/data` into the sandbox)

## Preconditions

- Attacker needs write access to a config directory scanned by appspawn
- In OpenHarmony, `GetCfgFiles("etc/sandbox")` returns system-level paths, but custom vendor overlay directories may be writable by privileged apps

## Fix Recommendation

Replace `stat()` + `fopen()` with atomic fd-based operations:

```c
char *ReadFile(const char *fileName) {
    int fd = open(fileName, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat fileStat;
    if (fstat(fd, &fileStat) != 0 || fileStat.st_size <= 0 || ...) {
        close(fd); return NULL;
    }
    buffer = malloc(fileStat.st_size + 1);
    read(fd, buffer, fileStat.st_size);  // same fd, no race
    close(fd);
    return buffer;
}
```
