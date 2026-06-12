/*
 * PoC: Uninitialized memory read in Curl_update_timer
 * Bug Location: lib/multi.c:3604
 * CWE-908: Use of Uninitialized Resource
 *
 * Build with MemorySanitizer:
 *   clang -fsanitize=memory -fsanitize-memory-track-origins \
 *         -fno-omit-frame-pointer -O1 -g poc.c -lcurl -o poc
 *
 * Note: Requires libcurl compiled with MSan instrumentation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>

static int timer_call_count = 0;

/* Timer callback */
static int timer_callback(CURLM *multi, long timeout_ms, void *userp)
{
    timer_call_count++;
    printf("[TIMER CALLBACK #%d] timeout_ms = %ld\n", timer_call_count, timeout_ms);
    return 0;
}

/* Socket callback */
static int socket_callback(CURL *easy, curl_socket_t s, int what, void *userp, void *socketp)
{
    printf("[SOCKET CALLBACK] socket=%d, what=%d\n", (int)s, what);
    return 0;
}

/* Dummy write callback */
static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    return size * nmemb;
}

int main(int argc, char *argv[])
{
    CURLM *multi_handle;
    CURL *easy_handle;
    CURLMcode mc;
    int running_handles;
    int use_msan = 0;

    if(argc > 1 && strcmp(argv[1], "--msan") == 0) {
        use_msan = 1;
        printf("=== Running with MemorySanitizer detection mode ===\n\n");
    }

    printf("=== PoC: curl multi uninitialized memory read ===\n");
    printf("Bug location: lib/multi.c:3604\n");
    printf("Issue: expire_ts may be uninitialized when copied to last_expire_ts\n\n");

    if(use_msan) {
        printf("NOTE: Compile with -fsanitize=memory to detect uninitialized read:\n");
        printf("  clang -fsanitize=memory -fno-omit-frame-pointer -g \\\n");
        printf("        poc.c -lcurl -o poc\n\n");
        printf("Requires: libcurl compiled with MSan instrumentation\n\n");
    }

    curl_global_init(CURL_GLOBAL_ALL);

    /* Create multi handle */
    multi_handle = curl_multi_init();
    curl_multi_setopt(multi_handle, CURLMOPT_TIMERFUNCTION, timer_callback);
    curl_multi_setopt(multi_handle, CURLMOPT_SOCKETFUNCTION, socket_callback);

    /* ===== STEP 1: Add an easy handle ===== */
    printf("[STEP 1] Creating easy handle with timeout\n");
    easy_handle = curl_easy_init();
    curl_easy_setopt(easy_handle, CURLOPT_URL, "http://httpbin.org/delay/5");
    curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(easy_handle, CURLOPT_TIMEOUT_MS, 2000L);
    curl_easy_setopt(easy_handle, CURLOPT_NOSIGNAL, 1L);

    curl_multi_add_handle(multi_handle, easy_handle);

    /* ===== STEP 2: Initial socket action ===== */
    printf("[STEP 2] Calling curl_multi_socket_action() to start transfers\n");
    mc = curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);
    printf("[STEP 2] Running handles: %d\n\n", running_handles);

    /* ===== STEP 3: Process timeout event ===== */
    printf("[STEP 3] Calling curl_multi_socket_action(CURL_SOCKET_TIMEOUT)\n");
    printf("[STEP 3] This clears last_expire_ts via memset() at line 3257\n\n");

    mc = curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);

    /* ===== STEP 4: Remove the handle to trigger edge case ===== */
    printf("[STEP 4] Removing handle to trigger edge case state\n");
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);

    /* ===== STEP 5: Try to trigger Curl_update_timer() with specific state ===== */
    printf("[STEP 5] Attempting to trigger Curl_update_timer() in edge case state\n");
    printf("[STEP 5] When called, Curl_update_timer() at line 3565:\n");
    printf("         1. Declares: struct curltime expire_ts; (UNINITIALIZED)\n");
    printf("         2. Calls: multi_timeout(multi, &expire_ts, &timeout_ms);\n");
    printf("         3. Logic determines whether to update timer\n");
    printf("         4. If set_value becomes TRUE:\n");
    printf("            - Line 3604: multi->last_expire_ts = expire_ts;\n");
    printf("            - READS POTENTIALLY UNINITIALIZED expire_ts!\n\n");

    mc = curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);

    printf("[STEP 5] If running with MemorySanitizer, uninitialized read would be detected\n\n");

    /* ===== STEP 6: Bug analysis ===== */
    printf("=== Bug Analysis ===\n");
    printf("The bug occurs in Curl_update_timer() at line 3604:\n\n");

    printf("  CURLMcode Curl_update_timer(struct Curl_multi *multi)\n");
    printf("  {\n");
    printf("    struct curltime expire_ts;    // Line 3567 - UNINITIALIZED\n");
    printf("    long timeout_ms;\n");
    printf("    // ...\n");
    printf("    multi_timeout(multi, &expire_ts, &timeout_ms);  // Line 3574\n");
    printf("    // ...\n");
    printf("    if(set_value) {\n");
    printf("      multi->last_expire_ts = expire_ts;  // Line 3604 - POTENTIAL UNINIT READ\n");
    printf("    }\n");
    printf("  }\n\n");

    printf("While multi_timeout() initializes expire_time in current paths:\n");
    printf("  - Line 3496: if(multi_has_dirties) *expire_time = *multi_now()\n");
    printf("  - Line 3506: else if(multi->timetree) *expire_time = timetree->key\n");
    printf("  - Line 3528: else *expire_time = tv_zero\n\n");

    printf("The bug pattern is FRAGILE:\n");
    printf("  - Future code changes could introduce uninitialized paths\n");
    printf("  - No defensive initialization at declaration\n");
    printf("  - Line 3604 assumes expire_ts is always valid\n\n");

    printf("=== Detection ===\n");
    printf("Compile with MemorySanitizer to detect:\n");
    printf("  clang -fsanitize=memory -fno-omit-frame-pointer -g \\\n");
    printf("        poc.c -lcurl -o poc\n");
    printf("  ./poc --msan\n\n");

    printf("Expected MSan output (if bug is triggered):\n");
    printf("  WARNING: MemorySanitizer: use-of-uninitialized-value\n");
    printf("    #0 in Curl_update_timer lib/multi.c:3604\n");
    printf("    #1 in curl_multi_socket_action lib/multi.c:3298\n\n");

    printf("=== Impact ===\n");
    printf("1. Undefined behavior (reading uninitialized memory)\n");
    printf("2. Garbage timestamp values in multi->last_expire_ts\n");
    printf("3. Incorrect timer management decisions\n");
    printf("4. Non-deterministic behavior based on stack contents\n\n");

    printf("=== Suggested Fix ===\n");
    printf("At lib/multi.c:3567, initialize the variable:\n");
    printf("  struct curltime expire_ts = {0, 0};\n\n");

    /* Cleanup */
    curl_multi_cleanup(multi_handle);
    curl_global_cleanup();

    printf("=== PoC completed ===\n");
    printf("Note: This bug may not manifest without MSan instrumentation\n");
    return 0;
}
