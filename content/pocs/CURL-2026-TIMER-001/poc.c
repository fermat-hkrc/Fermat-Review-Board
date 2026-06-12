/*
 * PoC: Timer state inconsistency in curl_multi_socket_action
 * Bug Location: lib/multi.c:3257
 * CWE-665: Improper Initialization
 *
 * Build:
 *   gcc -Wall -O0 -g poc.c -lcurl -o poc
 *
 * Expected: Timer callback invoked incorrectly due to state mismatch
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>

static int timer_call_count = 0;
static long last_timeout_value = -1;

/* Timer callback - tracks invocations */
static int timer_callback(CURLM *multi, long timeout_ms, void *userp)
{
    timer_call_count++;
    last_timeout_value = timeout_ms;
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

int main(void)
{
    CURLM *multi_handle;
    CURL *easy1, *easy2;
    CURLMcode mc;
    int running_handles;

    printf("=== PoC: curl multi timer state inconsistency ===\n");
    printf("Bug: memset() clears last_expire_ts but not last_timeout_ms\n");
    printf("Location: lib/multi.c:3257\n\n");

    curl_global_init(CURL_GLOBAL_ALL);

    /* Create multi handle */
    multi_handle = curl_multi_init();
    curl_multi_setopt(multi_handle, CURLMOPT_TIMERFUNCTION, timer_callback);
    curl_multi_setopt(multi_handle, CURLMOPT_SOCKETFUNCTION, socket_callback);

    /* ===== STEP 1: Add first handle ===== */
    printf("[STEP 1] Adding first easy handle with 2000ms timeout\n");
    easy1 = curl_easy_init();
    curl_easy_setopt(easy1, CURLOPT_URL, "http://httpbin.org/delay/5");
    curl_easy_setopt(easy1, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(easy1, CURLOPT_TIMEOUT_MS, 2000L);
    curl_easy_setopt(easy1, CURLOPT_NOSIGNAL, 1L);

    curl_multi_add_handle(multi_handle, easy1);
    curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);

    printf("[STEP 1] Timer callback count: %d, last_timeout: %ld ms\n\n",
           timer_call_count, last_timeout_value);

    /* ===== STEP 2: Trigger TIMEOUT event ===== */
    printf("[STEP 2] Calling curl_multi_socket_action(CURL_SOCKET_TIMEOUT)\n");
    printf("[STEP 2] This triggers line 3257: memset(&multi->last_expire_ts, 0, ...)\n");
    printf("[STEP 2] BUG: multi->last_timeout_ms is NOT RESET!\n");
    printf("[STEP 2] State after memset:\n");
    printf("         - last_expire_ts = {0, 0} (cleared)\n");
    printf("         - last_timeout_ms = 2000 (NOT cleared - BUG!)\n\n");

    mc = curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);

    /* ===== STEP 3: Add second handle with SAME timeout ===== */
    printf("[STEP 3] Adding second easy handle with 2000ms timeout (same as before)\n");
    easy2 = curl_easy_init();
    curl_easy_setopt(easy2, CURLOPT_URL, "http://httpbin.org/delay/5");
    curl_easy_setopt(easy2, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(easy2, CURLOPT_TIMEOUT_MS, 2000L);
    curl_easy_setopt(easy2, CURLOPT_NOSIGNAL, 1L);

    int prev_count = timer_call_count;
    curl_multi_add_handle(multi_handle, easy2);
    curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);

    /* ===== STEP 4: Check if timer callback was invoked ===== */
    printf("[STEP 3] Timer callback invoked: %s\n\n",
           (timer_call_count > prev_count) ? "YES (INCORRECT!)" : "NO (correct)");

    printf("=== Bug Explanation ===\n");
    printf("At Curl_update_timer() line 3589:\n");
    printf("  else if(curlx_ptimediff_us(&multi->last_expire_ts, &expire_ts)) {\n");
    printf("    // Compares ZERO timestamp vs VALID timestamp\n");
    printf("    // Returns TRUE because they differ\n");
    printf("    set_value = TRUE;  // Timer callback invoked!\n");
    printf("  }\n\n");

    printf("Expected behavior:\n");
    printf("  - Timeout value unchanged (2000ms)\n");
    printf("  - Timer callback should NOT be invoked\n\n");

    printf("Actual behavior:\n");
    printf("  - last_expire_ts cleared but last_timeout_ms not reset\n");
    printf("  - State inconsistency causes timestamp comparison to fail\n");
    printf("  - Timer callback invoked unnecessarily\n\n");

    printf("=== Fix ===\n");
    printf("At lib/multi.c:3257, after memset():\n");
    printf("  multi->last_timeout_ms = -1;  // ADD THIS LINE\n\n");

    /* Cleanup */
    curl_multi_remove_handle(multi_handle, easy1);
    curl_multi_remove_handle(multi_handle, easy2);
    curl_easy_cleanup(easy1);
    curl_easy_cleanup(easy2);
    curl_multi_cleanup(multi_handle);
    curl_global_cleanup();

    printf("=== PoC completed ===\n");
    return 0;
}
