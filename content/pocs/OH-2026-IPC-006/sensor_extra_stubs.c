/*
 * Supplementary IPC stubs for sensors_sensor_lite.
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "serializer.h"
#include "samgr_lite.h"
#include "sensor_agent_type.h"

bool ReadUint32(IpcIo *io, uint32_t *value) {
    if (io == NULL || io->bufferCur == NULL || io->bufferLeft < sizeof(uint32_t)) {
        if (value) *value = 0;
        return false;
    }
    memcpy(value, io->bufferCur, sizeof(uint32_t));
    io->bufferCur = (char *)io->bufferCur + sizeof(uint32_t);
    io->bufferLeft -= sizeof(uint32_t);
    return true;
}

const uint8_t *ReadBuffer(IpcIo *io, size_t len) {
    if (io == NULL || io->bufferCur == NULL || len == 0 || io->bufferLeft < len) {
        return NULL;
    }
    const uint8_t *ptr = (const uint8_t *)io->bufferCur;
    io->bufferCur = (char *)io->bufferCur + len;
    io->bufferLeft -= len;
    return ptr;
}

bool WriteRemoteObject(IpcIo *io, const SvcIdentity *svc) {
    (void)io;
    (void)svc;
    return true;
}

/*
 * sensor_agent_proxy.c has `static SensorEvent *g_sensorEvent;`
 * We can't access it directly. Instead, provide a constructor that
 * calls RegisterSensorChannel's allocation logic indirectly.
 *
 * Workaround: The real code at line 287 does:
 *   g_sensorEvent = (SensorEvent *)malloc(sizeof(SensorEvent));
 * We'll use a different approach — provide a test-only init function
 * that the test driver calls BEFORE SensorChannelCallback.
 *
 * Since g_sensorEvent is static, we use the fact that
 * SensorChannelCallback at line 242 dereferences it. If we can't
 * init it through the normal path, we accept the NULL deref as
 * a SEPARATE vulnerability (CWE-476) and focus on DispatchData.
 *
 * ALTERNATIVE: Compile sensor_agent_proxy.c with -Dstatic= to
 * remove the static qualifier, making g_sensorEvent accessible.
 */
