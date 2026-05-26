---
id: PBT-OH-2026-DRIVERS-002
date: "2026-05-19"
repo: sensors_sensor_lite
repo_url: https://gitcode.com/openharmony/sensors_sensor_lite
title: "SetModeImpl accepts any int32_t mode value — missing range validation for SensorMode enum"
cwe: CWE-20
cwe_name: Improper Input Validation
severity: MEDIUM
status: SUBMITTED
language: C
issue_url: https://gitcode.com/openharmony/sensors_sensor_lite/issues/32
affected_version: "*"
component: sensor_service
file_paths:
  - services/src/sensor_service_impl.c
  - interfaces/kits/native/include/sensor_agent_type.h
author: Toan
---

## Summary

`SetModeImpl` in `services/src/sensor_service_impl.c:279-289` validates `sensorId` but completely ignores the `mode` parameter. Any `int32_t` value — including negative numbers and values far exceeding the defined `SensorMode` enum range — is silently accepted and returns `SENSOR_OK`. Invalid modes propagate through the full call chain to the hardware driver unchecked.

## Vulnerable Code

```c
// services/src/sensor_service_impl.c lines 279–289
int32_t SetModeImpl(int32_t sensorId, const SensorUser *user, int32_t mode)
{
    HILOG_DEBUG(HILOG_MODULE_APP, "[SERVICE:%s]: %s begin",
        SENSOR_SERVICE, __func__);
    if ((sensorId >= SENSOR_TYPE_ID_MAX) || (sensorId < 0)) {
        HILOG_ERROR(HILOG_MODULE_APP, "[SERVICE:%s]: %s sensorId: %d is invalid",
            SENSOR_SERVICE, __func__, sensorId);
        return SENSOR_ERROR_INVALID_ID;
    }
    // ← NO validation of `mode`. Any int32_t passes silently.
    return SENSOR_OK;
}
```

The `SensorMode` enum defines exactly 5 valid modes (0–4), with `SENSOR_MAX_MODE = 5` as a sentinel for range checking:

```c
// interfaces/kits/native/include/sensor_agent_type.h
typedef enum SensorMode {
    SENSOR_DEFAULT_MODE  = 0,
    SENSOR_REALTIME_MODE = 1,
    SENSOR_ON_CHANGE     = 2,
    SENSOR_ONE_SHOT      = 3,
    SENSOR_FIFO_MODE     = 4,
    SENSOR_MAX_MODE,           // = 5, sentinel — not a real mode
} SensorMode;
```

## Trigger Conditions

1. Caller invokes `SetMode` with any out-of-range `mode` value on a valid subscribed sensor
2. `SetModeImpl` validates `sensorId` but skips `mode` validation entirely
3. Invalid `mode` propagates through the full call chain to the hardware driver:

```
SetMode(sensorTypeId, user, mode)                    ← agent API
  → SetModeByProxy(proxy, sensorId, user, mode)      ← checks proxy!=NULL, user!=NULL only
      → IPC invoke to service
          → SetModeImpl(sensorId, user, mode)         ← NO mode check
              → g_sensorDevice->SetMode(sensorId, mode)  ← garbage mode reaches driver
```

4. All of the following incorrectly return `SENSOR_OK(0)`:

| Input | Expected return | Actual return |
|-------|-----------------|---------------|
| `mode = -1` | `SENSOR_ERROR_INVALID_PARAM (-3)` | `SENSOR_OK (0)` |
| `mode = -100` | `SENSOR_ERROR_INVALID_PARAM (-3)` | `SENSOR_OK (0)` |
| `mode = 5` (`SENSOR_MAX_MODE`) | `SENSOR_ERROR_INVALID_PARAM (-3)` | `SENSOR_OK (0)` |
| `mode = 100` | `SENSOR_ERROR_INVALID_PARAM (-3)` | `SENSOR_OK (0)` |
| `mode = INT32_MAX` | `SENSOR_ERROR_INVALID_PARAM (-3)` | `SENSOR_OK (0)` |

## Impact

- **Invalid mode reaches hardware driver**: No layer in the call chain rejects invalid modes — the service layer ignores it, the proxy layer ignores it, and the driver receives garbage
- **Silent acceptance**: Callers receive `SENSOR_OK` for any mode value, giving no error signal for incorrect usage
- **Undefined hardware behavior**: Driver behavior with out-of-range mode values is unpredictable

## Suggested Fix

Add a 2-line range check using the existing `SENSOR_MAX_MODE` sentinel:

```c
int32_t SetModeImpl(int32_t sensorId, const SensorUser *user, int32_t mode)
{
    if ((sensorId >= SENSOR_TYPE_ID_MAX) || (sensorId < 0)) {
        return SENSOR_ERROR_INVALID_ID;
    }
+   if (mode < 0 || mode >= (int32_t)SENSOR_MAX_MODE) {
+       return SENSOR_ERROR_INVALID_PARAM;
+   }
    return SENSOR_OK;
}
```

`SENSOR_MAX_MODE` is already defined in `sensor_agent_type.h` for exactly this purpose.