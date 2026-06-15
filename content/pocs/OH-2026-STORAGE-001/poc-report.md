# PoC Report: VolumeExternal::Unmarshalling() NULL Pointer Dereference

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Component | OpenHarmony storage_service |
| File | `foundation/filemanagement/storage_service/services/storage_manager/src/volume/volume_external.cpp` |
| Function | `VolumeExternal::Unmarshalling()` (line 139) |
| CWE | CWE-476 (NULL Pointer Dereference) |
| Severity | MEDIUM |
| Impact | Denial of Service — crash storage_manager_service |

## Root Cause

`VolumeExternal::Unmarshalling()` calls `VolumeCore::Unmarshalling(parcel)` which can return `nullptr` when the Parcel data is malformed (any field read fails). The return value is immediately dereferenced without a null check:

```cpp
VolumeExternal *VolumeExternal::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<VolumeCore> volumeCorePtr(VolumeCore::Unmarshalling(parcel));
    VolumeExternal* obj = new (std::nothrow) VolumeExternal(*volumeCorePtr);
    //                                                      ^^^^^^^^^^^^^^
    //                              Dereferences nullptr if Unmarshalling failed!
    ...
}
```

`VolumeCore::Unmarshalling` reads 8 fields from the Parcel (String id, Int32 type, String diskId, Int32 state, Bool errorFlag, String fsType, String extraInfo, Uint32 partitionNum). If any of these reads fail due to truncated or malformed data, it returns nullptr.

## Trigger Path

```
IPC Client (attacker app)
  → StorageManagerProxy::GetVolumesById() or similar volume query
  → MessageParcel with malformed VolumeExternal data
  → StorageManagerStub::OnRemoteRequest()
  → VolumeExternal::Unmarshalling(parcel)     [volume_external.cpp:139]
    → VolumeCore::Unmarshalling(parcel)        ← returns nullptr
    → *volumeCorePtr                           ← CRASH
```

## Build Environment

- **OS**: Linux (any)
- **Compiler**: g++ (C++17)
- **Dependencies**: None
- **Build command**: `g++ -o poc poc.cpp -std=c++17 -O2`

## Reproduction Steps

1. Compile: `g++ -o poc poc.cpp -std=c++17 -O2`
2. Run: `./poc`
3. Observe SIGSEGV crash when dereferencing nullptr

## PoC Output

```
=== VolumeExternal::Unmarshalling() NULL Pointer Dereference PoC ===
[*] Crafted malformed Parcel (15 bytes):
[*]   id_ = "vol" (valid)
[*]   type_ = 1 (valid)
[*]   diskId_ = 0xFFFFFFFF (INVALID → causes Unmarshalling to return nullptr)

[*] Calling VolumeExternal::Unmarshalling with malformed Parcel...

[!] CRASH: Caught signal 11 (SIGSEGV)
[!] NULL pointer dereference triggered!

[+] PoC SUCCESS: VolumeExternal::Unmarshalling crashes on malformed Parcel
```

## Real-World Attack Scenario

1. Any app with access to StorageManager IPC interface (permission: `ohos.permission.STORAGE_MANAGER`)
2. App crafts a MessageParcel with truncated volume data
3. Sends IPC request that triggers VolumeExternal deserialization on the service side
4. storage_manager_service crashes on nullptr dereference
5. Repeated messages cause persistent DoS of storage management functionality

## Preconditions

- Attacker needs an app with permission to communicate with storage_manager_service
- The specific IPC code path must deserialize VolumeExternal from a client-provided Parcel
- Most likely trigger: volume notification/callback mechanisms where client provides serialized volume data

## Fix Recommendation

```cpp
VolumeExternal *VolumeExternal::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<VolumeCore> volumeCorePtr(VolumeCore::Unmarshalling(parcel));
    if (!volumeCorePtr) {
        return nullptr;
    }
    VolumeExternal* obj = new (std::nothrow) VolumeExternal(*volumeCorePtr);
    // ...
}
```
