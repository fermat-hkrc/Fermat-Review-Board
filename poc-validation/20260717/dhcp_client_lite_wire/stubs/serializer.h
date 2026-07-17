#ifndef DHCP_LITE_WIRE_SERIALIZER_H
#define DHCP_LITE_WIRE_SERIALIZER_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

struct SvcIdentity {
    int32_t handle = 0;
    uintptr_t token = 0;
    uintptr_t cookie = 0;
};

struct IpcIo {
    using Value = std::variant<std::u16string, int32_t, bool, std::string, SvcIdentity>;
    std::vector<Value> values;
    size_t read = 0;
};

inline void IpcIoInit(IpcIo *io, void *, size_t, size_t) { io->values.clear(); io->read = 0; }
inline bool WriteInterfaceToken(IpcIo *io, const uint16_t *data, size_t length)
{
    io->values.emplace_back(std::u16string(reinterpret_cast<const char16_t *>(data), length));
    return true;
}
inline uint16_t *ReadInterfaceToken(IpcIo *io, size_t *length)
{
    static std::u16string empty;
    if (io->read >= io->values.size()) { *length = 0; return nullptr; }
    auto *value = std::get_if<std::u16string>(&io->values[io->read++]);
    if (value == nullptr) { *length = 0; return nullptr; }
    *length = value->size();
    return reinterpret_cast<uint16_t *>(value->data());
}
inline bool WriteInt32(IpcIo *io, int32_t value) { io->values.emplace_back(value); return true; }
inline bool ReadInt32(IpcIo *io, int32_t *value)
{
    if (io->read >= io->values.size()) { *value = 0; return false; }
    auto *item = std::get_if<int32_t>(&io->values[io->read++]);
    *value = item == nullptr ? 0 : *item;
    return item != nullptr;
}
inline bool WriteBool(IpcIo *io, bool value) { io->values.emplace_back(value); return true; }
inline bool ReadBool(IpcIo *io, bool *value)
{
    if (io->read >= io->values.size()) { *value = false; return false; }
    auto *item = std::get_if<bool>(&io->values[io->read++]);
    *value = item == nullptr ? false : *item;
    return item != nullptr;
}
inline bool WriteString(IpcIo *io, const char *value) { io->values.emplace_back(std::string(value == nullptr ? "" : value)); return true; }
inline uint8_t *ReadString(IpcIo *io, size_t *length)
{
    if (io->read >= io->values.size()) { *length = 0; return nullptr; }
    auto *item = std::get_if<std::string>(&io->values[io->read++]);
    if (item == nullptr) { *length = 0; return nullptr; }
    *length = item->size() + 1;
    return reinterpret_cast<uint8_t *>(item->data());
}
inline bool WriteRemoteObject(IpcIo *io, const SvcIdentity *value) { io->values.emplace_back(*value); return true; }
inline bool ReadRemoteObject(IpcIo *io, SvcIdentity *value)
{
    if (io->read >= io->values.size()) return false;
    auto *item = std::get_if<SvcIdentity>(&io->values[io->read++]);
    if (item == nullptr) return false;
    *value = *item;
    return true;
}

#define IPC_INVALID_HANDLE (-1)
#define SERVICE_TYPE_ANONYMOUS 0
#define IPC_DATA_SIZE_SMALL 1024
#define MAX_IPC_OBJ_COUNT 8

#endif
