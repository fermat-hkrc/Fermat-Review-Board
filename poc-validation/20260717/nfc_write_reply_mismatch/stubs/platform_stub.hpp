#ifndef NFC_POC_PLATFORM_STUB_HPP
#define NFC_POC_PLATFORM_STUB_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace OHOS {
template <typename T>
using sptr = std::shared_ptr<T>;
template <typename T>
using wptr = std::weak_ptr<T>;

class MessageOption {};

class IRemoteObject;

class MessageParcel {
public:
    using Value = std::variant<std::u16string, int32_t, std::string, std::vector<uint8_t>, sptr<IRemoteObject>>;

    bool WriteInterfaceToken(const std::u16string &token) { values_.emplace_back(token); return true; }
    std::u16string ReadInterfaceToken() { return Read<std::u16string>(); }
    bool WriteInt32(int32_t value) { values_.emplace_back(value); return true; }
    int32_t ReadInt32() { return Read<int32_t>(); }
    bool WriteString(const std::string &value) { values_.emplace_back(value); return true; }
    bool ReadString(std::string &value) { value = Read<std::string>(); return true; }
    bool WriteUInt8Vector(const std::vector<uint8_t> &value) { values_.emplace_back(value); return true; }
    bool ReadUInt8Vector(std::vector<uint8_t> *value) { *value = Read<std::vector<uint8_t>>(); return true; }
    bool WriteRemoteObject(const sptr<IRemoteObject> &value) { values_.emplace_back(value); return true; }
    sptr<IRemoteObject> ReadRemoteObject() { return Read<sptr<IRemoteObject>>(); }
    size_t GetRawDataSize() const { return values_.size(); }

private:
    template <typename T>
    T Read()
    {
        if (index_ >= values_.size()) {
            return T{};
        }
        auto *value = std::get_if<T>(&values_[index_++]);
        return value == nullptr ? T{} : *value;
    }
    std::vector<Value> values_;
    size_t index_ = 0;
};

class IRemoteObject {
public:
    class DeathRecipient {
    public:
        virtual ~DeathRecipient() = default;
        virtual void OnRemoteDied(const wptr<IRemoteObject> &) = 0;
    };
    virtual ~IRemoteObject() = default;
    virtual int SendRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &) = 0;
    virtual bool IsProxyObject() const { return false; }
    virtual bool AddDeathRecipient(DeathRecipient *) { return true; }
    virtual bool RemoveDeathRecipient(DeathRecipient *) { return true; }
};

class IRemoteBroker {
public:
    virtual ~IRemoteBroker() = default;
    virtual sptr<IRemoteObject> AsObject() { return nullptr; }
};

class IPCObjectStub {
public:
    static int OnRemoteRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &) { return -1; }
};

template <typename T>
class IRemoteStub : public T, public IRemoteObject, public IPCObjectStub {
public:
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return OnRemoteRequest(code, data, reply, option);
    }
    virtual int OnRemoteRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &) = 0;
};

template <typename T>
class IRemoteProxy : public T {
public:
    explicit IRemoteProxy(const sptr<IRemoteObject> &remote) : remote_(remote) {}
    sptr<IRemoteObject> Remote() const { return remote_; }
private:
    sptr<IRemoteObject> remote_;
};

template <typename T>
class BrokerDelegator {};

template <typename T>
sptr<T> iface_cast(const sptr<IRemoteObject> &object)
{
    return std::dynamic_pointer_cast<T>(object);
}
}

#define ERR_NONE 0
#define DECLARE_INTERFACE_DESCRIPTOR(value) \
    static std::u16string GetDescriptor() { return std::u16string(value); }

#endif
