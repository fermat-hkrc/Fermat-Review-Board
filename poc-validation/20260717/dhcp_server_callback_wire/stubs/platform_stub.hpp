#ifndef DHCP_CALLBACK_POC_PLATFORM_HPP
#define DHCP_CALLBACK_POC_PLATFORM_HPP

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
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
    bool WriteInterfaceToken(const std::u16string &token) { token_ = token; return true; }
    std::u16string ReadInterfaceToken() { return token_; }
    bool WriteInt32(int32_t value) { return WriteScalar(value); }
    int32_t ReadInt32() { int32_t value = 0; ReadScalar(value); return value; }
    bool WriteString(const std::string &value)
    {
        const int32_t length = static_cast<int32_t>(value.size() + 1);
        WriteScalar(length);
        bytes_.insert(bytes_.end(), value.begin(), value.end());
        bytes_.push_back('\0');
        return true;
    }
    std::string ReadString()
    {
        int32_t length = 0;
        if (!ReadScalar(length) || length <= 0 || read_ + static_cast<size_t>(length) > bytes_.size()) {
            return {};
        }
        const char *data = reinterpret_cast<const char *>(bytes_.data() + read_);
        read_ += static_cast<size_t>(length);
        return std::string(data);
    }
    size_t GetRawDataSize() const { return bytes_.size(); }
private:
    template <typename T>
    bool WriteScalar(T value)
    {
        const auto *first = reinterpret_cast<const uint8_t *>(&value);
        bytes_.insert(bytes_.end(), first, first + sizeof(value));
        return true;
    }
    template <typename T>
    bool ReadScalar(T &value)
    {
        if (read_ + sizeof(value) > bytes_.size()) {
            value = T{};
            return false;
        }
        std::memcpy(&value, bytes_.data() + read_, sizeof(value));
        read_ += sizeof(value);
        return true;
    }
    std::u16string token_;
    std::vector<uint8_t> bytes_;
    size_t read_ = 0;
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
};

class IRemoteBroker {
public:
    virtual ~IRemoteBroker() = default;
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
}

#define ERR_NONE 0
#define DECLARE_INTERFACE_DESCRIPTOR(value) \
    static std::u16string GetDescriptor() { return std::u16string(value); }

#endif
