// Minimal IPC definitions normally re-exported through the Lite adapter.
#include "serializer.h"
struct IpcOwner {
    int exception;
    int retCode;
    void *variable;
    int32_t funcId;
};
struct IpcObjectStub {
    int (*func)(uint32_t, IpcIo *, IpcIo *, int);
    void *args;
    bool isRemote;
};
using MessageOption = int;
#define EC_SUCCESS 0
#define ERR_NONE 0
#define ERR_FAILED (-1)
#define INTERFACEDESCRIPTORL1 u"ohos.wifi.IDhcpClientService"
#define DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH (sizeof(INTERFACEDESCRIPTORL1) / sizeof(uint16_t))
#define DECLARE_INTERFACE_DESCRIPTOR_L1 ((uint16_t *)&INTERFACEDESCRIPTORL1[0])
