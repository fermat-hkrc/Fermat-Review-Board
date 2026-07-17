#ifndef DHCP_LITE_WIRE_IPC_SKELETON_H
#define DHCP_LITE_WIRE_IPC_SKELETON_H
#include "serializer.h"
struct IpcObjectStub {
    int (*func)(uint32_t, IpcIo *, IpcIo *, int);
    void *args;
    bool isRemote;
};
using MessageOption = int;
#endif
