#ifndef DHCP_LITE_WIRE_IPROXY_CLIENT_H
#define DHCP_LITE_WIRE_IPROXY_CLIENT_H
#include "iunknown.h"
using IOwner = void *;
using INotify = int (*)(IOwner owner, int code, IpcIo *reply);
struct IClientProxy {
    int (*Invoke)(IClientProxy *, int funcId, IpcIo *request, IOwner owner, INotify notify);
};
#endif
