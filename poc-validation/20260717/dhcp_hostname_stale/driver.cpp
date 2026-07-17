#include <cstring>
#include <iostream>

#include "dhcp_binding.h"
#include "dhcp_option.h"
#include "dhcp_s_define.h"
#include "dhcp_s_server.h"

int main()
{
    DhcpOptionNode sentinel {};
    DhcpOptionNode hostname {};
    sentinel.next = &hostname;
    hostname.previous = &sentinel;
    hostname.option.code = HOST_NAME_OPTION;

    DhcpMsgInfo message {};
    message.options.first = &sentinel;
    message.options.last = &hostname;
    message.options.size = 1;

    AddressBinding binding {};
    const char firstName[] = "long-name";
    std::memcpy(hostname.option.data, firstName, sizeof(firstName) - 1);
    hostname.option.length = sizeof(firstName) - 1;
    GetHostNameOption(&message, &binding);

    const char secondName[] = "x";
    std::memcpy(hostname.option.data, secondName, sizeof(secondName) - 1);
    hostname.option.length = sizeof(secondName) - 1;
    GetHostNameOption(&message, &binding);

    std::cout << "hostname_after_short_update='" << binding.deviceName
              << "' expected='x'" << std::endl;
    return std::strcmp(binding.deviceName, secondName) == 0 ? 1 : 0;
}
