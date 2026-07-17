// RFC 2132 option-overload input.  The production parser must switch to file.
#include <cstdio>
#include <cstring>

#include "dhcp_options.h"

int main()
{
    DhcpPacket packet {};

    // Main option field: option 52 says file contains more options.
    packet.options[0] = OPTION_OVERLOAD_OPTION;
    packet.options[1] = 1;
    packet.options[2] = FILE_FIELD;
    packet.options[3] = END_OPTION;

    // file: DNS option (code 6, length 4) with value 8.8.8.8.
    packet.file[0] = DOMAIN_NAME_SERVER_OPTION;
    packet.file[1] = 4;
    packet.file[2] = 8;
    packet.file[3] = 8;
    packet.file[4] = 8;
    packet.file[5] = 8;
    packet.file[6] = END_OPTION;

    std::uint32_t dns = 0;
    const bool found = GetDhcpOptionUint32(&packet, DOMAIN_NAME_SERVER_OPTION, &dns);
    std::printf("valid overload DNS parsed=%d value=%u\n", found ? 1 : 0, dns);
    return found ? 1 : 0;
}
