// Target-compile driver for RFC 2132 option overload handling.
// It calls production GetDhcpOptionUint32, which calls the production option
// walker.  The DHCP packet is a valid option-overload packet.
#include <cstdio>
#include <cstring>

#include "dhcp_options.h"

int main()
{
    DhcpPacket packet {};

    // Main option field: option 52 says that the boot-file field contains
    // additional DHCP options, followed by END.
    packet.options[0] = OPTION_OVERLOAD_OPTION;
    packet.options[1] = 1;
    packet.options[2] = FILE_FIELD;
    packet.options[3] = END_OPTION;

    // RFC-compliant DNS server option in packet.file: code 6, 4-byte value.
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

    // A compliant parser returns true and 0x08080808.  Returning false proves
    // that the real walker did not use the selected file field.
    return found ? 1 : 0;
}
