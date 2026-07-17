// The production parser returns addresses in network-byte representation.
// This driver supplies a valid /16 range that crosses a /24 boundary.
#include <cstdio>

#include "address_utils.h"

int main()
{
    const uint32_t begin = ParseIpAddr("192.168.1.250");
    const uint32_t end = ParseIpAddr("192.168.2.10");
    const uint32_t candidate = ParseIpAddr("192.168.2.1");
    const uint32_t netmask = ParseIpAddr("255.255.0.0");

    const int result = IpInRange(candidate, begin, end, netmask);
    std::printf("range 192.168.1.250..192.168.2.10; candidate=192.168.2.1; result=%d\n", result);

    // The candidate is inside the textual IPv4 range.  The production code
    // returns zero on little-endian systems because it orders raw network
    // representation values rather than host-order IPv4 values.
    return result == DHCP_FALSE ? 0 : 1;
}
