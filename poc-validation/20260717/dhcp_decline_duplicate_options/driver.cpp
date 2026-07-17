#include <cstdint>
#include <iostream>

extern "C" int RunDeclineScenario();
extern "C" int CountCapturedOption(uint8_t requestedCode);

int main()
{
    const int result = RunDeclineScenario();
    const int requestedIp = CountCapturedOption(50);
    const int serverId = CountCapturedOption(54);
    std::cout << "decline_result=" << result << " requested_ip_options=" << requestedIp
              << " server_id_options=" << serverId << " expected_each=1" << std::endl;
    return (result == 0 && requestedIp == 2 && serverId == 2) ? 0 : 1;
}
