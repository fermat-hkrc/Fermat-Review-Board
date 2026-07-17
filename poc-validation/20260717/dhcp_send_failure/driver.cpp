#include <iostream>

extern "C" int RunSendFailureScenario();

int main()
{
    const int result = RunSendFailureScenario();
    std::cout << "sendto_return=-1 handler_result=" << result << " expected_failure" << std::endl;
    return result == 0 ? 0 : 1;
}
