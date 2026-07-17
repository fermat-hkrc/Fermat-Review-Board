#include "/home/cupcup/data/openharmony-data/repos/communication_dhcp/services/dhcp_server/src/dhcp_s_server.cpp"

namespace OHOS::DHCP {
std::string Ip4IntConvertToStr(uint32_t, bool)
{
    return "192.0.2.1";
}

int32_t AddArpEntry(const std::string&, const std::string&, const std::string&)
{
    return 0;
}
}

extern "C" char *ParseStrMac(const uint8_t *, size_t)
{
    static char value[] = "00:00:00:00:00:00";
    return value;
}

extern "C" ssize_t __wrap_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t)
{
    return -1;
}

extern "C" int RunSendFailureScenario()
{
    ServerContext instance {};
    instance.serverFd = 7;
    instance.broadCastFlagEnable = 0;

    DhcpServerContext context {};
    context.instance = &instance;

    DhcpMsgInfo reply {};
    reply.length = 300;
    return TransmitOfferOrAckPacket(&context, &reply);
}
