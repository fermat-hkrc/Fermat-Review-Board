// The production SaveConfig implementation is linked unchanged.  Only fwrite
// is wrapped to model a short write that can occur at a real file boundary.
#include <cstdio>
#include <string>

#define private public
#include "dhcp_result_store_manager.h"
#undef private

namespace OHOS::DHCP {
int CheckDataLegal(const std::string &, int) { return 0; }
bool IsValidPath(const std::string &path) { return !path.empty(); }
}

extern "C" size_t __wrap_fwrite(const void *, size_t, size_t, FILE *)
{
    return 0;
}

int main()
{
    OHOS::DHCP::DhcpResultStoreManager manager;
    manager.m_fileName = "/tmp/dhcp_cache_write_loss.conf";
    IpInfoCached entry {};
    entry.bssid = "00:11:22:33:44:55";
    entry.ssid = "test-network";
    manager.m_allIpCached.push_back(entry);
    const int result = manager.SaveConfig();
    std::printf("save_result=%d cache_entries_after_write_failure=%zu expected_nonzero_and_preserved\n",
        result, manager.m_allIpCached.size());
    return result != 0 && !manager.m_allIpCached.empty() ? 1 : 0;
}
