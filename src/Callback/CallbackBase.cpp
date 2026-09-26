#include "CallbackBase.hpp"

bool isIpAllowed(const std::string &ip_str)
{
    auto ban_it = std::find(gServerConnectBanIpsList.begin(), gServerConnectBanIpsList.end(), ip_str);
    if (ban_it != gServerConnectBanIpsList.end())
    {
        return false; // IP 被禁止
    }

    if (gServerConnectAllowIpsList.empty())
    {
        return true;
    }

    // 如果白名单不为空，只有在白名单中的 IP 才能访问
    auto allow_it = std::find(gServerConnectAllowIpsList.begin(), gServerConnectAllowIpsList.end(), ip_str);
    if (allow_it != gServerConnectAllowIpsList.end())
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool selectBackendTarget(BackendTarget &target)
{
    if (gClientHostList.empty() || gClientPortList.empty())
    {
        return false;
    }

    size_t selectedIndex = 0;
    size_t listSize = gClientHostList.size();

    if (listSize == 1)
    {
        selectedIndex = 0;
    }
    else if (gClientSelectMode == CLIENT_SELECT_RANDOM) // random
    {
        selectedIndex = rand() % listSize;
    }
    else // roundRobin (default)
    {
        std::lock_guard<std::mutex> lock(gClientRoundRobinMutex);
        selectedIndex = gClientRoundRobinIndex;
        gClientRoundRobinIndex = (gClientRoundRobinIndex + 1) % listSize;
    }

    // 结果写进调用方持有的对象：每个 worker 各有自己的 target，
    // connect 期间不会被其它线程的选址结果覆盖。
    target.host = gClientHostList[selectedIndex];
    target.port = gClientPortList[selectedIndex];
    return true;
}
