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

void selectBackendTarget()
{
    if (gClientHostList.empty() || gClientPortList.empty())
    {
        return;
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

    // 更新全局变量供C代码使用
    // 注意: gClientHostList[selectedIndex] 是临时string, 需要复制到静态或全局
    static std::string selectedHost;
    selectedHost = gClientHostList[selectedIndex];
    gClientHostChar = const_cast<char *>(selectedHost.c_str());
    gClientPort = gClientPortList[selectedIndex];
}
