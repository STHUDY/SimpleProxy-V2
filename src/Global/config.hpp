#pragma once
#include "headfile.h"

extern std::string gConfigLogFilePathString;

extern std::string gServerHostString;
extern std::string gServerTlsCertFileString;
extern std::string gServerTlsKeyFileString;
extern std::vector<std::string> gServerConnectAllowIpsList;
extern std::vector<std::string> gServerConnectBanIpsList;

extern std::vector<std::string> gClientHostList;
extern std::vector<int> gClientPortList;
extern int gClientSelectMode;  // 0=roundRobin, 1=random
extern int gClientRoundRobinIndex;
extern std::mutex gClientRoundRobinMutex;

extern std::string gClientTlsHostNameString;
extern std::string gClientTlsSniString;
extern std::string gClientTlsCertFileString;

extern ThreadpoolAutoCtrlByTime rgThreadPool;