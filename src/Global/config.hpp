#pragma once
#include "headfile.h"

extern std::string gConfigLogFilePathString;

extern std::string gServerHostString;
extern std::string gServerTlsCertFileString;
extern std::string gServerTlsKeyFileString;
extern std::vector<std::string> gServerConnectAllowIpsList;
extern std::vector<std::string> gServerConnectBanIpsList;

extern std::string gClientHostString;

extern std::string gClientTlsHostNameString;
extern std::string gClientTlsSniString;
extern std::string gClientTlsCertFileString;

extern ThreadpoolAutoCtrlByTime rgThreadPool;