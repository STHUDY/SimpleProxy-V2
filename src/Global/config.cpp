#include "config.hpp"

std::string gConfigLogFilePathString;

std::string gServerHostString;
std::string gServerTlsCertFileString;
std::string gServerTlsKeyFileString;
std::vector<std::string> gServerConnectAllowIpsList;
std::vector<std::string> gServerConnectBanIpsList;

std::string gClientHostString;

std::string gClientTlsHostNameString;
std::string gClientTlsSniString;
std::string gClientTlsCertFileString;

// 运行时变量
ThreadpoolAutoCtrlByTime rgThreadPool;
