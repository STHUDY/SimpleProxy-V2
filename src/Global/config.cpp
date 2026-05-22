#include "config.hpp"

std::string gConfigLogFilePathString;

std::string gServerHostString;
std::string gServerTlsCertFileString;
std::string gServerTlsKeyFileString;
std::vector<std::string> gServerConnectAllowIpsList;
std::vector<std::string> gServerConnectBanIpsList;

std::string gClientHostString;

std::string gClientHostNameString;
std::string gClientSniString;
std::string gServerCertFileString;

// 运行时变量
ThreadpoolAutoCtrlByTime rgThreadPool;
