#include "config.hpp"

std::string gConfigLogFilePathString;

std::string gServerHostString;
std::string gServerTlsCertFileString;
std::string gServerTlsKeyFileString;
std::vector<std::string> gServerConnectAllowIpsList;
std::vector<std::string> gServerConnectBanIpsList;

std::vector<std::string> gClientHostList;
std::vector<int> gClientPortList;
int gClientSelectMode = 0;  // 0=roundRobin, 1=random
int gClientRoundRobinIndex = 0;
std::mutex gClientRoundRobinMutex;

std::string gClientTlsHostNameString;
std::string gClientTlsSniString;
std::string gClientTlsCertFileString;

// 运行时变量
ThreadpoolAutoCtrlByTime rgThreadPool;
