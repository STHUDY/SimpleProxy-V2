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
// gClientSelectMode（0=roundRobin, 1=random）只在 config.h 里声明，不要在这里重复声明。
// 它被包在 config.h 的 extern "C" 里，而本文件是 C++ 头；同名变量一旦先后以不同链接属性
// 声明，MSVC 会因为符号 mangle 不一致而链接失败。
extern std::mutex gClientRoundRobinMutex;

extern std::string gClientTlsHostNameString;
extern std::string gClientTlsSniString;
extern std::string gClientTlsCertFileString;

extern ThreadpoolAutoCtrlByTime rgThreadPool;