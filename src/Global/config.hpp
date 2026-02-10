#pragma once
#include "headfile.h"

extern std::string LogLevel;
extern std::string LogFilePath;

extern std::string serverHost;
extern std::string clientHost;

extern ThreadpoolAutoCtrlByTime threadPool;

extern std::vector<std::string> allowIpList;
extern std::vector<std::string> banIpList;

// extern std::unordered_set<int> ActiveSocketList;
// extern std::mutex ActiveSocketsListMutex;

extern std::string tlsCertFile;
extern std::string tlsKeyFile;

extern std::string tlsClientHostName;
extern std::string tlsClientSni;
extern std::string tlsServerCaFile;
