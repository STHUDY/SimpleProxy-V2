#include "config.hpp"

std::string LogLevel;
std::string LogFilePath;

std::string serverHost;
std::string clientHost;

ThreadpoolAutoCtrlByTime threadPool;

std::vector<std::string> allowIpList;
std::vector<std::string> banIpList;

// std::unordered_set<int> ActiveSocketList;
// std::mutex ActiveSocketsListMutex;

std::string tlsCertFile;
std::string tlsKeyFile;

std::string tlsClientHostName;
std::string tlsClientSni;
std::string tlsServerCaFile;
