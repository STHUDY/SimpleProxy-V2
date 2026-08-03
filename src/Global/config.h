#ifndef __GLOBAL_CONFIG_H__
#define __GLOBAL_CONFIG_H__

#include "headfile.h"

extern int gConfigSocketIoUseMode;
extern bool gConfigSocketUseThreadpoolAccept;
extern bool gConfigSocketNoBlockReadOrWrite;
extern bool gConfigSocketNoBlockConnect;
extern int gConfigSocketAcceptTimeoutMs;
extern int gConfigSocketConnectTimeoutMs;
extern int gConfigSocketPollingIntervalMs;
extern int gConfigSocketReadOrWriteTimeoutMs;

extern bool gConfigTlsEnbale;
extern int gConfigTlsSocketIoUseMode;
extern int gConfigTlsSslIoUseMode;
extern bool gConfigTlsUseThreadpoolAccept;
extern bool gConfigTlsUseThreadpoolSslConnect;
extern bool gConfigTlsNoBlockReadOrWrite;
extern bool gConfigTlsNoBlockConnect;
extern int gConfigTlsAcceptTimeoutMs;
extern int gConfigTlsConnectTimeoutMs;
extern int gConfigTlsPollingIntervalMs;
extern int gConfigTlsReadOrWriteTimeoutMs;

extern bool gConfigLogEnbale;
extern bool gConfigLogEnbaleConsole;
extern bool gConfigLogEnbaleFile;
extern int gConfigLogLevel;
extern char *gConfigLogFileChar;

extern int gConfigThreadpoolMinWorkers;
extern int gConfigThreadpoolMaxWorkers;
extern int gConfigThreadpoolClearThreadTimeMs;
extern int gConfigThreadpoolPollingIntervalMs;
extern int gConfigThreadpoolStepAddWorkers;

extern char *gServerHostChar;
extern int gServerPort;
extern int gServerSocketMaxBacklog;
extern int gServerSocketBufferSize;
extern char *gServerTlsCertFileChar;
extern char *gServerTlsKeyFileChar;

extern char *gClientHostChar;
extern int gClientPort;
extern int gClientSelectMode;  // 0=roundRobin, 1=random
extern int gClientRoundRobinIndex;
extern int gClientSocketBufferSize;
extern char *gClientTlsHostNameChar;
extern char *gClientTlsSniChar;
extern char *gClientTlsCertFileChar;

// 运行时变量
extern bool rgSocketInit;
extern bool rgSocketServerRun;
extern int rgSocketServerFd;
extern struct sockaddr_in rgSocketServerAddr;

extern bool rgTlsInit;
extern bool rgTlsServerRun;
extern int rgSslAcceptTimeoutMs;
extern int rgTlsSocketServerFd;
extern struct sockaddr_in rgTlsServerAddr;

extern pthread_mutex_t rgLogWriteFileMutex;
extern FILE *rgLogFileOpen;

#endif