#ifndef __GLOBAL_CONFIG_H__
#define __GLOBAL_CONFIG_H__

#include "headfile.h"

extern int ConnectTimeout;
extern int PollingIntervalMs;

extern bool LogEnbale;
extern bool LogEnbaleConsole;
extern int LogLevelNumber;
extern char *LogFilePathChar;
extern pthread_mutex_t LogMutex;
extern FILE *LogFile;

extern int ThreadPoolMaxThreadNumber;
extern int ThreadPoolMinThreadNumber;
extern int ThreadPoolStepAddThreadNumber;
extern int ThreadPoolClearThreadTimeMs;
extern int ThreadPoolWaitTimeMs;

extern char *serverHostChar;
extern int serverPort;

extern char *clientHostChar;
extern int clientPort;

extern int serverSocketBufferSize;
extern int serverSocketMaxBacklog;

extern int clientSocketBufferSize;

extern bool TlsEnbale;
extern bool TlsNoBlock;
extern bool TlsNoBlockConnect;

extern bool SocketNoBlockConnect;
extern bool SocketEnableSync;

extern char *tlsCertFileChar;
extern char *tlsKeyFileChar;

extern char *tlsClientHostNameChar;
extern char *tlsClientSniChar;
extern char *tlsServerCaFileChar;

// 运行时变量
extern bool SocketServerRun;
extern bool TlsServerRun;

extern int socketServerFd;
extern struct sockaddr_in serverAddr;

extern bool tlsInit;

extern SSL_CTX *serverTlsCtx;
extern SSL_CTX *clientTlsCtx;

#endif