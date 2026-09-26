#ifndef __GLOBAL_CONFIG_H__
#define __GLOBAL_CONFIG_H__

#include "headfile.h"

// 这里的全局量定义在 config.c（C 编译），却被 main.cpp / SocketCallback.cpp /
// TlsCallback.cpp 这些 C++ 文件读写，所以必须声明成 C 链接。
// GCC/Clang 的 Itanium ABI 不对全局命名空间的变量做 mangle，所以缺 extern "C"
// 在 Linux 上照样能链接；MSVC 会 mangle 每一个全局量，缺了就全是 LNK2001。
#ifdef __cplusplus
extern "C"
{
#endif

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
extern int gClientSocketBufferSize;
extern char *gClientTlsHostNameChar;
extern char *gClientTlsSniChar;
extern char *gClientTlsCertFileChar;

// 运行时变量
extern bool rgSocketInit;
extern bool rgSocketServerRun;
extern SOCKET_T rgSocketServerFd;
extern struct sockaddr_in rgSocketServerAddr;

extern bool rgTlsInit;
extern bool rgTlsServerRun;
extern int rgSslAcceptTimeoutMs;
extern SOCKET_T rgTlsSocketServerFd;
extern struct sockaddr_in rgTlsServerAddr;

extern NET_MUTEX_T rgLogWriteFileMutex;
extern NET_MUTEX_T rgLogOutputMutex;
extern FILE *rgLogFileOpen;

extern int rgConnectIndex;

#ifdef __cplusplus
}
#endif

#endif