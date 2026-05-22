#include "config.h"

int gConfigSocketIoUseMode = CONNECT_USE_IO_NONE;
bool gConfigSocketNoBlockReadOrWrite = false;
bool gConfigSocketNoBlockConnect = false;
int gConfigSocketAcceptTimeoutMs = 5000;
int gConfigSocketConnectTimeoutMs = 5000;
int gConfigSocketPollingIntervalMs = 1000;
int gConfigSocketReadOrWriteTimeoutMs = 5000;

bool gConfigTlsEnbale = false;
int gConfigTlsSocketIoUseMode = CONNECT_USE_IO_NONE;
int gConfigTlsSslIoUseMode = CONNECT_USE_IO_NONE;
bool gConfigTlsUseThreadpoolSslConnect = false;
bool gConfigTlsNoBlockReadOrWrite = false;
bool gConfigTlsNoBlockConnect = false;
int gConfigTlsAcceptTimeoutMs = 5000;
int gConfigTlsConnectTimeoutMs = 5000;
int gConfigTlsPollingIntervalMs = 1000;
int gConfigTlsReadOrWriteTimeoutMs = 5000;

bool gConfigLogEnbale = true;
bool gConfigLogEnbaleConsole = true;
bool gConfigLogEnbaleFile = false;
int gConfigLogLevel = LOG_LEVEL_DEBUG;
char *gConfigLogFileChar = NULL;

int gConfigThreadpoolMinWorkers = 5;
int gConfigThreadpoolMaxWorkers = 10;
int gConfigThreadpoolClearThreadTimeMs = 10000;
int gConfigThreadpoolPollingIntervalMs = 1000;
int gConfigThreadpoolStepAddWorkers = 1;

char *gServerHostChar = NULL;
int gServerPort = 0;
int gServerSocketMaxBacklog = 5;
int gServerSocketBufferSize = 1024;
char *gServerTlsCertFileChar = NULL;
char *gServerTlsKeyFileChar = NULL;

char *gClientHostChar = NULL;
int gClientPort = 0;
int gClientSocketBufferSize = 1024;
char *gClientTlsHostNameChar = NULL;
char *gClientTlsSniChar = NULL;
char *gClientTlsCertFileChar = NULL;

// 运行时变量
bool rgSocketInit = false;
bool rgSocketServerRun = false;
int rgSocketServerFd = -1;
struct sockaddr_in rgSocketServerAddr;

bool rgTlsInit = false;
bool rgTlsServerRun = false;
int rgSslAcceptTimeoutMs = -1;
int rgTlsSocketServerFd = -1;
struct sockaddr_in rgTlsServerAddr;

pthread_mutex_t rgLogWriteFileMutex;
FILE *rgLogFileOpen = NULL;
