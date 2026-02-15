#include "config.h"

int ConnectTimeout = 60;
int PollingIntervalMs = 10;

bool LogEnbale = false;
bool LogEnbaleConsole = true;
int LogLevelNumber = 0;
char *LogFilePathChar = NULL;
pthread_mutex_t LogMutex;
FILE *LogFile = NULL;

int ThreadPoolMaxThreadNumber = 10;
int ThreadPoolMinThreadNumber = 100;
int ThreadPoolStepAddThreadNumber = 10;
int ThreadPoolClearThreadTimeMs = 10 * 60 * 1000;
int ThreadPoolWaitTimeMs = 500;

char *serverHostChar = NULL;
int serverPort = 0;

char *clientHostChar = NULL;
int clientPort = 0;

int serverSocketBufferSize = 0;
int serverSocketMaxBacklog = 0;

int clientSocketBufferSize = 0;

bool TlsEnbale = false;
bool TlsNoBlock = false;
bool TlsNoBlockConnect = false;

bool SocketNoBlockConnect = false;
bool SocketEnableSync = false;

char *tlsCertFileChar = NULL;
char *tlsKeyFileChar = NULL;

char *tlsClientHostNameChar = NULL;
char *tlsClientSniChar = NULL;
char *tlsServerCaFileChar = NULL;

// 运行时变量
bool SocketServerRun = false;
bool TlsServerRun = false;

int socketServerFd = -1;
struct sockaddr_in serverAddr;

bool tlsInit = false;

SSL_CTX *serverTlsCtx = NULL;
SSL_CTX *clientTlsCtx = NULL;
