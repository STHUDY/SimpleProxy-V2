#ifndef __N_TLS_H__
#define __N_TLS_H__

#include "headfile.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct TlsClientInfo
    {
        SOCKET_T fd;                  // 套接字；Windows 上是 64 位句柄，不能用 int 存
        struct sockaddr_in addr;      // 客户端地址
        NET_SOCKLEN_T addr_len;       // 地址长度
        char ip_str[INET_ADDRSTRLEN]; // IP字符串
        int port;                     // 端口号
        SSL *ssl;                     // TLS/SSL对象
        SSL_CTX *ssl_ctx;             // TLS/SSL上下文
    } TlsClientInfo;

    typedef struct SocketClientInfo SocketClientInfo;

    // 回调只收 clientInfo：clientInfo->fd 就是握手用的那个 fd
    typedef void (*TlsClientCallback)(TlsClientInfo *clientInfo);
    typedef void (*TlsSocketUpgradeCallback)(SocketClientInfo *clientInfo, TlsClientCallback tlsCallback);

    SSL_CTX *createContext(bool isServer);

    bool configureServerContext(SSL_CTX *ctx);

    bool configureClientContext(SSL_CTX *ctx);

    void initTlsServer();

    void listenTlsServer(TlsSocketUpgradeCallback socketUpgradeTlsCallback, TlsClientCallback tlsCallback);

    void closeTlsServer();

    // 成功返回 0 并填充 clientInfo，失败返回 -1
    int connectTlsServer(TlsClientInfo *clientInfo, const char *sni, const char *host, int port);

    void closeTlsResource();

#ifdef __cplusplus
}
#endif

#endif
