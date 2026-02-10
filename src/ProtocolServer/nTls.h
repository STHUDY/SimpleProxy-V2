#ifndef __N_TLS_H__
#define __N_TLS_H__

#include "headfile.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct TlsClientInfo
    {
        int fd;                       // 套接字文件描述符
        struct sockaddr_in addr;      // 客户端地址
        socklen_t addr_len;           // 地址长度
        char ip_str[INET_ADDRSTRLEN]; // IP字符串
        int port;                     // 端口号
        SSL *ssl;                     // TLS/SSL对象
        SSL_CTX *ssl_ctx;             // TLS/SSL上下文
    } TlsClientInfo;

    typedef void (*TlsClientCallback)(int client_fd, TlsClientInfo *client_info);

    void initTlsServer();

    void listenTlsServer(TlsClientCallback callback);

    void closeTlsServer();

    int connectTlsServer(TlsClientInfo *client_info, const char *sni);

    void closeTlsResource();

#ifdef __cplusplus
}
#endif

#endif