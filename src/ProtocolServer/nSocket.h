#ifndef __N_SOCKET_H__
#define __N_SOCKET_H__

#include "headfile.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct SocketClientInfo
    {
        int fd;
        struct sockaddr_in addr;      // 客户端地址
        socklen_t addr_len;           // 地址长度
        char ip_str[INET_ADDRSTRLEN]; // IP字符串
        int port;                     // 端口号
    } SocketClientInfo;

    typedef void (*SocketClientCallback)(int clientFd, SocketClientInfo *clientInfo);

    void initSocketServer();

    void listenSocketServer(SocketClientCallback callback);

    void closeSocketServer();

    int connectSocketServer(SocketClientInfo *clientInfo);

#ifdef __cplusplus
}
#endif

#endif