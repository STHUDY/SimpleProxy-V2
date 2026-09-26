#ifndef __N_SOCKET_H__
#define __N_SOCKET_H__

#include "headfile.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct SocketClientInfo
    {
        SOCKET_T fd;                  // 套接字；Windows 上是 64 位句柄，不能用 int 存
        struct sockaddr_in addr;      // 客户端地址
        NET_SOCKLEN_T addr_len;       // 地址长度
        char ip_str[INET_ADDRSTRLEN]; // IP字符串
        int port;                     // 端口号
    } SocketClientInfo;

    // 回调只收 clientInfo：clientInfo->fd 就是 accept 返回的那个 fd，
    // 再单独传一遍是冗余参数
    typedef void (*SocketClientCallback)(SocketClientInfo *clientInfo);

    void initSocketServer();

    void listenSocketServer(SocketClientCallback callback);

    void closeSocketServer();

    // 成功返回套接字（同时写入 clientInfo->fd），失败返回 SOCKET_INVALID
    SOCKET_T connectSocketServer(SocketClientInfo *clientInfo, const char *host, int port);

#ifdef __cplusplus
}
#endif

#endif
