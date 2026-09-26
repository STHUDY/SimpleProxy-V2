#ifndef __PLATFORM_SOCKET_WINDOWS_H__
#define __PLATFORM_SOCKET_WINDOWS_H__
#include "headfile.h"

// Windows 平台的 socket 生命周期、收发超时与 IPv4 地址解析接口。
// 不写 include guard / #pragma once，不 include "headfile.h"：
// 可重复展开，只含函数声明，不定义 struct / enum / 变量。
// SOCKET / struct sockaddr_in / closesocket 由 headfile.h 的 winsock 分支提前引入。

#ifdef __cplusplus
extern "C"
{
#endif

// Winsock 要求在任何 socket 调用之前先 WSAStartup，
// 否则所有调用一律返回 WSANOTINITIALISED。成功返回 true。
bool netWsaStartup(void);
void netWsaCleanup(void);

// 关闭套接字。必须用 closesocket：Windows 上 close() 关的是 CRT 文件描述符，
// 拿它关 socket 会失败并留下句柄泄漏。
int netSocketClose(SOCKET_T fd);

// 双向关闭套接字。Winsock 没有 SHUT_RDWR，对应常量是 SD_BOTH。
int netShutdownBoth(SOCKET_T fd);

// 设置接收/发送超时（毫秒）。Windows 的 SO_RCVTIMEO / SO_SNDTIMEO 收 DWORD 毫秒数，
// 不是 POSIX 的 struct timeval，所以这个差异必须封在这里，调用方只传毫秒。
int netSetRecvTimeoutMs(SOCKET_T fd, int timeoutMs);
int netSetSendTimeoutMs(SOCKET_T fd, int timeoutMs);

// 解析主机名或点分十进制为 IPv4，只填 sin_family 与 sin_addr，sin_port 交给调用方。
// 走 getaddrinfo 而不是 gethostbyname：后者在 Windows 上已废弃，且返回的
// hostent 指向线程局部内存，跨线程使用不安全。
// 失败返回 false。
bool netResolveIpv4(const char *host, struct sockaddr_in *addrOut);

// 分配对齐内存。转发缓冲要按缓存行（64 字节）对齐才不会拖慢 memcpy。
// 这里不用 new (std::align_val_t) T[]：MSVC 的过对齐数组 new 与
// operator delete[](p, align_val_t) 配对有问题（报 C2956），GCC 上却是好的，
// 放平台层才能让两个平台走同一条路。
// 用 _aligned_malloc 而不是 aligned_alloc：后者要求 size 必须是 alignment 的整数倍，
// 而 bufferSize 是用户可配的，不保证满足。返回 NULL 表示失败。
void *netAlignedAlloc(size_t size, size_t alignment);
void netAlignedFree(void *ptr);

#ifdef __cplusplus
}
#endif

#endif //__PLATFORM_SOCKET_WINDOWS_H__
