// Linux 平台的 socket 生命周期、收发超时与 IPv4 地址解析接口。
// 不写 include guard / #pragma once，不 include "headfile.h"：
// 可重复展开，只含函数声明，不定义 struct / enum / 变量。
// pthread_mutex_t / struct sockaddr_in 等由 headfile.h 提前引入的 POSIX 头提供。

#ifdef __cplusplus
extern "C"
{
#endif

// Windows 必须在任何 socket 调用之前 WSAStartup，否则一律返回 WSANOTINITIALISED。
// Linux 上是空实现（返回 true），这样调用方不需要写平台判断。
bool netWsaStartup(void);
void netWsaCleanup(void);

// 关闭套接字。POSIX 用 close，fd 非法时返回 -1
int netSocketClose(SOCKET_T fd);

// 双向关闭套接字，用于唤醒阻塞在 accept() 上的线程。
// Linux 有 SHUT_RDWR，直接用。
int netShutdownBoth(SOCKET_T fd);

// 设置接收/发送超时（毫秒）。两平台语义一致，
// 但参数结构不同（见各自实现），调用方不要自己拼 timeval。
int netSetRecvTimeoutMs(SOCKET_T fd, int timeoutMs);
int netSetSendTimeoutMs(SOCKET_T fd, int timeoutMs);

// 解析主机名或点分十进制为 IPv4，只填 sin_family 与 sin_addr，sin_port 交给调用方。
// 走 getaddrinfo 统一处理，省掉 inet_pton + gethostbyname 两段分支。
// 失败返回 false。
bool netResolveIpv4(const char *host, struct sockaddr_in *addrOut);

// 分配对齐内存。转发缓冲要按缓存行（64 字节）对齐才不会拖慢 memcpy。
// 这里不用 new (std::align_val_t) T[]：MSVC 的过对齐数组 new 与
// operator delete[](p, align_val_t) 配对有问题（报 C2956），GCC 上却是好的，
// 放平台层才能让两个平台走同一条路。
// 用 posix_memalign 而不是 aligned_alloc：后者要求 size 必须是 alignment 的整数倍，
// 而 bufferSize 是用户可配的，不保证满足。返回 NULL 表示失败。
void *netAlignedAlloc(size_t size, size_t alignment);
void netAlignedFree(void *ptr);

#ifdef __cplusplus
}
#endif
