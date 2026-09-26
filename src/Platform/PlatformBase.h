// 跨平台共享的 socket 类型别名、平台相关常量与通用接口声明。
//
// 本文件刻意不写 include guard / #pragma once，也不 include "headfile.h"。
// headfile.h 的函数体在单个 TU 里会展开多次（nSocket.h / nTls.h / config.h / Log.h
// 四个头都会回头 include 它），所以这里的每个宏、typedef、声明都必须能被重复展开：
// 只能出现宏、typedef 和函数声明，不能出现 struct / enum / 变量定义 / inline 函数。
// 系统头（winsock2.h、sys/socket.h 等）由 headfile.h 在前面统一引入，这里直接用。

#if defined(_WIN32)

// Winsock 的 SOCKET 是 UINT_PTR，64 位；用 int 存会在 x64 上截断
#define SOCKET_T SOCKET
// Winsock 的 accept / getsockname / getpeername 收 int *，不是 socklen_t
#define NET_SOCKLEN_T int
// MSVC 只有大写的 SSIZE_T，没有 POSIX 的 ssize_t
#define NET_SSIZE_T long long
#define SOCKET_INVALID INVALID_SOCKET
// Winsock 的 send 不会像 POSIX 那样触发 SIGPIPE，所以不需要 MSG_NOSIGNAL
#define SOCKET_SEND_FLAGS 0
// INVALID_SOCKET 是 (SOCKET)(~0)，是个巨大的正数，
// 所以这里绝不能用 fd >= 0 判活，必须与 SOCKET_INVALID 比较
#define netSocketValid(fd) ((fd) != INVALID_SOCKET)

#else

#define SOCKET_T int
#define NET_SOCKLEN_T socklen_t
#define NET_SSIZE_T ssize_t
#define SOCKET_INVALID (-1)
#define SOCKET_SEND_FLAGS MSG_NOSIGNAL
#define netSocketValid(fd) ((fd) >= 0)

#endif

// netWaitSetWait 填进 states[] 的取值，两个平台的实现语义一致
#define NET_WAIT_NONE 0
#define NET_WAIT_READY 1
#define NET_WAIT_FAILED 2

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __cplusplus
}
#endif
