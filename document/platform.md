# 跨平台适配层

## 为什么有这一层

`src/Platform/` 收拢所有平台差异。**业务代码里不出现 `#ifdef _WIN32`**，平台分支只存在于本目录内部和 `CMakeLists.txt` 里。

改造前，平台耦合的 85% 集中在 4 个文件（`nTls.c` 84 处、`nSocket.c` 70 处、`TlsCallback.cpp` 68 处、`SocketCallback.cpp` 22 处）。收敛后这 4 个文件里的平台差异降到零。

## 平台差异对照表

全部经 Windows SDK 10.0.26100 / OpenSSL 3.6.4 头文件与实测确认。

| 主题 | Linux | Windows | 适配方式 |
| --- | --- | --- | --- |
| 套接字类型 | `int` | `SOCKET` = `UINT_PTR`（64 位） | `SOCKET_T` |
| 无效值 | `-1` | `INVALID_SOCKET` = `(SOCKET)(~0)` | `SOCKET_INVALID` + `netSocketValid()` |
| 判活 | `fd >= 0` | `fd >= 0` **恒真**（无效值是巨大正数） | `netSocketValid(fd)` |
| 关闭 | `close()` | `closesocket()`（`close()` 对 socket 无效） | `netSocketClose()` |
| 双向关闭 | `shutdown(fd, SHUT_RDWR)` | 没有 `SHUT_RDWR`，是 `SD_BOTH` | `netShutdownBoth()` |
| 库初始化 | 不需要 | **必须** `WSAStartup`，否则一律 `WSANOTINITIALISED` | `netWsaStartup()` / `netWsaCleanup()` |
| 错误来源 | `errno` | `WSAGetLastError()`（`errno` 无意义） | `netLastError()` |
| 错误常量 | `EAGAIN` / `EINTR` / … | `WSAEWOULDBLOCK` / `WSAEINTR` / … | `netIs*()` 谓词 |
| 错误文本 | `strerror` | `FormatMessageA` | `netErrorString()` |
| 超时参数 | `struct timeval` | `DWORD` 毫秒 | `netSetRecv/SendTimeoutMs()` |
| 地址长度类型 | `socklen_t` | 无 `socklen_t`，用 `int` | `NET_SOCKLEN_T` |
| 读写返回类型 | `ssize_t` | 无 `ssize_t`（只有大写 `SSIZE_T`） | `NET_SSIZE_T` |
| `send` 标志 | `MSG_NOSIGNAL` | 不需要（Winsock 不产生 SIGPIPE） | `SOCKET_SEND_FLAGS` |
| `SIGPIPE` | 存在，需 `signal(SIGPIPE, SIG_IGN)` | **不存在** | `main.cpp` 里 `#if !defined(_WIN32)` |
| `sigaction` | 有 | 无，退化为 `signal()` | `installSigintHandler()` |
| fd 上限 | `RLIMIT_NOFILE`，可提到 65536 | 无此概念 | 降级为说明性日志 |
| 互斥量 | `pthread_mutex_t` | `CRITICAL_SECTION` | `NET_MUTEX_T` + 4 宏 |
| 线程安全本地时间 | `localtime_r(tm, time)` | `localtime_s(tm, time)`（**参数序相同**，返回 0 成功） | `netLocalTime()` |
| 事件等待 | `epoll`（水平触发） | `WSAPoll` | `netWaitSet*()` |
| `POLLIN` 数值 | `0x001` | `0x0100 \| 0x0200`（`POLLRDNORM\|POLLRDBAND`） | 常量只留在各自实现内 |
| `POLLWRNORM` 数值 | `0x004` | `0x0010` | 同上 |
| 名称解析 | `gethostbyname`（`hostent` 指向静态内存） | `gethostbyname` 已废弃 | 统一用 `getaddrinfo` |
| 对齐内存 | `posix_memalign` | `_aligned_malloc` | `netAlignedAlloc()` / `netAlignedFree()` |
| **connect 到 0.0.0.0** | 内核按 `127.0.0.1` 处理，能连 | 返回 `WSAEADDRNOTAVAIL` | 显式映射 `INADDR_LOOPBACK` |
| 证书信任库 | `OPENSSLDIR` | 同样读 `OPENSSLDIR`，**不读 Windows 证书库** | 追加 `client.tls.cert` |
| 源文件编码 | UTF-8 | UTF-8 无 BOM，MSVC 默认按系统 ANSI 代码页读 | CMake 加 `/utf-8` |
| CRT | 系统默认 | 必须 `/MD`（vcpkg `*-md` triplet） | 见 [build.md](build.md) |

**`POLLIN` 数值不同**这一条决定了事件抽象的形状：共享 API **不能暴露事件标志位**，只暴露 `int wantWrite`，让每个实现自己用自己的常量。

## 接口清单

### `PlatformBase.h` — 共享宏

```c
SOCKET_T            // SOCKET(int) / int
NET_SOCKLEN_T       // int / socklen_t
NET_SSIZE_T         // long long / ssize_t
SOCKET_INVALID      // INVALID_SOCKET / (-1)
SOCKET_SEND_FLAGS   // 0 / MSG_NOSIGNAL
netSocketValid(fd)  // 宏
NET_WAIT_NONE / NET_WAIT_READY / NET_WAIT_FAILED
```

只有这一个文件带 `#if defined(_WIN32)` / `#else`，因为它承载平台相关的常量，而平台头必须早于所有声明存在。

### `PlatformSocket*.h/.c`

```c
bool  netWsaStartup(void);       void netWsaCleanup(void);
int   netSocketClose(SOCKET_T fd);
int   netShutdownBoth(SOCKET_T fd);
int   netSetRecvTimeoutMs(SOCKET_T fd, int timeoutMs);
int   netSetSendTimeoutMs(SOCKET_T fd, int timeoutMs);
bool  netResolveIpv4(const char *host, struct sockaddr_in *addrOut);
void *netAlignedAlloc(size_t size, size_t alignment);
void  netAlignedFree(void *ptr);
```

`netResolveIpv4` 的契约：**只填 `sin_family` 和 `sin_addr`，绝不碰 `sin_port`**。

不能整块 `memcpy(addrOut, result->ai_addr, sizeof(struct sockaddr_in))` —— `getaddrinfo` 返回的结构里 `sin_port` 是 0（没传 service 名），整块覆盖会把调用方已经设好的端口清零。调用点（`nSocket.c` / `nTls.c` 的 connect 路径）是在解析**之前**设端口的，所以一旦整块拷贝就变成连 0 端口，表现为 `WSAEADDRNOTAVAIL`，而日志如果打印 `port` 变量而非 `serverAddr.sin_port` 就完全看不出来。日志已改成从结构体取端口。

### `PlatformError*.h/.c`

```c
int         netLastError(void);
const char *netErrorString(int errCode);   // 立即拷贝，不要长期持有
bool netIsWouldBlock(int) / netIsInterrupted(int) / netIsTimeout(int) / netIsReset(int)
bool netIsInProgress(int) / netIsAborted(int) / netIsFdExhausted(int)
```

两处容易搞错：

- **Windows 的 `netIsWouldBlock()` 同时接受 `WSAEWOULDBLOCK` 和 `WSAETIMEDOUT`。** POSIX 上 `SO_RCVTIMEO` 到期返回 `EAGAIN`，调用方靠这个谓词认出"暂时没数据"进超时分支；Windows 同样的超时报的是 `WSAETIMEDOUT`，不加进来的话那些分支一个都进不去，连接会静默断开、丢掉超时日志。不会误伤忙循环 —— 超时选项只在 `readOrWriteTimeoutMs > 0` 时才设，那种配置下超时分支本来就会断开。
- **`netErrorString()` 会裁掉尾部 `\r\n` / 空格。** `FormatMessageA` 和部分 glibc 的 `strerror` 都会在结尾补换行，日志那边还会再补一个，不裁就多出空行。

### `PlatformMutex*.h`（纯宏，无 `.c`）

```c
NET_MUTEX_T                                     // CRITICAL_SECTION / pthread_mutex_t
NET_MUTEX_INIT(m) / NET_MUTEX_DESTROY(m) / netMutexLock(m) / netMutexUnlock(m)
```

宏内部已经带 `&`，**调用处不能再传 `&`**，否则展开成 `&(&m)`（rvalue），`EnterCriticalSection` 拒绝非 const 指针。

必须显式 `NET_MUTEX_INIT`。原来的日志互斥量从来没有初始化过，只是 glibc 下全零值恰好等于合法的 `PTHREAD_MUTEX_INITIALIZER`；全零的 `CRITICAL_SECTION` 是非法的，`EnterCriticalSection` 会抛 `STATUS_INVALID_CRITICAL_SECTION`。现在 `main()` 第一行就初始化。

### `PlatformTime*.h`（纯宏，无 `.c`）

```c
netLocalTime(tmPtr, timePtr)   // localtime_s(tm,time)==0 / localtime_r(tm,time)!=NULL
```

用 `_r`/`_s` 而不是 `localtime`：`localtime` 返回共享的静态 `struct tm`，多 worker 并发打日志会互相覆盖时间戳。

### `PlatformWait*.h/.c`

```c
struct PlatformWaitSet;                                  // 不透明，只在前置声明
struct PlatformWaitSet *netWaitSetCreate(void);
int   netWaitSetAdd(struct PlatformWaitSet *set, SOCKET_T fd);
void  netWaitSetDestroy(struct PlatformWaitSet *set);
int   netWaitSetWait(struct PlatformWaitSet *set, int count, int wantWrite,
                     int timeoutMs, SOCKET_T *fds, int *states);
```

- `fds` / `states` 由调用方提供，长度都是 `count`
- 返回就绪个数，`0` 超时，`-1` 出错
- `states[i]` 取 `NET_WAIT_NONE` / `NET_WAIT_READY` / `NET_WAIT_FAILED`
- **不暴露事件标志位**（见上文 `POLLIN` 数值差异）
- **不定义结构体**：`PlatformWaitSet` 的真实定义在 `.c` 里；Windows 版是空壳（`WSAPoll` 不需要预登记），Linux 版持有一个 epoll fd，生命周期跨多次 wait 复用

Linux 实现注册 `EPOLLIN | EPOLLOUT`，等哪个方向由 `netWaitSetWait` 的 `wantWrite` 过滤。**判定顺序是先看等的方向、再看错误**：对端正常关闭时内核给的是 `EPOLLIN | EPOLLRDHUP`，必须让读事件先命中，才能走到 `SSL_read` 的干净关闭分支；反过来会把正常关闭误判成错误。

## 无 guard 约束（重要）

`headfile.h` **没有 include guard**，`src/Platform/` 下的头**也不写**。这是有意的设计，不是遗漏。

`headfile.h` 的 C 段有 4 个递归源（`nSocket.h`、`nTls.h`、`config.h`、`Log.h`），它们都在 guard 置位**之后**才 `#include "headfile.h"`。所以 **`headfile.h` 的函数体在单个 C TU 里会执行 5 次**（外层 + 4 层嵌套）。Platform 头挂在同一张表里，同样被展开 5 次。

靠这三条保证不出错：

| 规则 | 原因 |
| --- | --- |
| **Platform 头绝不 `#include "headfile.h"`** | 两边都没有 guard，互相 include 就是无限递归。系统头由 `headfile.h` 提前引入，Platform 头直接用 |
| **Platform 头内不定义 `struct` / `enum` / 变量** | 重复展开时是硬错误。`PlatformWaitSet` 只能用不完整前置声明 `struct PlatformWaitSet;`，真实定义放 `.c` |
| **类型别名用宏而不是 `typedef`** | 相同宏体重复定义在 C/C++ 都是无条件合法；`typedef` 重复要靠 C11 才合法 |

只含宏、`typedef`、函数声明、`extern "C"` 的头重复展开完全无害。**不放 `inline`、不放函数定义。**

（`.hpp` 里有两处 `inline` —— `ThreadpoolSimple.hpp` 和 `ThreadpoolAutoCtrlByTime.hpp` 的模板函数。模板不能放在 `.cpp`，这两处是既有且必要的，不算破例。）

因为 Platform 头不能 include `headfile.h`，`src/Platform/*.c` 必须自己把 `headfile.h` 拉进来，所以它们是全仓库唯一 include 两个头的实现文件：

```c
#include "headfile.h"                 // 系统头 + PlatformBase.h 提供 SOCKET_T
#include "PlatformSocketWindows.h"    // 自己模块的声明（此时已幂等）
```

这三条已用专门 TU 验证过：把 5 个 Platform 头各显式 include 5 次，MSVC `/W4` 下 **0 error 0 warning**。

`define.h` 是同一模式的先例（纯宏、不 include `headfile.h`）。

## C/C++ 混合的链接问题

项目是 C（`nSocket.c`、`nTls.c`、`Log.c`、`config.c`、Platform 的 6 个 `.c`）+ C++（其余）。

### 被 C++ 引用的 C 头必须包 `extern "C"`

`nSocket.h`、`nTls.h`、5 个 Platform 头都有。**`config.h` 也必须有** —— 它的 `g*` / `rg*` 全局量定义在 `config.c`（C 编译），却被 `main.cpp` / `SocketCallback.cpp` / `TlsCallback.cpp` 读写。

GCC/Clang 的 Itanium ABI **不对全局命名空间的变量做 mangle**，所以缺 `extern "C"` 在 Linux 上照样能链接；MSVC 会 mangle 每一个全局量，缺了就是一片 `LNK2001`。

### 同名变量不能跨头重复声明

`gClientSelectMode` 曾经在 `config.h`（现包在 `extern "C"` 里）和 `config.hpp`（C++ 头）各声明一次。同一个名字先后以不同链接属性声明，MSVC 上符号 mangle 不一致，直接链接失败。已从 `config.hpp` 删掉，只留 `config.h` 一份。

### `Log.h` 不包 `extern "C"`

这是刻意的：`Log.h` 只给 C 文件用，所有 `.cpp` 对 `*ConsoleCharString` 的调用数恒为 0。`Log.hpp` 声明的 C++ 重载本就该是 C++ 链接。

**用 grep 闸门锁住这个前提**：`.cpp` 中 `CharString` 命中数必须为 0。

### `SSL_set_fd` 的形参是 `int`

`int SSL_set_fd(SSL *s, int fd)` —— OpenSSL 在所有平台都用 `int` 接 fd。Windows 的 `SOCKET` 是 64 位句柄，传入需要**显式 `(int)` 收窄**（实际句柄值远小于 `INT_MAX`）。两处：`nTls.c` 和 `TlsCallback.cpp`。
