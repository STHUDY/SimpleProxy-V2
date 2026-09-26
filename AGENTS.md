# AGENTS.md

给 AI agent 的工作说明。**`MISTAKE.md` 记录了本仓库已核实但尚未修复的缺陷**（含每条的成因与证据），改动相关模块前先读，避免把同样的问题重新引入。已修复的缺陷不再收录，成因分析保留在 git 历史里。

## 项目

SimpleProxy-V2：C/C++17 从零实现的 TCP / TLS 端口转发代理，单 CMake 目标 `SimpleProxy`。

入口 `src/main.cpp` 的流程：解析 `-c <config>` → 逐项校验 → 提升 `RLIMIT_NOFILE` → 初始化监听（明文或 TLS）→ `rgThreadPool.init()` → 提交 accept 循环作为常驻任务 → 主线程阻塞在 `std::cin`（输入 `exit` 回车或 Ctrl+C 优雅退出）。

```
src/
├── main.cpp                 入口：参数、配置加载校验、启动/关闭
├── headfile.h               统一头（所有 .c/.cpp 只 include 它）
├── define.h                 宏：I/O 模式、日志级别、后端选择策略
├── Platform/                跨平台适配层（业务代码里不得出现 #ifdef）
│   ├── PlatformBase.h       共享类型别名 + 平台相关常量 + 通用判定宏
│   ├── Linux/               PlatformSocket/Error/Mutex/Time/Wait(epoll)
│   └── Windows/             PlatformSocket/Error/Mutex/Time/Wait(WSAPoll)
├── Global/                  全局状态（C 与 C++ 各一份，见下）
├── Log/                     日志（C 与 C++ 各一套同名 API）
├── ProtocolServer/          裸系统调用封装：nSocket(明文) / nTls(TLS)
├── Threadpool/              ThreadpoolSimple + ThreadpoolAutoCtrlByTime
└── Callback/                业务层：防火墙、后端选择、连接生命周期、转发
```

另有两个非源码目录：`document/`（技术文档）、`test/`（测试场景配置 + 说明）。

两条转发链路（调用链细节见 `document/architecture.md`）：

- **明文**：`socketListenerCallback` → `listenSocketServer(socketServerCallback)` → `socketServerCallback` → `socketCreateProxyMission` → 2 个 `socketProxyWorkerSingle`（一方向一个，共享 `CallbackShareInfo`）
- **TLS**：`tlsListenerCallback` → `listenTlsServer(tlsSocketUpgradeCallback, tlsServerCallback)` → `tlsSocketUpgradeTlsAccept`（SSL_accept）→ `tlsCreateProxyMission` → 1 个 `tlsProxyWorker`（`netWaitSet` 同时监听两端；Linux 走 epoll，Windows 走 WSAPoll）

## 平台与构建

- **支持 Windows 与 Linux**。平台差异全部收敛在 `src/Platform/`，**业务代码（`main.cpp` 除外，它有少量 `#if defined(_WIN32)` 处理信号）里不得出现 `#ifdef _WIN32`**。差异对照表见 `document/platform.md`。
- 依赖：`yaml-cpp` + `OpenSSL` 两平台 `REQUIRED`；`Threads` 只在非 Windows 才 `find_package`。
  - Linux：`sudo apt install build-essential cmake libyaml-cpp-dev libssl-dev`
  - Windows：走 vcpkg（`vcpkg.json` 声明 `openssl` / `yaml-cpp`），**必须给 CMake 指前缀**，否则 `find_package(yaml-cpp REQUIRED)` 失败：
    ```powershell
    cmake -S . -B build -G "Visual Studio 18 2026" -A x64 "-DCMAKE_PREFIX_PATH=$PWD\vcpkg_installed\x64-windows-static-md"
    cmake --build build --config Release
    ```
- **VS 生成器不要传 `-DCMAKE_BUILD_TYPE`**（多配置，由 `--config` 选）、**不要用 `make`**（不产 Makefile）。详见 `document/build.md`。
- **默认构建类型是 Debug**（`CMakeLists.txt` 里 `if(NOT CMAKE_BUILD_TYPE)`）。任何性能 / 时延 / 吞吐结论都必须显式用 `Release`。
- 运行：`./build/SimpleProxy [-c config.yml]`（Windows：`.\build\Release\SimpleProxy.exe`）
- **配置里的相对路径按进程 CWD 解析**，不是按配置文件所在目录。
- **没有测试框架、没有 CI、没有 lint / format 配置**。不要擅自引入测试框架。`test/` 下只有场景配置和说明文档。验证方式 = 干净编译 + 手工冒烟。
- **验证状态**：Windows x64（MSVC）编译与明文 / TLS 冒烟均已通过；**Linux 侧尚未实际编译验证**（编写时手头无 gcc），不要声称"Linux 已验证"。


## 源码组织

- **GLOB 陷阱**：`CMakeLists.txt` 用 `file(GLOB_RECURSE ...)` 收集源文件。新增 / 删除 / 重命名源文件后**必须重新执行 `cmake ..`**（或删掉 `CMakeCache.txt`），只跑 `make` 不会生效。
- **include 纪律**：所有 `.c` / `.cpp` 只 include `headfile.h`（或本模块的 `.hpp`，其内部再 include `headfile.h`）。需要系统头就加到 `src/headfile.h`，不要在业务文件里单独 include。
  - **例外**：`src/Platform/*.c` include **两个**头 —— `headfile.h` + 自己模块的头。因为 Platform 头不能 include `headfile.h`（会无限递归，见下），只能由 `.c` 自己拉。
- **include 写裸文件名**（`#include "nSocket.h"`）：`CMakeLists.txt` 把每个 `src/*` 及其下所有层都加进了 include 路径，新增目录自动生效。
- **`headfile.h` 没有 include guard**，它会被同一个 TU 重复展开。重复展开是常态而非意外：
  - `headfile.h` 的 C 段有 4 个递归源（`nSocket.h` / `nTls.h` / `config.h` / `Log.h`），它们在 guard 置位**之后**才 include `headfile.h`，所以 **`headfile.h` 的函数体在单个 C TU 里会执行 5 次**（外层 + 4 层嵌套）。
  - **新增头文件必须满足以下之一**：① 自带 guard 或 `#pragma once`（`nSocket.h` / `nTls.h` / `config.h` / `Log.h` 走这条）；② **不 `#include "headfile.h"`**，且内容只含可重复展开的宏 / `typedef` / 函数声明（`define.h` 与 `src/Platform/` 下的头走这条）。**两者都不满足就是无限递归。**
  - 走第 ② 条时还有两条硬约束：**不定义 `struct` / `enum` / 变量**（重复展开是硬错误，`PlatformWaitSet` 只能用不完整前置声明）；**类型别名用宏不用 `typedef`**（相同宏体重复定义无条件合法，`typedef` 重复要靠 C11）。
- `TlsCallback.cpp` 用了 `std::ostringstream`，`<sstream>` 已补进 `headfile.h`；用到新标准库设施时同样把头文件补进去，不要依赖传递包含。
- **`.clangd` 的 `Add` 列表必须和 `CMakeLists.txt` 展开出的 include 路径一致**（当前 = `src` + 5 个子目录 + `Platform/` + `Platform/Linux` + `Platform/Windows`，共 9 条）。增删 `src/` 子目录时同步它；clangd 的 `Add` 不支持 glob，只能逐条列。`CompilationDatabase: build/` 依赖 `CMakeLists.txt` 里的 `CMAKE_EXPORT_COMPILE_COMMANDS`。
- **全局配置是 C / C++ 双份**：
  - `src/Global/config.h` + `config.c` —— C 侧（`g*` 配置、`rg*` 运行时、`char*` 别名）
  - `src/Global/config.hpp` + `config.cpp` —— C++ 侧（`std::string` / `std::vector` / `rgThreadPool`）
  - 新增配置项要同时改两侧 + 在 `main.cpp` 里解析；C 侧靠 `const_cast<char *>(stdString.c_str())` 桥接
  - **`config.c` 的初始值与 `main.cpp` 里的 `.as<T>(default)` 不一致**（如 `maxWokers` 10 vs 15、`bufferSize` 1024 vs 8192）。`main.cpp` 每次都会赋值，所以**实际生效的是 `main.cpp` 的默认值**
- **日志同样是双份 API**：C 侧 `logOutput*ConsoleCharString`（声明在 `Log.h`），C++ 侧重载 `logOutput*Console`（声明在 `Log.hpp`）。`logOutputFatalConsole` 在 `Log.c` 和 `Log.cpp` 各有一份实现，`Log.h` 未声明 C 版本，目前没有 `.c` 文件调用它。

## 跨平台红线

违反这几条在 Linux 上看不出来，在 Windows 上会直接崩或静默失效。

- **fd 判活一律用 `netSocketValid(fd)`，禁止写 `fd >= 0` / `fd < 0` / `fd = -1`。** Windows 的 `INVALID_SOCKET` 是 `(SOCKET)(~0)`，是个**巨大的正数**，`>= 0` 恒真 —— 照原样写就会拿无效句柄去 `close`。同理赋值用 `SOCKET_INVALID`。`PlatformWaitEpoll.c` 里的 `epollDescriptor` 是 epoll 的 fd 不是套接字，可以用 `int` + `-1`。
- **套接字类型一律 `SOCKET_T`，长度类型 `NET_SOCKLEN_T` / `NET_SSIZE_T`。** Windows 的 `SOCKET` 是 64 位 `UINT_PTR`，用 `int` 存会在 x64 上截断。`ssize_t` 在 MSVC 根本不存在。
- **关闭用 `netSocketClose()`，不用 `close()`。** Windows 上 `close()` 关的是 CRT 文件描述符，对 socket 无效，会留下句柄泄漏。
- **双向关闭用 `netShutdownBoth()`，不要写 `SHUT_RDWR`。** Winsock 里对应常量叫 `SD_BOTH`。
- **收发超时用 `netSetRecvTimeoutMs()` / `netSetSendTimeoutMs()`，不要自己拼 `struct timeval`。** Windows 的 `SO_RCVTIMEO` 收 `DWORD` 毫秒数，形态不同。
- **收发标志用 `SOCKET_SEND_FLAGS`，不要写 `MSG_NOSIGNAL`。** Winsock 的 `send` 不产生 SIGPIPE，那个宏在 Windows 上不存在。`SIGPIPE` 忽略与 `sigaction` 都已在 `main.cpp` 里按平台 `#if` 分流。
- **错误处理用 `netLastError()` + `netIs*()` 谓词，不要直接读 `errno`。** Windows 走 `WSAGetLastError()`，错误码编号与 POSIX 完全不同。注意 Windows 的 `netIsWouldBlock()` **同时接受 `WSAEWOULDBLOCK` 和 `WSAETIMEDOUT`** —— 套接字超时报的是后者，而 POSIX 报 `EAGAIN`，不加进来超时分支一个都进不去。
- **地址解析用 `netResolveIpv4()`。** 它**只填 `sin_family` 和 `sin_addr`，绝不碰 `sin_port`**（调用方在解析之前就设好端口了，整块 `memcpy` 会把端口清零，表现为连 0 端口）。`inet_pton` / `inet_ntop` 两平台同名，不需要包装。
- **`connect()` 路径的 `0.0.0.0` / `*` 映射到 `INADDR_LOOPBACK`；`bind()` 路径保持 `INADDR_ANY`。** Linux 内核把 connect 到 `0.0.0.0` 按 `127.0.0.1` 处理，Windows 直接返回 `WSAEADDRNOTAVAIL`。
- **`WSAStartup()` 是强制的**，所有 socket 调用之前必须有（`main()` 最早期调 `netWsaStartup()`，退出前 `netWsaCleanup()`）。Windows 的互斥量也**必须显式 `NET_MUTEX_INIT`** —— 全零 `CRITICAL_SECTION` 是非法的，`EnterCriticalSection` 会抛异常；glibc 下全零恰好合法，所以以前漏初始化也没暴露。
- **不要引入 `inline`。** 仓库现状：`ThreadpoolSimple.hpp` / `ThreadpoolAutoCtrlByTime.hpp` 各有一处模板函数**必须** inline（模板不能放 `.cpp`），除此之外为零。`src/Platform/` 下的头连 `inline` 都不能有（会随 `headfile.h` 重复展开）。
- **`SSL_set_fd` 的形参是 `int`**，传 `SOCKET_T` 要显式 `(int)` 收窄（实际句柄值远小于 `INT_MAX`）。
- **`CFLAGS` / `CXXFLAGS` 按编译器分开写。** MSVC 不认 `-O3` / `-ftree-vectorize`，硬套只会得到 `D9002 忽略未知选项`、Release 等于没开优化；而且必须显式 `/MD`（vcpkg `*-md` triplet），否则 `LNK2038`。
- **`add_compile_options()` / `add_definitions()` 必须写在 `add_executable()` 之前。** 它们只对其后创建的目标生效，写晚了 `/utf-8` 和所有预定义宏一个都不生效，表现为满屏 `C4819` + 中文注释里的声明"未声明的标识符"。
- **`src/Platform/` 的两个实现目录只编译当前平台的那一份**，`CMakeLists.txt` 用 `list(FILTER ...)` 排除。另一份进编译会因为缺 `sys/epoll.h` / `SHUT_RDWR` 或缺 `winsock2.h` 而报错。
- **被 C++ 引用的 C 头必须包 `extern "C"`，包括 `config.h`。** 它的全局量定义在 `config.c`，却被 `main.cpp` / `SocketCallback.cpp` / `TlsCallback.cpp` 读写。Itanium ABI 不对全局命名空间的变量 mangle，Linux 上缺了照样链接；MSVC mangle 每一个全局量，缺了就是一片 `LNK2001`。
- **同名变量不能跨头重复声明。** `gClientSelectMode` 曾经在 `config.h`（`extern "C"` 里）和 `config.hpp` 各声明一次，MSVC 上链接失败。已从 `config.hpp` 删除。
- **`Log.h` 刻意不加 `extern "C"`**（它只给 C 文件用）。用 grep 闸门锁住这个前提：`.cpp` 中 `CharString` 命中数必须为 0。

## 内存与生命周期红线

- accept 回调把 `SocketClientInfo` 以**栈对象地址**传入（`nSocket.c` / `nTls.c` 的 accept 循环里）。回调必须 `new SocketClientInfo(*clientInfo)` 堆拷贝后才能返回，否则指针悬垂。
- **明文与 TLS 的所有权模型不同，不要混用**：
  - 明文：一条连接 = 2 个任务共享 `CallbackShareInfo{init, close, timeout, mutex}`。先退出者只置 `close = true` 就返回；**观察到 `close == true` 的那一个**负责关闭两个 fd、释放两个 info、`shareInfo` 和 `mutex`。不要新增第三条清理路径，也不要重复释放。
  - TLS：一条连接 = 1 个任务，没有 `shareInfo`，由 `cleanup` lambda 一次性收尾。
- 缓冲区必须配对：`netAlignedAlloc(size, 64)` ↔ `netAlignedFree(ptr)`。**不要改回 `new (std::align_val_t(64)) char[n]`** —— MSVC 的过对齐数组 new 与 `operator delete[](p, align_val_t)` 配对有问题（C2956），GCC 上却是好的。**分配失败必须判空**：`netAlignedAlloc` 返回 NULL 而不是抛异常，NULL 指针配非零长度喂给 `recv` / `SSL_read` 就是访问违例。
- **`CallbackShareInfo::close` 是 `std::atomic<bool>`**，转发循环在锁外读它，写入侧在锁内。改这块时保持原子性，不要退回普通 bool。
- **后端选址结果必须显式传参**：`selectBackendTarget(BackendTarget&)` 写入调用方持有的 `BackendTarget{std::string host; int port;}`，`connectSocketServer` / `connectTlsServer` 接收 `const char *host, int port`。**不要**改回写全局 `gClientHostChar` / `gClientPort` —— 那是已修掉的并发 bug（多线程会连到别的后端）。这两个全局现在只在 `main.cpp` 启动时赋值一次，已无读取点。
- 日志互斥量在 `main()` 第一行就 `NET_MUTEX_INIT`，因为紧接着的每一步都会打日志。
- **YAML 裸键陷阱**：`node.as<std::string>(fallback)` 对 null 节点（裸键 `key:`）返回字面量 `"null"` 而非 `fallback`。字符串配置一律过 `normalizeConfigString()`，8 处（`log.filePath`、`server.host`、`server.tls.cert`、`server.tls.privkey`、`server.tls.key`、`client.tls.hostname`、`client.tls.sni`、`client.tls.cert`）。`int` / `bool` 没有这个问题。

## 线程池容量

- 有两个常驻任务：自动扩缩容 manager（`init()` 里 `pushMission`）+ accept 循环。
- 明文模式每条连接常驻 **2 个** worker（双向各一），TLS 握手阶段短暂占 1~2 个。
- **容量换算**（`ThreadpoolAutoCtrlByTime.cpp:129,147,166,195`）：`setMin/setMaxThreadNumber` 内部各 `+1`，`init()` 又 `setPoolSize(min_thread_number + 1)`，所以
  - 实际初始 worker = **`minWokers + 2`**
  - 实际上限 = **`maxWokers + 1`**
  - 可用连接数还要再扣掉常驻的 2 个任务
  - 经验值：`maxWokers >= 2 × 预期最大并发连接数`
- 扩容：`stepAddThreadNumber > 0` 时按步长但不超过实际缺口；`<= 0` 时按 `pendingMissions / 2`（至少 1）。
- 容量不足的日志信号：`exec_mission error`（任务被丢弃）、`create_worker error`。
- `waitMissionDone()` 等到 `getMissionNumber() == 0 && getBusyThreadNumber() <= 1`；`shutdown()` 内部还会再调一次。
- 已知副作用：任务抛异常会走 `errorCallback(0x0002)`，从队列里**额外弹掉一个无关任务**再回调 mission_drop（`ThreadpoolAutoCtrlByTime.hpp:66`）。看到 `exec_mission error` 时要意识到可能丢的是别的任务。

## 配置键位

生效默认值全部取自 `src/main.cpp` 的 `.as<T>(default)`。`config.yml` 现值与之不一致时**以本表为准**。

`config.socket`

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `ioUseMode` | string | `none` | 识别 `none`/`select`/`poll`/`epoll`，**非 `none` 启动即 FATAL 退出**（其余未实现） |
| `useThreadpoolAccept` | bool | `true` | `false` = 在 accept 任务内同步建连（阻塞监听） |
| `noBlockReadOrWrite` | bool | `false` | **死配置**，从未被读取 |
| `noBlockConnect` | bool | `false` | **死配置** |
| `acceptTimeoutMs` | int | `-1` | >0 时给监听 socket 设 `SO_SNDTIMEO`/`SO_RCVTIMEO` |
| `connectTimeoutMs` | int | `-1` | >0 时给后端 socket 设收发超时 |
| `pollingIntervalMs` | int | `500` | **只被 TLS 转发路径读取**（`TlsCallback.cpp:438`，写阻塞时 `netWaitSetWait` 的超时） |
| `readOrWriteTimeoutMs` | int | `-1` | >0 时给两端 fd 设收发超时；`<=0` 空闲连接永久占用 worker |

`config.tls`（**仅 `enable: true` 时才被读取**，其余键全部忽略）

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enable` | bool | `false` | `true` = 对客户端解密（SSL_accept）、对后端重新加密（SSL_connect）。**不是原始字节透传**，后端也必须是 TLS 服务 |
| `socketIoUseMode` | string | `none` | 非 `none` 启动即 FATAL 退出 |
| `sslIoUseMode` | string | `none` | 非 `none` 启动即 FATAL 退出 |
| `useThreadpoolAccept` | bool | `true` | TLS 握手（`SSL_accept`）是否交线程池 |
| `useThreadpoolSslAccept` | bool | `true` | 连接后端（`SSL_connect`）是否交线程池 |
| `noBlockReadOrWrite` | bool | `false` | **死配置**，从未被读取 |
| `noBlockConnect` | bool | `false` | **死配置** |
| `acceptTimeoutMs` | int | `-1` | |
| `connectTimeoutMs` | int | `-1` | 写阻塞重试的总超时；`<=0` 表示不启用该超时 |
| `pollingIntervalMs` | int | `100` | `netWaitSetWait` 的超时（epoll_wait / WSAPoll） |
| `readOrWriteTimeoutMs` | int | `-1` | 空闲连接超时（毫秒，与 `pollingIntervalMs` 同单位累加） |

`config.log`

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enable` | bool | `true` | 总开关 |
| `console` | bool | `true` | 控制台输出（带 ANSI 颜色） |
| `level` | string | `debug` | `debug`/`info`/`warn`/`error`/`fatal`，输出该级别及以上 |
| `file` | bool | `false` | |
| `filePath` | string | `""` | 文件或父目录不存在则降级为不写文件；首次写入时才 `fopen` |

`config.threadpool`

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `minWokers` | int | `5` | 拼写是 `Wokers`，属对外契约，不要"修正"；实际初始 worker = 值 + 2 |
| `maxWokers` | int | `15` | 同上；实际上限 = 值 + 1 |
| `clearThreadTimeMs` | int | `10000` | 空闲多久后开始缩容 |
| `pollingIntervalMs` | int | `500` | 扩缩容 manager 循环间隔 |
| `stepAddThreadNumber` | int | `1` | 每次扩容步长；`<=0` 时按 `pendingMissions/2` 自适应 |

`server`

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `host` | string | **必填** | `0.0.0.0`/`*` = 所有网卡，`127.0.0.1`/`localhost` = 本机，其他交给 `netResolveIpv4()`（走 getaddrinfo） |
| `port` | int | **必填** | `<=0` 退出 |
| `socket.maxBacklog` | int | `128` | `<=0` 降级为 5 |
| `socket.bufferSize` | int | `8192` | **后端 → 客户端**方向 |
| `tls.cert` | string | `""` | 证书 PEM；文件不存在则清空并报错（仅 `enable: true` 时读） |
| `tls.privkey` | string | `""` | 私钥 PEM。**规范键是 `privkey`**；仍兼容旧的 `key`（读到 `key` 时打 deprecation 警告）。文件不存在则清空并报错 |
| `connect.banIps` | list | `[]` | IP 黑名单，**完整字符串精确比较**（无 CIDR / 通配符），优先级最高 |
| `connect.allowedIps` | list | `[]` | 为空表示不限制；非空则只放行命中项 |

`client`

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `host` | string \| list | **必填** | 单值或数组（多后端） |
| `port` | int \| list | **必填** | 元素个数必须与 `host` 一致，否则启动失败 |
| `selectMode` | string | `roundRobin` | `roundRobin`（互斥锁保护的循环索引）/ `random`（`rand() % n`） |
| `socket.bufferSize` | int | `8192` | **客户端 → 后端**方向 |
| `tls.hostname` | string | `""` | **死配置** |
| `tls.sni` | string | `""` | 为空则透传客户端握手 SNI；同时用于后端证书主机名校验。`0.0.0.0` / `localhost` 会被 `isValidTlsHost` 判为无效并**告警**，此时主机名校验不生效。**要留空必须写 `sni: ""`**，裸键会被读成字符串 `"null"` |
| `tls.cert` | string | `""` | 后端 CA 文件路径（**追加**到信任库，不是替换）。文件不存在则清空并报错。留空则只依赖 OpenSSL 默认信任库（`SSL_CERT_FILE` / `OPENSSLDIR`），Windows 上默认为空 |

拼写错误同属对外契约，改名会破坏已有配置：`minWokers` / `maxWokers`、`gConfigTlsEnbale`。`privkey` 是规范键，`key` 只是兼容用的别名。

## 提交约定

- 单行小写祈使句，无 prefix / scope：`fix tls error`、`update cmake`、`optimize threadpool and callback`。
- 直接提交 `main`，没有 PR 流程、没有打标签。
- 注释与日志文案用中文，标识符用英文。
- 改动配置键、默认值或转发行为时，把变更同步到 `README.md` 的配置项参考表（本文件只记开发约定，配置表以 README 为准）。
