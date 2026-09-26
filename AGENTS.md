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
├── Global/                  全局状态（C 与 C++ 各一份，见下）
├── Log/                     日志（C 与 C++ 各一套同名 API）
├── ProtocolServer/          裸系统调用封装：nSocket(明文) / nTls(TLS)
├── Threadpool/              ThreadpoolSimple + ThreadpoolAutoCtrlByTime
└── Callback/                业务层：防火墙、后端选择、连接生命周期、转发
```

两条转发链路（调用链细节见 `MISTAKE.md` 相关条目）：

- **明文**：`socketListenerCallback` → `listenSocketServer(socketServerCallback)` → `socketServerCallback` → `socketCreateProxyMission` → 2 个 `socketProxyWorkerSingle`（一方向一个，共享 `CallbackShareInfo`）
- **TLS**：`tlsListenerCallback` → `listenTlsServer(tlsSocketUpgradeCallback, tlsServerCallback)` → `tlsSocketUpgradeTlsAccept`（SSL_accept）→ `tlsCreateProxyMission` → 1 个 `tlsProxyWorker`（epoll 同时监听两端）

## 平台与构建

- **仅支持 Linux**：直接依赖 `unistd.h` / `sys/epoll.h` / `sys/socket.h` / `sys/resource.h`。
- **本机当前无法编译**：未安装 WSL，也没有 `g++` / `gcc` / `cl` / `ninja`（只有 `cmake` 和 `make`）。`build/` 内只有 `.cmake/api/`，没有 `CMakeCache.txt` / `Makefile`，说明本机从未完成过一次 configure。**编译验证必须在 Linux / WSL2 上进行**，不要在没有工具链的环境下声称"已验证"。
- 依赖（三个 `find_package` 都是 `REQUIRED`，缺一即 configure 失败）：`sudo apt install build-essential cmake libyaml-cpp-dev libssl-dev`
- 构建：

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

- **默认构建类型是 Debug（`-O0 -g`）**（`CMakeLists.txt:22-23`）。任何性能 / 时延 / 吞吐结论都必须显式用 `Release`（`-O3 -DNDEBUG -funroll-loops -ftree-vectorize`）。
- 运行：`./build/SimpleProxy [-c config.yml]`
- **没有测试、没有 CI、没有 lint / format 配置**。不要擅自引入测试框架。验证方式 = 干净编译 + 手工冒烟（起一个本地后端连上去看转发；TLS 用 `openssl s_server` / `s_client`）。

## 源码组织

- **GLOB 陷阱**：`CMakeLists.txt:11` 用 `file(GLOB_RECURSE ...)` 收集源文件。新增 / 删除 / 重命名源文件后**必须重新执行 `cmake ..`**（或删掉 `CMakeCache.txt`），只跑 `make` 不会生效。
- **include 纪律**：所有 `.c` / `.cpp` 只 include `headfile.h`（或本模块的 `.hpp`，其内部再 include `headfile.h`）。需要系统头就加到 `src/headfile.h`，不要在业务文件里单独 include。
- **include 写裸文件名**（`#include "nSocket.h"`）：`CMakeLists.txt:33-38` 把每个 `src/*` 子目录都加进了 include 路径。
- **`headfile.h` 没有 include guard**，它会被同一个 TU 重复展开，靠下游 `nSocket.h` / `nTls.h` / `config.h` / `Log.h` / `define.h` 的 `#ifndef` 和各 `.hpp` 的 `#pragma once` 终止递归。**新增头文件必须自带 guard 或 `#pragma once`**，否则无限递归。
- `TlsCallback.cpp` 用了 `std::ostringstream`，`<sstream>` 已补进 `headfile.h`；用到新标准库设施时同样把头文件补进去，不要依赖传递包含。
- **`.clangd` 的 `Add` 列表必须和 `CMakeLists.txt` 展开出的 include 路径一致**（当前 = `src` + 5 个子目录）。增删 `src/` 子目录时同步它；clangd 的 `Add` 不支持 glob，只能逐条列。`CompilationDatabase: build/` 依赖 `CMakeLists.txt` 里的 `CMAKE_EXPORT_COMPILE_COMMANDS`。
- **全局配置是 C / C++ 双份**：
  - `src/Global/config.h` + `config.c` —— C 侧（`g*` 配置、`rg*` 运行时、`char*` 别名）
  - `src/Global/config.hpp` + `config.cpp` —— C++ 侧（`std::string` / `std::vector` / `rgThreadPool`）
  - 新增配置项要同时改两侧 + 在 `main.cpp` 里解析；C 侧靠 `const_cast<char *>(stdString.c_str())` 桥接
  - **`config.c` 的初始值与 `main.cpp` 里的 `.as<T>(default)` 不一致**（如 `maxWokers` 10 vs 15、`bufferSize` 1024 vs 8192）。`main.cpp` 每次都会赋值，所以**实际生效的是 `main.cpp` 的默认值**
- **日志同样是双份 API**：C 侧 `logOutput*ConsoleCharString`（声明在 `Log.h`），C++ 侧重载 `logOutput*Console`（声明在 `Log.hpp`）。`logOutputFatalConsole` 在 `Log.c` 和 `Log.cpp` 各有一份实现，`Log.h` 未声明 C 版本，目前没有 `.c` 文件调用它。

## 内存与生命周期红线

- accept 回调把 `SocketClientInfo` 以**栈对象地址**传入（`nSocket.c:33`、`nTls.c:83`）。回调必须 `new SocketClientInfo(*clientInfo)` 堆拷贝后才能返回，否则指针悬垂。
- **明文与 TLS 的所有权模型不同，不要混用**：
  - 明文：一条连接 = 2 个任务共享 `CallbackShareInfo{init, close, timeout, mutex}`。先退出者只置 `close = true` 就返回；**观察到 `close == true` 的那一个**负责 `shutdown` + `close` 两个 fd、释放两个 info、`shareInfo` 和 `mutex`（`SocketCallback.cpp:196-214`）。不要新增第三条清理路径，也不要重复释放。
  - TLS：一条连接 = 1 个任务，没有 `shareInfo`，由 `cleanup` lambda 一次性收尾（`TlsCallback.cpp:245-280`）。
- 缓冲区必须配对：`new (std::align_val_t(64)) char[n]` ↔ `operator delete[](p, std::align_val_t(64))`。写成普通 `delete[]` 是历史上真实修过的 bug（commit `155ebee`）。
- **`CallbackShareInfo::close` 是 `std::atomic<bool>`**，转发循环在锁外读它（`SocketCallback.cpp:118,132,168`），写入侧在锁内（`:107,:223`）。改这块时保持原子性，不要退回普通 bool。
- **后端选址结果必须显式传参**：`selectBackendTarget(BackendTarget&)` 写入调用方持有的 `BackendTarget{std::string host; int port;}`，`connectSocketServer` / `connectTlsServer` 接收 `const char *host, int port`。**不要**改回写全局 `gClientHostChar` / `gClientPort` —— 那是已修掉的并发 bug（多线程会连到别的后端）。这两个全局现在只在 `main.cpp` 启动时赋值一次，已无读取点。
- 收发统一用 `MSG_NOSIGNAL`（`main.cpp:101` 已 `SIGPIPE` 忽略），保持这个约定。
- fd 判活用 `>= 0`。

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
| `pollingIntervalMs` | int | `500` | **只被 TLS 转发路径读取**（`TlsCallback.cpp:407`） |
| `readOrWriteTimeoutMs` | int | `-1` | >0 时给两端 fd 设收发超时；`<=0` 空闲连接永久占用 worker |

`config.tls`（**仅 `enable: true` 时才被读取**，其余键全部忽略）

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enable` | bool | `false` | `true` = 透传 TLS（后端也走 TLS） |
| `socketIoUseMode` | string | `none` | 非 `none` 启动即 FATAL 退出 |
| `sslIoUseMode` | string | `none` | 非 `none` 启动即 FATAL 退出 |
| `useThreadpoolAccept` | bool | `true` | TLS 握手是否交线程池 |
| `useThreadpoolSslAccept` | bool | `true` | 连接后端是否交线程池 |
| `noBlockReadOrWrite` | bool | `false` | **死配置**，从未被读取 |
| `noBlockConnect` | bool | `false` | **死配置** |
| `acceptTimeoutMs` | int | `-1` | |
| `connectTimeoutMs` | int | `-1` | 写阻塞重试的超时；`<=0` 表示不启用该超时 |
| `pollingIntervalMs` | int | `100` | `epoll_wait` 超时 |
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
| `host` | string | **必填** | `0.0.0.0`/`*` = 所有网卡，`127.0.0.1`/`localhost` = 本机，其他先 `inet_pton` 再 `gethostbyname` |
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
| `tls.sni` | string | `""` | 为空则透传客户端握手 SNI；同时用于后端证书主机名校验。`0.0.0.0` / `localhost` 会被 `isValidTlsHost` 判为无效并**告警**，此时主机名校验不生效 |
| `tls.cert` | string | `""` | **死配置**（固定用系统信任库） |

拼写错误同属对外契约，改名会破坏已有配置：`minWokers` / `maxWokers`、`gConfigTlsEnbale`。`privkey` 是规范键，`key` 只是兼容用的别名。

## 提交约定

- 单行小写祈使句，无 prefix / scope：`fix tls error`、`update cmake`、`optimize threadpool and callback`。
- 直接提交 `main`，没有 PR 流程、没有打标签。
- 注释与日志文案用中文，标识符用英文。
- 改动配置键、默认值或转发行为时，把变更同步到 `README.md` 的配置项参考表（本文件只记开发约定，配置表以 README 为准）。
