# 目录结构

## 完整布局

```
SimpleProxy-V2/
├── CMakeLists.txt              单目标构建脚本（C11 + C++17）
├── config.yml                  附带配置（明文模式示例）
├── README.md                   面向使用者
├── AGENTS.md                   面向开发者的约定与红线
├── MISTAKE.md                  已核实但未修复的缺陷
├── .clangd                     clangd 配置（include 路径必须与 CMake 展开结果一致）
├── .gitignore
├── vcpkg.json                  依赖清单（openssl / yaml-cpp）
├── document/                   本目录：技术文档
├── tlstest/                    TLS 冒烟测试材料（已 gitignore）
└── src/
    ├── main.cpp                入口：参数、配置加载校验、启动/关闭
    ├── headfile.h              统一头（所有 .c/.cpp 只 include 它）
    ├── define.h                宏：I/O 模式、日志级别、后端选择策略
    │
    ├── Platform/               跨平台适配层
    │   ├── PlatformBase.h      共享类型别名 + 平台相关常量 + 通用判定宏
    │   ├── Linux/
    │   │   ├── PlatformSocketLinux.h/.c    socket 生命周期、超时、IPv4 解析、对齐内存
    │   │   ├── PlatformErrorLinux.h/.c     errno 判定与错误文本
    │   │   ├── PlatformWaitEpoll.h/.c      事件等待（epoll 水平触发）
    │   │   ├── PlatformMutexLinux.h        互斥量（纯宏，无 .c）
    │   │   └── PlatformTimeLinux.h         本地时间（纯宏，无 .c）
    │   └── Windows/
    │       ├── PlatformSocketWindows.h/.c
    │       ├── PlatformErrorWindows.h/.c
    │       ├── PlatformWaitWsapol.h/.c    事件等待（WSAPoll）
    │       ├── PlatformMutexWindows.h      互斥量（纯宏，无 .c）
    │       └── PlatformTimeWindows.h       本地时间（纯宏，无 .c）
    │
    ├── Global/                 全局状态
    │   ├── config.h/.c         C 侧：g* 配置、rg* 运行时、char* 别名、日志互斥量
    │   └── config.hpp/.cpp     C++ 侧：std::string / std::vector / rgThreadPool
    │
    ├── Log/                    日志（C 与 C++ 各一套同名 API）
    │   ├── Log.h/.c            C 版：*ConsoleCharString
    │   └── Log.hpp/.cpp        C++ 版：*Console（char* / std::string 重载）
    │
    ├── ProtocolServer/         裸系统调用封装
    │   ├── nSocket.h/.c        明文：创建/绑定/监听/accept/connect
    │   └── nTls.h/.c           TLS：同上 + OpenSSL 上下文与握手
    │
    ├── Threadpool/             线程池
    │   ├── ThreadpoolSimple.h/.cpp          基础任务队列与 worker 管理
    │   └── ThreadpoolAutoCtrlByTime.h/.cpp  按积压量与空闲时长自动扩缩容
    │
    └── Callback/               业务层
        ├── CallbackBase.h/.cpp 防火墙判定、后端选址
        ├── SocketCallback.h/.cpp 明文连接生命周期与双向转发
        └── TlsCallback.h/.cpp   TLS 握手与 epoll 转发
```

C/C++ 代码共 **4384 行**（37 个源文件）。

## 各层职责与依赖方向

```
main.cpp
   │
   ├── Threadpool/          （纯 C++，零平台代码，只用 std::thread / std::mutex）
   │
   ├── ProtocolServer/      → 依赖 Platform/、Log/、Global/
   ├── Callback/            → 依赖 ProtocolServer/、Threadpool/、Platform/、Log/、Global/
   └── Log/、Global/         → 依赖 Platform/（互斥量、时间）
```

**依赖是单向的**：`Platform/` 不依赖任何业务层；`Threadpool/` 不依赖 `ProtocolServer/` 和 `Callback/`。唯一的"逆向"依赖是 `Callback/` 调用 `ProtocolServer/`，这是转发流程决定的。

## 命名规范

| 类别 | 规范 | 示例 |
| --- | --- | --- |
| 目录 | PascalCase 英文 | `Platform/`、`ProtocolServer/`、`Threadpool/` |
| C 头 | PascalCase 或单字小写 | `Log.h`、`nSocket.h`、`headfile.h`、`define.h` |
| C++ 头 | PascalCase + `.hpp` | `CallbackBase.hpp`、`ThreadpoolSimple.hpp` |
| C 实现 | 与头同名 + `.c` | `nSocket.c`、`Log.c` |
| C++ 实现 | 与头同名 + `.cpp` | `TlsCallback.cpp` |
| `.h` include guard | `__XXX_H__`，目录前缀可选 | `__LOG_H__`、`__GLOBAL_CONFIG_H__`、`__PLATFORM_SOCKET_H__` |
| `.hpp` guard | `#pragma once` | — |
| 平台差异宏 | `__XXX_H__` | `__N_SOCKET_H__` |
| 类型/函数/变量 | 英文 | `SocketClientInfo`、`connectSocketServer`、`rgTlsInit` |
| 宏常量 | 全大写下划线 | `CONNECT_USE_IO_NONE`、`LOG_LEVEL_DEBUG`、`SOCKET_INVALID` |
| 注释与日志文案 | 中文 | — |
| 提交信息 | 单行小写祈使句，无 prefix | `fix tls error` |

**没有 snake_case 文件名**。平台层的文件也遵守这一点：`PlatformSocketWindows.h` 而不是 `platform_socket_windows.h`。

## include 纪律

1. **每个 `.c` / `.cpp` 只 include 自己模块的那一个头**
   ```c
   #include "nSocket.h"      // nSocket.c
   #include "headfile.h"     // main.cpp（唯一例外，它就是入口）
   ```
   18 个实现文件里有 12 个是这个形态。

2. **`src/Platform/*.c` 是有意的例外，include 两个头**
   ```c
   #include "headfile.h"            // 系统头 + PlatformBase.h 提供 SOCKET_T
   #include "PlatformSocketWindows.h" // 自己模块的声明
   ```
   因为 Platform 头不能 include `headfile.h`（会无限递归），所以只能由 `.c` 自己把 `headfile.h` 拉进来。第二个 include 此时是幂等的（`headfile.h` 已经引入过），保留它是为了让"这个 .c 依赖哪个模块"保持显式可读。

3. **系统头只写在 `headfile.h` 里**，业务文件不单独 include。新增系统头加到 `headfile.h` 对应平台分支里。

4. **include 用裸文件名**（`#include "nSocket.h"` 而不是相对路径），因为 CMake 把 `src/` 下所有层都加进了 include 路径：
   ```cmake
   file(GLOB_RECURSE SUBDIRS ${PROJECT_SOURCE_DIR}/src/*)
   foreach(DIR IN LISTS SUBDIRS)
       get_filename_component(PATH ${DIR} DIRECTORY)
       file(TO_CMAKE_PATH "${PATH}" PATH)   # Windows 上 GLOB 返回反斜杠，统一成正斜杠
       include_directories(${PATH})
   endforeach()
   ```
   这会自动包含新增的 `src/Platform/`、`src/Platform/Linux/`、`src/Platform/Windows/`。

5. **`.clangd` 的 `Add` 列表必须与上面展开出的集合完全一致**，且只能逐条列（clangd 的 `Add` 不支持 glob）。当前 9 条：
   ```
   -Isrc  -Isrc/Callback  -Isrc/Global  -Isrc/Log
   -Isrc/Platform  -Isrc/Platform/Linux  -Isrc/Platform/Windows
   -Isrc/ProtocolServer  -Isrc/Threadpool
   ```
   增删 `src/` 子目录时两边都要改。

6. **`src/Platform/` 下的头是例外** —— 它们不 include 任何东西（包括 `headfile.h`），由 `headfile.h` 单向引入。原因见 [platform.md](platform.md)。

## GLOB 陷阱

`CMakeLists.txt` 用 `file(GLOB_RECURSE ...)` 收集源文件。**新增 / 删除 / 重命名源文件后必须重新执行 `cmake ..`**（或删掉 `CMakeCache.txt`），只跑 `make` / `cmake --build` 不会生效。
