# 架构与调用链

## 进程模型

单进程、单线程主循环 + 线程池。所有网络 I/O 与业务逻辑都在 worker 线程里跑，主线程只负责启动、读配置、等退出信号。

```
main()
 ├─ 初始化：信号处理、互斥量、WSAStartup、rlimit、YAML 解析与校验
 ├─ 初始化监听：initTlsServer() 或 initSocketServer()
 ├─ rgThreadPool.init()                      启动自动扩缩容 manager（常驻任务 1/2）
 ├─ rgThreadPool.submitMission(listenerCallback)  提交 accept 循环（常驻任务 2/2）
 └─ 阻塞在 std::cin >> cmd                    输 exit 回车或 Ctrl+C 退出
      └─ 关监听 fd → waitMissionDone() → shutdown() → 释放 TLS 资源
```

`headfile.h` 里 `PlatformMutex` 的两个全局互斥量在 `main()` 第一行就 `NET_MUTEX_INIT`，因为紧接着的每一步都会打日志。

## 两条转发链路

### 明文链路

一条连接 = **2 个 worker**，各负责一个方向，共享一个 `CallbackShareInfo`。

```
main.cpp
 └─ initSocketServer()                                        nSocket.c     socket/bind/listen
 └─ rgThreadPool.submitMission(socketListenerCallback)
     └─ socketListenerCallback()                              SocketCallback.cpp
         └─ listenSocketServer(socketServerCallback)          nSocket.c
             └─ listenSocketConnectIoNone()                   nSocket.c   accept 循环【常驻】
                 └─ socketServerCallback(&clientInfo)                        栈对象地址
                     ├─ new SocketClientInfo(*clientInfo)     堆拷贝（必须）
                     ├─ new SocketClientInfo                   给后端用
                     └─ pushMission(socketCreateProxyMission)  或同步调用
                         ├─ isIpAllowed(ip_str)                CallbackBase.cpp   防火墙
                         ├─ selectBackendTarget(backend)        CallbackBase.cpp   多后端选址
                         ├─ connectSocketServer(...)           nSocket.c          连后端
                         ├─ new CallbackShareInfo + new std::mutex
                         ├─ pushMission(socketProxyWorkerSingle, a→b)   方向 1
                         └─ pushMission(socketProxyWorkerSingle, b→a)   方向 2
```

### TLS 链路

一条连接 = **1 个 worker**（`epoll`/`WSAPoll` 同时监听两端 fd）。握手阶段短暂占用 1~2 个 worker。

```
main.cpp
 └─ initTlsServer()                                           nTls.c
 └─ rgThreadPool.submitMission(tlsListenerCallback)
     └─ tlsListenerCallback()                                 TlsCallback.cpp
         └─ listenTlsServer(tlsSocketUpgradeCallback, tlsServerCallback)
             └─ listenSocketConnectIoNone()                   nTls.c   accept 循环【常驻】
                 └─ tlsSocketUpgradeCallback(&clientInfo, tlsCallback)
                     ├─ new SocketClientInfo(*clientInfo)
                     └─ pushMission(tlsSocketUpgradeTlsAccept)  或同步调用
                         ├─ createContext(true) + configureServerContext()   载入代理证书
                         ├─ SSL_accept()                        客户端握手
                         └─ tlsServerCallback(&tlsClientInfo)
                             ├─ new TlsClientInfo(*tlsClientInfo)  ×2
                             └─ pushMission(tlsCreateProxyMission)  或同步调用
                                 ├─ isIpAllowed()                 防火墙
                                 ├─ SSL_get_servername()           SNI 透传
                                 ├─ connectTlsServer()             nTls.c
                                 │   ├─ connectTlsSocketServer()   TCP 连接
                                 │   ├─ configureClientContext()  信任库（含 client.tls.cert）
                                 │   ├─ SSL_set_tlsext_host_name()  SNI
                                 │   ├─ SSL_set1_host()            主机名校验
                                 │   └─ SSL_connect()              后端握手
                                 └─ pushMission(tlsProxyWorker)    单任务
                                     └─ netWaitSetWait() 循环：SSL_read → SSL_write
```

## 线程模型

### 常驻任务

| 任务 | 说明 |
| --- | --- |
| 自动扩缩容 manager | `ThreadpoolAutoCtrlByTime::managerThreadpool()`，循环间隔 `pollingIntervalMs` |
| accept 循环 | 阻塞在 `accept()`，直到 `closeXxxServer()` 先 `shutdown` 再 `close` 唤醒 |

### 每连接的 worker 占用

| 模式 | 握手阶段 | 转发阶段 |
| --- | --- | --- |
| 明文 | 0（同步或走 accept 任务） | **2** |
| TLS | 1（`SSL_accept`）+ 1（`SSL_connect`） | **1** |

### 容量换算

`setMin/setMaxThreadNumber` 内部各 `+1`，`init()` 又 `setPoolSize(min_thread_number + 1)`，所以：

- 实际初始 worker = **`minWokers + 2`**
- 实际上限 = **`maxWokers + 1`**
- 可用连接数还要再扣掉 2 个常驻任务

明文每连接吃 2 个，所以 **`maxWokers >= 2 × 预期最大并发连接数`** 是经验下限。

容量不足的日志信号：`exec_mission error`（任务被丢弃）、`create_worker error`。

### 自动扩缩容

`managerThreadpool()` 每轮读 `poolSize / busy / free / pending`，然后：

- `poolSize < min` 或 `> max` → 直接纠正到边界
- `pendingMissions > freeThreads`（有积压）→ 扩容，缺口 = `busy + pending - poolSize`
  - `stepAddThreadNumber > 0`：按步长，但不超实际缺口
  - `<= 0`：按 `pendingMissions / 2`，至少加 1
- 有积压时**不进入缩容逻辑**（避免刚扩就缩）
- 距上次调整超过 `clearThreadTimeMs` 且有空闲 → 按 `idle / max(pending,1)` 缩容

`shutdown()` 内部会再调一次 `waitMissionDone()`。

## 连接生命周期与内存所有权

### 跨 C/C++ 边界的指针规则

accept 回调把**栈上 `SocketClientInfo` 的地址**传给回调（`nSocket.c` / `nTls.c` 里构造后立即传），回调**必须 `new` 出堆拷贝**才能返回，否则指针悬垂。

```c
SocketClientInfo clientInfo;                       // accept 循环的栈对象
memset(&clientInfo, 0, sizeof(clientInfo));
clientInfo.fd = clientFd;
...
callback(&clientInfo);                             // 传地址
```

### 明文：两 worker 共享一个 `CallbackShareInfo`

```c
typedef struct CallbackShareInfo {
    bool             init;     // 首次进入的 worker 负责设超时
    std::atomic<bool> close;   // 谁先退出谁置 true
    float            timeout;  // 从未被读取（遗留字段）
    std::mutex      *mutex;    // 堆上的互斥量
} CallbackShareInfo;
```

`close` 是 `std::atomic<bool>`：转发循环在锁外读它，写入侧在锁内。**读用原子、写在锁内**这个组合是靠原子操作的顺序保证 happens-before 的，不能退回普通 `bool`，也不能把读挪进锁内。

清理协议（`SocketCallback.cpp:207-225`）：

1. 先退出的 worker：置 `shareInfo->close = true`（在锁内），解锁返回，**不释放任何东西**
2. 后退出的 worker：加锁发现 `close == true` → 由它负责
   `netShutdownBoth(aSocket)` / `netShutdownBoth(bSocket)` / `netSocketClose(aSocket)` / `netSocketClose(bSocket)` / `delete aConnectInfo` / `delete bConnectInfo` / `delete shareInfo` / 解锁后 `delete mutex`

**只有这一条清理路径**，不要新增第三条，也不要让两个 worker 都释放。

### TLS：单任务，`cleanup` lambda 一次性收尾

没有 `shareInfo`，因为只有一个 worker 持有两端。`cleanup()` 负责：销毁 wait set、释放两个缓冲、`SSL_shutdown` + `SSL_free` + `SSL_CTX_free` 两端 SSL、关两个 fd、`delete` 两个 info。握手未完成、缓冲分配失败、epoll 创建失败都在开头直接 `cleanup(); return;`。

### 转发缓冲区

64 字节对齐（缓存行），两平台都走 `netAlignedAlloc(size, 64)` / `netAlignedFree(ptr)`：

- Linux `posix_memalign`
- Windows `_aligned_malloc`

**不用 `new (std::align_val_t(64)) char[]`** —— GCC 正常，但 MSVC 的过对齐数组 new 与 `operator delete[](p, align_val_t)` 配对有问题（C2956）。而且 `posix_memalign`/`_aligned_malloc` 都不要求 size 是 alignment 的整数倍，而 `bufferSize` 是用户可配的。

**分配失败必须判空**：`netAlignedAlloc` 返回 NULL，不是抛异常。`SSL_read`/`recv` 拿到 NULL 指针配非零长度就是访问违例。

## 收发约定

- 统一 `SOCKET_SEND_FLAGS`（POSIX 是 `MSG_NOSIGNAL`，Windows 是 0 —— Winsock 的 `send` 不触发 SIGPIPE）
- `start` 时在 POSIX 上 `signal(SIGPIPE, SIG_IGN)`；Windows 上没有这个信号，跳过
- 明文路径阻塞在 `recv`，超时语义由 `SO_RCVTIMEO` 提供；`netIsWouldBlock()` 在 Windows 上**同时接受 `WSAEWOULDBLOCK` 和 `WSAETIMEDOUT`**，因为 Windows 把套接字超时报成后者而不是 POSIX 的 `EAGAIN`
- TLS 路径用 `netWaitSetWait` 等待，epoll/WSAPoll 都是水平触发，一次事件只做一次 `SSL_read`/`SSL_write`，剩余数据会再次触发通知，**不需要 `SSL_pending()` 手工排空**

## 多后端选址

`selectBackendTarget(BackendTarget &target)` 把结果写进**调用方持有的对象**，再按值传给 `connectSocketServer` / `connectTlsServer`。选址与建连之间没有任何共享可变状态。

两种策略（`gClientRoundRobinMutex` 保护）：

- `roundRobin`（默认）：循环索引
- `random`：`rand() % n`，并尽量避开上一次用过的索引

## 防火墙

`isIpAllowed(ip_str)` 在 accept 之后、连后端之前执行：

1. `banIps` 命中即拒（优先级最高）
2. `allowedIps` 为空 → 放行；非空 → 只放行命中项
3. 匹配是**完整字符串精确比较**，没有 CIDR / 通配符 / 前缀
4. 被拒时打 `SECURITY: Access denied`

判在前面的意义：不占用后端连接数，也不消耗线程池 worker。
