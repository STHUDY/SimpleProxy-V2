# MISTAKE.md

本仓库**已核实并已修复**的缺陷，每条含成因。改动相关模块前先读，避免把同样的问题重新引入。

第 19 节是**尚未修复**的遗留项。

---

## 1. 后端 TLS 握手失败的清理代码是死代码

`src/ProtocolServer/nTls.c` `connectTlsServer()`

```c
if (sslConnErr = SSL_ERROR_NONE)   // 赋值，不是比较
```

`SSL_ERROR_NONE` 是 `0`，条件恒假，于是握手失败时的 `ERR_get_error()` / `SSL_free` / `SSL_CTX_free` / `close` 整段永不执行。`SSL_connect` 失败仍返回 `0`（成功），把未完成握手的 `SSL*` 交给 `tlsProxyWorker`。

**已修为 `!=`。** 成功路径上 `sslConnErr` 保持 `SSL_ERROR_NONE`，任何失败路径都由 `SSL_get_error()` 填入真实错误码，所以 `!= SSL_ERROR_NONE` 恰好只在失败时成立。

**成因**：赋值/比较手误，编译器不会对 `if (x = 常量)` 报警（除非开 `-Wparentheses`，且它对常量也不一定报）。这类写法要按语义而不是按"能编译"来判断。

---

## 2. `config.yml` 的私钥键名和代码不一致

代码读 `config["server"]["tls"]["privkey"]`，而仓库 `config.yml` 写的是 `key: key.pem`。于是 `config.tls.enable: true` + 附带配置，必定打 `server.tls.privkey is empty`，私钥路径为空。

**已修**：`config.yml` 改成规范键 `privkey`；同时 `main.cpp` 保留对旧键 `key` 的兼容读取（读到时打 deprecation 警告），这样已经部署了旧配置的机器升级后不会突然起不来。

**成因**：配置键没有单一来源，代码和示例各写各的。兼容别名比直接改键名安全，因为改键名会让旧配置静默失效。

---

## 3. SNI 判定是指针比较，且可能用 NULL 构造字符串

`src/Callback/TlsCallback.cpp`

```c
if (gClientTlsSniChar == "")     // 指针 vs 字符串字面量
sniStr = sni;                     // sni 可能为 NULL
```

`== ""` 实际在比地址。判"未配置 SNI"应该是 `gClientTlsSniChar == NULL || gClientTlsSniChar[0] == '\0'`。另外 `SSL_get_servername()` 在客户端没带 SNI 时返回 NULL，拿它构造 `std::string` 是 UB。

**已修**：判空改成 `NULL || [0] == '\0'`，并对 NULL 结果回退成空串。

**成因**：不崩只是因为附带配置恰好填了 `sni`，一旦删掉那行就崩。**不要用"现在没炸"推断判空是对的。**

---

## 4. 明文 accept 循环判断的是 TLS 的 I/O 模式开关

`src/ProtocolServer/nSocket.c` `listenSocketServer()`

```c
if (gConfigTlsSocketIoUseMode == CONNECT_USE_IO_NONE)   // 应为 gConfigSocketIoUseMode
```

`gConfigTlsSocketIoUseMode` 只在 `config.tls.enable: true` 时才被 `main.cpp` 赋值，明文模式下恒为 `config.c` 的初值 `0`。所以 `config.socket.ioUseMode` 配成非 `none` 根本拦不住 accept 循环，那个开关形同虚设。

**已修**：改判 `gConfigSocketIoUseMode`，并在 `main.cpp` 解析完配置后对三个 `*ioUseMode` 键做启动期 fail-fast 校验。

**成因**：复制粘贴时漏改变量名。这类"看名字就知道是笔误"的错误在 review 时最容易因为读得快而滑过去。

---

## 5. `ioUseMode` 非 `none` 时每条后端连接都失败，且没有"配置不支持"的提示

`connect()` 整段被 `gConfigSocketIoUseMode == CONNECT_USE_IO_NONE` 包住。配成 `epoll`/`select`/`poll` 时：

1. `socket()` 成功，但从不 `connect()`
2. `getsockname()` 在未连接 socket 上成功（拿到 `0.0.0.0:0`）
3. `getpeername()` 失败（`ENOTCONN`）→ 打 `Connect: getpeername failed`，返回 `-1`

表现是"每条连接都建连失败"，而不是"该 I/O 模型没实现"。

**已修**：三个 `ioUseMode` 键在 `main.cpp` 启动期就 FATAL 退出；`listenSocketServer` / `connectSocketServer` / `listenTlsServer` / `connectTlsSocketServer` / `connectTlsServer` 各自的入口也都有显式报错并返回失败。

**成因**：用"静默走不到"代替"显式拒绝"，把配置错误推迟到每条连接上，还伪装成了别的错误。

---

## 6. TLS 模式无法退出

`src/ProtocolServer/nTls.c` `closeTlsServer()`

```c
rgTlsServerRun = false;      // 只置标志，没有 shutdown / close
```

对比 `closeSocketServer()` 是老老实实 `shutdown` + `close` 了监听 fd 的。

accept 循环阻塞在 `accept()` 上，仅置标志没人读。`waitMissionDone()` 的条件是 `getMissionNumber() > 0 || getBusyThreadNumber() > 1`，常驻 accept 任务只占 1 个 busy，所以这一步会直接返回；真正的死锁在 `shutdown()` → `sthutdown()` 的 `it->thread->join()`，永久阻塞。**TLS 模式下按 `exit` 或 Ctrl+C 会卡住不退。**

**已修**：`closeTlsServer()` 补上 `shutdown()` + `close()` 并把 fd 置 `-1`。`shutdown()` 是唤醒阻塞中 `accept()` 的关键（Linux 上单靠 `close()` 不可靠），这也是明文路径一直能正常退出的原因。

**成因**：两个 close 函数是照着彼此写的，但只补了一半。`listenTlsServer()` 里的 `setsockopt` 失败分支同样只 `close` 不置 `-1`，一并修了。

---

## 7. `tls.noBlockReadOrWrite: true` 会让转发循环无法推进

`src/Callback/TlsCallback.cpp` `tlsProxyWorker()`

```c
for (int i = 0; i < eventsNumber;)
{
    int sslReadNum = SSL_read(srcSsl, buffer, bufferSize);
    if (gConfigTlsNoBlockReadOrWrite == false)
    {
        if (SSL_pending(srcSsl) == 0) { timeout = 0; i++; }   // 唯一推进点
    }
    if (sslReadNum > 0) { ...转发... }                        // 不推进
```

`i` 是循环唯一的推进条件，却被一个配置判断包住。配 `true` 时 `sslReadNum > 0` 分支里 `i` 永不递增 → 该 `for` 死循环，单条连接吃满一个 worker 且 CPU 打满。配 `false` 但 `SSL_pending() != 0` 时同样不推进。

**已修**：改成 `for (int i = 0; i < eventsNumber; i++)`，删掉 `SSL_pending()` 那层。epoll 是**水平触发**，一次事件只做一次 `SSL_read`/`SSL_write` 即可，剩余数据会再次触发 `EPOLLIN`，不需要手工排空 —— 原代码想用 `SSL_pending()` 做的事本来就不必做。

**后果**：`config.tls.noBlockReadOrWrite` 现在彻底没人读了，已退化为死配置。

**成因**：手写索引循环 + 散落在多个分支里的 `i++`，是 `for` 循环最经典的坏模式。**这种循环一律用 `i++` 写在 for 头里。**

---

## 8. TLS 握手成功后只拷了 4 字节地址

`src/Callback/TlsCallback.cpp`

```c
memcpy(&tlsClientInfo.addr, &aConnectInfo->addr, sizeof(aConnectInfo->addr_len));
tlsClientInfo.addr_len = sizeof(aConnectInfo->addr);
```

`sizeof(socklen_t)` = 4，目标 `struct sockaddr_in` = 16 字节；`addr_len` 反而被设成 16。传给 `tlsServerCallback` 的客户端地址只有 `sin_family` + `sin_port` 正确，`sin_addr` 全是 0xff 垃圾。`ip_str` 走另一条 `strncpy` 所以正确，防火墙判断不受影响。

**已修**：`memcpy` 长度用 `sizeof(...addr)`，`addr_len` 直接沿用来源的值。

**成因**：`addr_len` 与 `addr` 名字太像，长度表达式写成了同名字段。**`memcpy` 的第三参数永远是目标/源类型的大小，不是"长度字段"的名字。**

---

## 9. 后端选择用了非线程局部 static

`src/Callback/CallbackBase.cpp`

```c
static std::string selectedHost;                          // 非 thread_local
selectedHost = gClientHostList[selectedIndex];
gClientHostChar = const_cast<char *>(selectedHost.c_str());
gClientPort    = gClientPortList[selectedIndex];
```

`selectBackendTarget()` 被每条连接的 `socketCreateProxyMission` / `tlsCreateProxyMission` 在各自 worker 线程里调用，于是多线程并发写同一个 `std::string`，同时 `gClientHostChar` 指向的缓冲区可能正在被重新分配 —— C 侧的 `connectSocketServer()` 读它时是数据竞争 + 悬垂。`gClientPort` 同样是共享全局，多后端不同端口时会连到**别的后端的端口**。

**已修**：改成 `selectBackendTarget(BackendTarget &target)` 把结果写进调用方持有的对象，`connectSocketServer` / `connectTlsServer` 改为接收 `const char *host, int port`。选址与建连之间不再有任何共享可变状态。`gClientHostChar` / `gClientPort` 现在只在 `main.cpp` 启动时赋值一次，已无读取点。

**成因**：原注释"需要复制到静态或全局"说明作者意识到有拷贝需求，但选错了存储期 —— `static` 在这里是"全局可变"，`thread_local` 才对应"每线程一份"。而真正的正解是根本不共享：**让数据跟着调用链走，不要放进全局。**

---

## 10. `close` 标志非原子，且在锁外读

`src/Callback/CallbackBase.hpp` 曾是普通 `bool close;`，但 `socketProxyWorkerSingle()` 在**释放锁之后**读它（循环顶部与两处 `EAGAIN` 分支），写入侧却在锁内。

**已修**：改为 `std::atomic<bool>`。`CallbackShareInfo` 只通过指针传递、从不按值拷贝，所以不可拷贝不影响它。

**成因**：写入加锁、读取不加锁，锁的意图（建立 happens-before）根本没实现。**"共享标志要么全用原子、要么读写都在同一把锁内"，不能混。**

---

## 11. 两处 fd 判活用 `> 0`

- `src/ProtocolServer/nSocket.c` `listenSocketConnectIoNone()` —— `if (clientFd > 0)`：`accept()` 返回 0（合法 fd）时被当作失败，去走 errno 分支
- `src/Callback/SocketCallback.cpp` —— `if (aConnectInfo->fd > 0)`：客户端 fd 为 0 时跳过 `shutdown`+`close`，泄漏

**已修**：两处都改成 `>= 0`。同文件其他判活本来就是 `>= 0`。

**成因**：手误。**fd 判活一律 `>= 0`，`-1` 才是错误值。**

---

## 12. 附带配置会让后端证书主机名校验静默失效

`isValidTlsHost()` 排除 `"0.0.0.0"` 和 `"localhost"`（这是对的，SNI 本来就不能是地址），而 `config.yml` 的 `sni` 恰好填 `0.0.0.0`。于是 `connectTlsServer()` 里两条分支都不成立 → 既不 `SSL_set_tlsext_host_name()` 也不 `SSL_set1_host()`。链校验还在（`SSL_VERIFY_PEER`），但**主机名校验完全没开**，拿任意一张该 CA 签的证书都能冒充后端。

**已修**：`config.yml` 的 `sni` 留空（走客户端 SNI 透传）；代码侧在 `sni` 被 `isValidTlsHost` 拒绝、或压根没有可用 SNI 时**打告警**，不再让安全降级悄无声息。

**成因**："把配置项解析出来"和"这个值真的生效了"是两件事，被过滤掉的配置值原本没有任何反馈。**任何被静默丢弃的安全相关配置都必须告警。**

---

## 13. 系统信任库加载失败只 warn，函数照样返回 true

`src/ProtocolServer/nTls.c` `configureClientContext()`

```c
if (!SSL_CTX_set_default_verify_paths(ctx))
{
    logOutputWarnConsoleCharString("Warning: ... verification will be disabled");
}
return true;     // 加载失败也是 true
```

**已修**：改成打 error 并 `return false`，`connectTlsServer()` 会清理后返回 `-1`（配合第 1 条，这个 `-1` 现在才真正生效）。

**成因**：告警文案说"校验会被禁用"，但返回 `true` 让调用方以为成功 —— 实际效果是 `SSL_VERIFY_PEER` 生效了却因为没有 trust store 而对所有后端握手失败，而握手失败又被第 1 条吞掉，最终表现为"连上了但没有数据"。**函数返回成功就必须真的成功。**

---

## 14. 写阻塞与空闲超时的单位/符号都错了

`src/Callback/TlsCallback.cpp` `tlsProxyWorker()` 里 `timeout` 按**秒**累加（`PollTimeSeconds`），却拿去和**毫秒**的配置项比：

```c
timeout += PollTimeSeconds;                                  // 秒
if (timeout > gConfigTlsConnectTimeoutMs)                    // 毫秒，且默认值是 -1
```

`x > -1` 对任何非负 `x` 成立 → `connectTimeoutMs` 未配置（默认 -1）时，TLS 写一旦返回 `SSL_ERROR_WANT_WRITE`，即使 `select()` 成功可写也会立刻断连，一次都不重试。同一处 `readOrWriteTimeoutMs` 的比较（`timeout > gConfigTlsReadOrWriteTimeoutMs`）也有同样的单位错，只是没有符号错那么显眼。

附带两个问题：那个 `select()` 等的是 `activeFd`（**源**端），而真正需要等可写的是**目标**端；以及这里读的是明文配置项 `gConfigSocketPollingIntervalMs`。

**已修**：`timeout` 统一按毫秒累加（`pollTimeMs`），两处比较都改成 `> 0` 才启用且同单位；`select()` 改等目标 fd（`isAtoB ? bSocket : aSocket`）。附带配置原本靠 `connectTimeoutMs: 5000` 掩盖了这个问题。

**成因**：`timeout` 变量名没带单位，两个不同量纲的值被塞进同一个变量。**跨配置项做时间比较前，先确认两边同单位，并把单位写进变量名。**

---

## 15. 日志时间戳与行缓冲不是线程安全的

- `src/Log/Log.c` —— `static char time_str[100]` + `localtime()`（返回共享静态 `struct tm`）
- `src/Log/Log.c` `writeToFile()` —— `static char outputMsg[512]`，且 `snprintf` 在 `pthread_mutex_lock` **之前**执行，锁只护住了 `fopen`/`fprintf`/`fflush`
- `src/Log/Log.cpp` —— 同样用 `static char time_str[100]`

`Log.c` 原注释已经承认了（"此处简单起见，使用静态缓冲区可能冲突"）。多 worker 并发打日志时会出现时间戳错乱或日志行内容串接。

**已修**：`localtime()` → `localtime_r()`；时间戳与行缓冲改为调用方/栈上缓冲；在 `config.h`/`config.c` 新增 `rgLogOutputMutex`，控制台 `printf`/`cout` 整行加锁输出（C 侧 5 个函数各自加锁，C++ 侧收敛到 `outputConsole()` 辅助函数）。

**成因**："为了少一次分配"引入 `static` 缓冲，省下的开销远小于排查日志错乱的成本；锁的边界也只圈了一半。**日志的无锁优化是最后一个该做的优化。**

---

## 16. 任务出队顺序不一致

worker 消费用 `front()` + `pop_front()`（FIFO，`ThreadpoolSimple::assignMissions` 路径），而丢弃路径 `popMission()` / `getAndPopMission()` 用 `back()` + `pop_back()`（LIFO）。`errorCallback(0x0002)` 走的正是 LIFO。

**影响**：某任务抛异常触发 mission_drop 时，丢掉的是**最后入队**的那个，不是刚排队的那个。当前两条转发链路的入队顺序恰好和直觉相反，容易误判"丢的是哪条连接"。

**未修**（见第 19 节）。

---

## 17. `headfile.h` 没有 include guard，且缺 `<sstream>`

`src/headfile.h` 全文没有 `#ifndef`。它能被重复展开完全靠下游 `nSocket.h` / `nTls.h` / `config.h` / `Log.h` / `define.h` 的 `#ifndef` 和各 `.hpp` 的 `#pragma once` 把递归掐断。

同时 `TlsCallback.cpp` 用了 `std::ostringstream`，`headfile.h` 里没有 `<sstream>`，此前靠传递包含编译通过。

**已修**：`<sstream>` 补进 `headfile.h`。

**未修**：include guard 本身仍然缺失（见第 19 节）。新增头文件必须自带 guard 或 `#pragma once`，否则会在这个递归链上炸成无限递归。

---

## 18. `.clangd` 与实际目录不符

`-Isrc/Handle` —— `src/` 下没有 `Handle` 目录；缺 `-Isrc/Callback` —— 该目录存在且 `headfile.h` 依赖它。另外 `build/` 里没有 `compile_commands.json`，`CompilationDatabase: build/` 也无从生效。

**未修**（见第 19 节）。后果是编辑器跨模块跳转和补全会缺符号，容易误以为是自己 include 写错了。

---

## 19. 尚未修复的遗留项

以下都是核实过但**没有**动的，改动相关代码时请留意：

- **第 16 条** 任务出队 FIFO/LIFO 混用
- **第 17 条** `headfile.h` 仍无 include guard
- **第 18 条** `.clangd` 仍过期
- `config.c` 的默认值全是死值：`main.cpp` 对每个键都会 `as<T>(default)`，`config.c` 的初始值一律被覆盖，但两者并不一致 —— `maxWokers` 10 vs 15、`pollingIntervalMs`（socket）100 vs 500、`pollingIntervalMs`（threadpool）1000 vs 500、`maxBacklog` 5 vs 128、两个 `bufferSize` 1024 vs 8192、`useThreadpoolSslAccept` false vs true。**读 `config.c` 推断运行时行为会得到错误答案，改默认值只改 `config.c` 不生效。**
- 死配置（解析了但代码里从未读取）：`config.socket.noBlockReadOrWrite`、`config.socket.noBlockConnect`、`config.tls.noBlockReadOrWrite`、`config.tls.noBlockConnect`、`client.tls.hostname`、`client.tls.cert`
- 交叉使用：`config.socket.pollingIntervalMs` 只被 TLS 转发路径读取（写阻塞时的 `select()` 超时）；明文路径两个 `pollingIntervalMs` 都不读
- 从未使用的成员：`CallbackShareInfo::timeout`（只在 `SocketCallback.cpp` 赋 0）、`rgSslAcceptTimeoutMs`、`ThreadpoolAutoCtrlByTime::thread_pool_simple` / `mission_dorp_callback` / `submit_count`（只自增无人读）
- `logOutputFatalConsole(const char*)` 在 `Log.c` 和 `Log.cpp` 各有一份实现（分别是 C 和 C++ 链接），`Log.h` 没有声明 C 版本。目前没有 `.c` 文件调用它，所以没暴露 —— 从 C 代码里调它会得到隐式声明。
