# MISTAKE.md

本仓库**已核实、但当前代码里仍然存在**的缺陷，每条含成因与证据。改动相关模块前先读，避免把同样的问题重新引入。

已修复的缺陷不再收录。它们的成因分析保留在 git 历史里，需要追溯时用 `git show <commit>` 或 `git log -S`。

---

## 1. `client.tls.sni` 写成裸键会被读成字符串 `"null"`

`config.yml:55`

```yaml
    sni: # SNI扩展，留空则透传客户端握手SNI；...
```

这是**裸键**，YAML 里等价于 null。而 yaml-cpp 的 `as<std::string>(fallback)` 对 null 节点有专门分支，**返回字面量 `"null"`，不是 `fallback`**（`include/yaml-cpp/node/impl.h`）：

```cpp
template <typename S>
struct as_if<std::string, S> {
  std::string operator()(const S& fallback) const {
    if (node.Type() == NodeType::Null)
      return "null";                    // 忽略 fallback
    if (node.Type() != NodeType::Scalar)
      return fallback;
    return node.Scalar();
  }
};
```

于是 `gClientTlsSniString = "null"`，`gClientTlsSniChar` 既非 `NULL` 也非 `'\0'`，后续每一步都走错分支：

1. `TlsCallback.cpp:142` 的判空不成立 → 不走 SNI 透传，`sniStr = "null"`
2. `nTls.c:544` `isValidTlsHost("null")` 为真（非空、不是 `0.0.0.0` / `localhost`）→ **不打 WARN**
3. `nTls.c:549` `SSL_set_tlsext_host_name(ssl, "null")` → 给后端发了假 SNI
4. `nTls.c:558` `SSL_set1_host(ssl, "null")` → 强制要求后端证书对 `null` 有效

**表现**：TLS 模式下每条连接的后端握手都失败（X509 主机名不匹配），而且没有任何告警提示原因。

**规避**：要留空必须写 `sni: ""`（显式空串）。显式空串走 `node.Scalar()` 分支拿到 `""`，才会真正触发客户端 SNI 透传。

**受影响的其他键**（都要小心裸键）：

| 键 | 裸键读到的值 | 后果 |
| --- | --- | --- |
| `client.tls.sni` | `"null"` | **静默功能失效**，见上 |
| `client.tls.hostname` | `"null"` | 死配置，无影响 |
| `client.tls.cert` | `"null"` | 死配置，无影响 |
| `server.tls.cert` | `"null"` | 随后被 `std::filesystem::exists("null")` 判为不存在 → 清空 + ERROR |
| `server.tls.privkey` | `"null"` | 同上 |
| `config.log.filePath` | `"null"` | 仅 `log.file: true` 时读；路径不存在 → 降级为不写文件 + WARN |

**非字符串类型没有这个问题**：`as_if<T, S>`（`int` / `bool` 走这条）在键缺失或解码失败时都会正确回落到 `fallback`。

**成因**：「解析出配置值」和「这个值是不是我以为的那个值」是两件事。**给 yaml-cpp 传字符串时，null 节点不会回落到默认值。** 要么在配置里写显式空串，要么在代码里把 `"null"` 归一成空串 —— 现在的代码两者都没做。

---

## 2. 任务出队顺序不一致

`src/Threadpool/ThreadpoolSimple.cpp`

worker 消费用 `front()` + `pop_front()`（`:126-127`，FIFO），而丢弃路径 `popMission()` / `getAndPopMission()` 用 `back()` + `pop_back()`（`:284-285`、`:300-301`，LIFO）。`errorCallback(0x0002)` 走的正是 LIFO。

**影响**：某任务抛异常触发 mission_drop 时，丢掉的是**最后入队**的那个，不是刚排队的那个。当前两条转发链路的入队顺序恰好和直觉相反，容易误判"丢的是哪条连接"。

**成因**：同一个队列有两种出队语义，且没有注释说明哪一种是本意。**队列的出队语义必须全局唯一。**

---

## 3. `headfile.h` 没有 include guard

`src/headfile.h` 全文没有 `#ifndef`，也没有 `#pragma once`。它能被重复展开完全靠下游 `nSocket.h` / `nTls.h` / `config.h` / `Log.h` / `define.h` 的 `#ifndef` 和各 `.hpp` 的 `#pragma once` 把递归掐断。

**风险**：新增头文件一旦忘了自带 guard 或 `#pragma once`，就会在这条递归链上展开成无限递归。编译期报错通常指向毫不相干的位置。

**成因**：靠下游兜底来终止递归是隐式契约，没有任何地方声明它。**每个头文件都必须自己终结自己。**

---

## 4. `src/` 子目录增删后必须同步 `.clangd`

`.clangd` 的 `Add` 列表和 `CMakeLists.txt` 里 `file(GLOB_RECURSE SUBDIRS src/*)` + `get_filename_component(... DIRECTORY)` 展开出来的 include 路径是**同一件事的两份声明**：CMake 自动跟着 `src/` 走，`.clangd` 不会。

CMake 当前实际添加的是 `src` 加全部 5 个子目录（`Callback` / `Global` / `Log` / `ProtocolServer` / `Threadpool`）。`.clangd` 里的 `Add` 必须与这个集合完全一致，且**只能用目录名，不能用通配符**（clangd 的 `Add` 不支持 glob）。

新增 `src/` 子目录时要同时做两件事：把头文件按裸文件名 include（依赖 CMake 自动加的 include 路径），并往 `.clangd` 里补一条对应的 `-I`。

**成因**：目录增删只改了 CMake 一侧，工具配置靠人记。**include 路径在仓库里有两份声明，改一处必须改另一处。**

---

## 5. 其他遗留项

以下都是核实过、当前仍然存在的：

- **`config.c` 的默认值全是死值**：`main.cpp` 对每个键都会 `as<T>(default)`，`config.c` 的初始值一律被覆盖，但两者并不一致 —— `gConfigThreadpoolMaxWorkers` 10 vs 15、`gConfigSocketPollingIntervalMs` 100 vs 500、`gConfigThreadpoolPollingIntervalMs` 1000 vs 500、`gServerSocketMaxBacklog` 5 vs 128、`gServerSocketBufferSize` / `gClientSocketBufferSize` 1024 vs 8192、`gConfigTlsUseThreadpoolSslConnect` false vs true。**读 `config.c` 推断运行时行为会得到错误答案，改默认值只改 `config.c` 不生效。**
- **死配置**（解析了但代码里从未读取，已逐个确认非 config 文件中零引用）：`config.socket.noBlockReadOrWrite`、`config.socket.noBlockConnect`、`config.tls.noBlockReadOrWrite`、`config.tls.noBlockConnect`、`client.tls.hostname`、`client.tls.cert`。
- **交叉使用**：`config.socket.pollingIntervalMs` 只被 TLS 转发路径读取（`TlsCallback.cpp:425`，写阻塞时 `select()` 的超时）；明文路径两个 `pollingIntervalMs` 都不读。
- **从未使用的成员**：`CallbackShareInfo::timeout`（`CallbackBase.hpp:9`，只在 `SocketCallback.cpp:49` 赋 0）、`rgSslAcceptTimeoutMs`（`config.c:58`，零引用）、`ThreadpoolAutoCtrlByTime::thread_pool_simple` / `mission_dorp_callback`（各只有声明那一处）、`submit_count`（只有声明和 `submit_count++`，无人读）。
- **重复符号**：`logOutputFatalConsole(const char*)` 在 `Log.c:59`（C 链接）和 `Log.cpp:67`（C++ 链接）各有一份实现，`Log.hpp:4` 声明了 C++ 版而 `Log.h` 没有声明 C 版。目前没有 `.c` 文件调用它，所以没暴露 —— 从 C 代码里调它会得到隐式声明。
