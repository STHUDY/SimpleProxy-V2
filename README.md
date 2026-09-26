# SimpleProxy-V2

C/C++17 从零实现的 TCP / TLS 端口转发代理。不含任何第三方框架，只依赖 `libyaml-cpp`（配置解析）和 `OpenSSL`（TLS），单 CMake 目标 `SimpleProxy`，单可执行文件。

**仅支持 Linux**（直接依赖 `unistd.h` / `sys/epoll.h` / `sys/socket.h` / `sys/resource.h`）。

## 特性

- **明文转发**：客户端连接经代理连到后端，一条连接 2 个 worker 各负责一个方向
- **TLS 转发**：代理两端各做一次握手（对客户端 `SSL_accept`、对后端 `SSL_connect`），握手后转发明文载荷
- **多后端**：后端 `host` / `port` 支持数组，`roundRobin`（默认）或 `random` 选址
- **IP 黑白名单**：`banIps` 优先，`allowedIps` 非空即白名单
- **自动扩缩容线程池**：一个常驻 manager 线程按积压任务量和空闲时长调整 worker 数量
- **分级日志**：5 个级别，控制台 ANSI 彩色输出，可选写文件，多线程整行加锁
- **地址解析**：`0.0.0.0` / `*` / `127.0.0.1` / `localhost` 走短路，其余先 `inet_pton` 再 `gethostbyname`（IPv4）

---

## 优势

面向的场景是"把一个后端安全地暴露出去，顺带做负载均衡和访问控制"，在这个定位上比通用代理更省事。

### 部署简单

- **单可执行文件 + 单个 YAML**，没有运行时依赖、没有插件系统、没有配置模板语言。拷过去 `./SimpleProxy -c config.yml` 就起来了，容器里扔进去就能用。
- **依赖只有三个**：`libyaml-cpp`、`OpenSSL`、`pthread`。对比 nginx 还要 Lua/正则库那一套、HAProxy 还要编译器和运行时版本对齐，审计和换机器的成本都低得多。
- **纯转发，不解析应用层协议**。不识别 HTTP / SSH / 数据库协议，代理本身就没有"某个协议解析错了"这类故障面，也不用为了升级后端协议而重启代理。

### TLS 能力比通用反代更贴合"换后端"这个需求

- **两端独立握手**：对客户端 `SSL_accept`、对后端 `SSL_connect`，两端证书链、协议版本、密码套件可以各自独立配置。既能对外提供一个统一证书，又能连到同样跑 TLS 的内网后端——stunnel 之类的纯 TCP 透传做不到对后端握手，nginx 反代还得单独配上游 `proxy_ssl_*`。
- **客户端 SNI 透传**：`sni` 留空时代理把客户端握手带来的 SNI 原样发给后端。多租户 / CDN / 同证书多域名场景下，后端仍能按主机名分流。
- **后端证书强制校验**：`SSL_VERIFY_PEER` + 系统信任库，并对 SNI 做主机名校验。配置被判定无效时会**显式告警**，不会悄悄降级成"只验链不验主机名"。

### 控制能力是内建的，不是外挂

- **IP 黑白名单前置到连后端之前**：被拒的连接根本不会占用后端连接数，也不会消耗线程池 worker。
- **多后端负载均衡**：`roundRobin` / `random` 两种策略，host/port 一一对应，顺手就能把几个实例挂上去。
- **超时是分层可配的**：监听 socket、后端建连、客户端握手、转发收发、连接空闲各自独立，不会出现"改一个超时把另一个也改了"。

### 工程实现上的几个刻意选择

- **TLS 转发用 1 个 worker + `epoll` 同时监听两端 fd**，明文转发用 2 个 worker 各管一个方向。前者把每连接的 worker 占用减半。
- **后端选址结果按值往下传**：`selectBackendTarget()` 写入调用方持有的对象，再传给建连函数，选址和建连之间没有任何共享可变状态——多后端并发时不会连到别的后端的端口。
- **转发缓冲区 64 字节对齐**（`new (std::align_val_t(64))`），且分配/释放严格配对；`recv` / `send` 统一带 `MSG_NOSIGNAL` 并在启动时 `SIG_IGN` 掉 `SIGPIPE`。
- **启动期 fail-fast**：`ioUseMode` 非 `none`、`server.host` 为空、`server.port <= 0`、`client.host` / `client.port` 为空或个数不匹配、YAML 语法错误——这些都在启动时报错退出，不会带着错误配置跑起来再在每条连接上重复失败。证书 / 私钥文件不存在同样在启动时立刻报 ERROR 并清空路径，而不是等到第一条连接才暴露。
- **退出路径经过专门设计**：关闭监听 fd 时先 `shutdown` 再 `close`，用来唤醒阻塞在 `accept()` 上的线程，否则线程池 `join()` 会永久卡死。`exit` 回车和 Ctrl+C 都能干净退出。
- **日志线程安全**：时间戳用 `localtime_r` + 栈上缓冲，控制台和文件输出都整行加锁，多 worker 并发打日志不会出现时间戳错乱或行内容串接。
- **端口、超时、线程数、日志全部有配置项**，调参不需要改代码；启动时还会自动把 `RLIMIT_NOFILE` 提到 65536（受 `rlim_max` 限制）。

> 这些都是设计取向，不代表无代价。并发上限受线程池容量约束（见下方「已知限制」的容量换算），且 `ioUseMode` 目前只实现了 `none`。

---

## 环境依赖

三个 `find_package` 在 `CMakeLists.txt` 里都是 `REQUIRED`，缺任意一个 configure 就会失败：

```bash
sudo apt install build-essential cmake libyaml-cpp-dev libssl-dev
```

- `Threads`（pthread）
- `yaml-cpp` —— 配置解析
- `OpenSSL` —— `SSL` + `Crypto`

> 仓库里的 `vcpkg.json` / `vcpkg-configuration.json` 只是依赖清单（`openssl`、`yaml-cpp`），Linux 构建走系统包，不经过 vcpkg。

## 编译

**默认构建类型是 Debug（`-O0 -g`）**。任何时延 / 吞吐相关的结论都必须显式用 `Release`（`-O3 -DNDEBUG -funroll-loops -ftree-vectorize`）。

Debug：

```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

Release：

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

可用的构建类型：`Debug` / `Release` / `RelWithDebInfo` / `MinSizeRel`。

> **GLOB 陷阱**：`CMakeLists.txt` 用 `file(GLOB_RECURSE ...)` 收集源文件。新增 / 删除 / 重命名源文件后**必须重新执行 `cmake ..`**（或删掉 `CMakeCache.txt`），只跑 `make` 不会生效。

## 运行

```bash
./build/SimpleProxy [-c config.yml]
```

- `-c <file>` 指定配置文件，默认 `./config.yml`
- `-h` / `--help` 打印用法
- 启动时读取配置、尝试把 `RLIMIT_NOFILE` 提升到 `65536`（受 `rlim_max` 限制，失败只打 WARN）
- 主线程阻塞在 `std::cin`，**输入 `exit` 回车或按 Ctrl+C 优雅退出**：关监听 fd → 等任务排空 → 线程池 shutdown → 释放 TLS 资源

以下配置错误**启动即 FATAL 退出**，不会静默降级：

| 条件 | 表现 |
| --- | --- |
| `config.socket.ioUseMode` / `config.tls.socketIoUseMode` / `config.tls.sslIoUseMode` 非 `none` | 只有 `none` 被实现，其余报"not implemented" |
| `server.host` 为空 | `server host is empty` |
| `server.port <= 0` | `server port is empty` |
| `client.host` 或 `client.port` 为空 | `client host/port is empty` |
| `client.host` 与 `client.port` 元素个数不一致 | `client host and port count mismatch` |
| 配置文件 YAML 语法错误 | `Configuration error in config.yml` |

监听 socket 初始化失败（`socket` / `setsockopt` / `bind` / `listen` 任一失败）也会返回非零退出码。

## 最小可用配置

### 明文

```yaml
server:
  host: 0.0.0.0
  port: 9800
client:
  host: 127.0.0.1
  port: 10808
```

冒烟：起一个本地后端，再 `nc 127.0.0.1 9800`，或在 `client.port` 指向的端口上开一个 `nc -l`。

### TLS

```yaml
config:
  tls:
    enable: true
server:
  host: 0.0.0.0
  port: 9800
  tls:
    cert: cert.pem
    privkey: key.pem
client:
  host: 127.0.0.1
  port: 8443
  tls:
    sni: ""
```

自签测试证书：

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=localhost"
```

用 `openssl s_server` 当后端验证：

```bash
openssl s_server -accept 8443 -cert cert.pem -key key.pem -www
openssl s_client -connect 127.0.0.1:9800 -servername localhost
```

---

## TLS 模式要点

**代理是终止 TLS，不是原始字节透传**：对客户端完成 `SSL_accept` 之后，再对后端独立完成一次 `SSL_connect`，两个 `SSL` 之间转发解密后的明文载荷。因此后端也必须是 TLS 服务，且代理需要自己的证书和私钥。

- **证书与私钥**：`server.tls.cert` 和 `server.tls.privkey`（规范键是 `privkey`；旧的 `key` 仍兼容，读到时打 deprecation 警告）。文件不存在会被清空并打 ERROR，随后所有握手失败。
- **后端证书校验**：固定用**系统信任库**（`SSL_CTX_set_default_verify_paths`）+ `SSL_VERIFY_PEER`。`client.tls.cert`（自定义 CA）是**死配置**，从未被读取。内网自签 CA 必须装进系统信任库，否则全部握手失败。系统信任库加载失败时**直接拒绝建连**（返回 `-1`），不会退化成"不校验"。
- **SNI**：`client.tls.sni` 为空串 = 透传客户端握手带来的 SNI。同时用于后端证书的主机名校验（`SSL_set1_host`）。
  - **必须写成 `sni: ""`，不能只写 `sni:`**。yaml-cpp 的 `as<std::string>(fallback)` 对 null 节点返回的是字面量字符串 `"null"` 而不是 `fallback`，所以裸键会被当成 SNI = `null`：既不透传客户端 SNI，又强制要求后端证书对 `null` 这个主机名有效，结果是**每条连接握手都失败且没有任何告警**。见下方「已知限制」。
  - `sni` 被填成 `0.0.0.0` / `localhost` → 判为无效（SNI 本来就不能是地址），**主机名校验会失效**，且每条连接打 WARN。
  - `sni` 为空串且客户端握手没带 SNI → 同样只做链校验、不做主机名校验，打 WARN。
  - 任何"被静默丢弃的安全相关配置"都会告警，不会无声降级。
- **缓冲区下限**：`config.tls.enable: true` 时任一 `bufferSize < 8192` 都会打性能告警。
- **转发模型**：一条连接只有 1 个 worker，用 `epoll`（水平触发）同时监听两端 fd。

## 多后端

`client.host` 和 `client.port` 都接受单值或数组，**两者元素个数必须一致**，否则启动失败：

```yaml
client:
  host: ["10.0.0.1", "10.0.0.2", "example.com"]
  port: [10808, 10808, 443]
  selectMode: roundRobin   # roundRobin | random
```

- `roundRobin`（默认）：互斥锁保护的循环索引
- `random`：`rand() % n`，并尽量避开上一次用过的索引

选址结果写入每个 worker 自己持有的 `BackendTarget`，再按值传给建连函数 —— 选址与建连之间没有共享可变状态。

## 防火墙

```yaml
server:
  connect:
    banIps: ["192.168.1.100"]
    allowedIps: []      # 非空即白名单
```

- `banIps` **优先级最高**，命中即拒
- 匹配方式是**完整字符串精确比较**，不支持 CIDR / 通配符 / 前缀
- `allowedIps` 为空表示不限制；非空时只放行命中项
- 两个列表都为空时启动打 `Firewall disabled - all IPs are allowed`
- 判断点在 accept 之后、**连后端之前**，被拒时打 `SECURITY: Access denied`

## 日志

```
[2026-09-26 12:00:00] [INFO] New connection established - Client: 127.0.0.1:52341 -> Backend: 0.0.0.0:10808
```

- 级别：`debug`（蓝）/ `info`（绿）/ `warn`（黄）/ `error`（红）/ `fatal`（紫），`level` 配某一级别即输出**该级别及以上**
- `console: false` 可关控制台（颜色是 ANSI 转义序列，非 TTY 下也是裸转义码）
- `file: true` 时**首次写入才 `fopen`**；`filePath` 或其父目录不存在会降级为不写文件并打 WARN
- 多线程并发下整行加锁输出，时间戳用 `localtime_r` + 栈上缓冲

---

## 配置项参考

> 表中的默认值是 **`src/main.cpp` 里 `.as<T>(default)` 的值**，也是唯一生效的默认值。`src/Global/config.c` 里的初始值全是死值（`main.cpp` 每次都会覆盖，且两者并不一致），**读 `config.c` 推断运行时行为会得到错误答案**。
>
> 仓库自带的 `config.yml` 现值与本表也不一致（例如 `minWokers: 10` vs `5`、`bufferSize: 1024` vs `8192`、`log.level: info` vs `debug`），**实际生效的是配置文件里写的值**，本表只代表"该项不写时取什么"。

### `config.socket`（明文路径）

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `ioUseMode` | string | `none` | 识别 `none`/`select`/`poll`/`epoll`，**非 `none` 启动即 FATAL 退出** |
| `useThreadpoolAccept` | bool | `true` | `false` = 在 accept 任务内同步建连（阻塞监听） |
| `noBlockReadOrWrite` | bool | `false` | **死配置**，从未被读取 |
| `noBlockConnect` | bool | `false` | **死配置**，从未被读取 |
| `acceptTimeoutMs` | int | `-1` | `> 0` 时给**监听 socket** 设 `SO_SNDTIMEO` / `SO_RCVTIMEO` |
| `connectTimeoutMs` | int | `-1` | `> 0` 时给**后端 socket** 设收发超时 |
| `pollingIntervalMs` | int | `500` | **只被 TLS 转发路径读取**（写阻塞时 `select()` 的超时）；明文路径两个 `pollingIntervalMs` 都不读 |
| `readOrWriteTimeoutMs` | int | `-1` | `> 0` 时给两端 fd 设收发超时；`<= 0` 空闲连接永久占用 worker |

### `config.tls`

**仅 `config.tls.enable: true` 时才被读取**，其余键全部忽略。

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enable` | bool | `false` | `true` = 对客户端解密、对后端重新加密 |
| `socketIoUseMode` | string | `none` | 非 `none` 启动即 FATAL 退出 |
| `sslIoUseMode` | string | `none` | 非 `none` 启动即 FATAL 退出 |
| `useThreadpoolAccept` | bool | `true` | TLS 握手（`SSL_accept`）是否交线程池 |
| `useThreadpoolSslAccept` | bool | `true` | 连接后端（`SSL_connect`）是否交线程池 |
| `noBlockReadOrWrite` | bool | `false` | **死配置**，从未被读取 |
| `noBlockConnect` | bool | `false` | **死配置**，从未被读取 |
| `acceptTimeoutMs` | int | `-1` | `> 0` 时给客户端 socket 设收发超时 |
| `connectTimeoutMs` | int | `-1` | 写阻塞重试的总超时；`<= 0` 不启用该超时 |
| `pollingIntervalMs` | int | `100` | `epoll_wait` 超时（毫秒） |
| `readOrWriteTimeoutMs` | int | `-1` | 空闲连接超时（毫秒，与上项同单位累加） |

### `config.log`

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enable` | bool | `true` | 总开关 |
| `console` | bool | `true` | 控制台输出（带 ANSI 颜色） |
| `level` | string | `debug` | `debug`/`info`/`warn`/`error`/`fatal`，输出该级别及以上 |
| `file` | bool | `false` | |
| `filePath` | string | `""` | 文件或父目录不存在则降级为不写文件；首次写入时才 `fopen` |

### `config.threadpool`

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `minWokers` | int | `5` | 拼写是 `Wokers`，属对外契约，不要"修正"；实际初始 worker = 值 + 2 |
| `maxWokers` | int | `15` | 同上；实际上限 = 值 + 1 |
| `clearThreadTimeMs` | int | `10000` | 空闲多久后开始缩容 |
| `pollingIntervalMs` | int | `500` | 扩缩容 manager 循环间隔 |
| `stepAddThreadNumber` | int | `1` | 每次扩容步长；`<= 0` 时按 `pendingMissions / 2` 自适应（至少 1） |

### `server`

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `host` | string | **必填** | `0.0.0.0` / `*` = 所有网卡，`127.0.0.1` / `localhost` = 本机，其他先 `inet_pton` 再 `gethostbyname`（仅 IPv4） |
| `port` | int | **必填** | `<= 0` 退出 |
| `socket.maxBacklog` | int | `128` | `<= 0` 降级为 5 |
| `socket.bufferSize` | int | `8192` | **后端 → 客户端**方向的转发缓冲 |
| `tls.cert` | string | `""` | 证书 PEM；文件不存在则清空并报错（仅 `enable: true` 时读） |
| `tls.privkey` | string | `""` | 私钥 PEM。**规范键是 `privkey`**；仍兼容旧的 `key`（读到时打 deprecation 警告）。文件不存在则清空并报错 |
| `connect.banIps` | list | `[]` | IP 黑名单，**完整字符串精确比较**，优先级最高 |
| `connect.allowedIps` | list | `[]` | 为空表示不限制；非空则只放行命中项 |

### `client`

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `host` | string \| list | **必填** | 单值或数组（多后端） |
| `port` | int \| list | **必填** | 元素个数必须与 `host` 一致，否则启动失败 |
| `selectMode` | string | `roundRobin` | `roundRobin`（互斥锁保护的循环索引）/ `random`（`rand() % n`） |
| `socket.bufferSize` | int | `8192` | **客户端 → 后端**方向的转发缓冲 |
| `tls.sni` | string | `""` | **必须显式写 `""`**：裸键 `sni:` 会被 yaml-cpp 读成字面量 `"null"`，导致后端握手全部失败。为空串则透传客户端握手 SNI；同时用于后端证书主机名校验。`0.0.0.0` / `localhost` 会被判为无效并**告警**，此时主机名校验不生效 |
| `tls.hostname` | string | `""` | **死配置**，从未被读取 |
| `tls.cert` | string | `""` | **死配置**，后端证书固定用系统信任库 |

> 拼写错误同属对外契约，改名会破坏已有配置：`minWokers` / `maxWokers`、`client.hostname` 的历史拼写、`server.tls.key` 兼容别名。

---

## 已知限制

- **仅 Linux**，无法在 Windows / macOS 上编译运行。
- **yaml-cpp 的 null 字符串陷阱**：`node.as<std::string>(fallback)` 在节点为 null（YAML 里写成裸键 `key:`）时返回的是**字面量字符串 `"null"`**，不是 `fallback`。受影响的键：`client.tls.sni`、`client.tls.hostname`、`client.tls.cert`、`server.tls.cert`、`server.tls.privkey`、`config.log.filePath`。
  - `client.tls.sni` 是唯一会造成**静默功能失效**的：它会真的被当成 SNI `null` 发给后端，并强制校验后端证书对 `null` 有效，表现为"TLS 模式所有连接握手失败"且无告警。**要留空必须写 `sni: ""`。**
  - 其余几项要么随后被 `std::filesystem::exists` 判为不存在而清空（`server.tls.cert` / `privkey`），要么本来就是死配置。
  - 非字符串类型（`int` / `bool`）的 `as<T>(fallback)` 没有这个问题：键缺失或解码失败都会正确回落到 `fallback`。
- **`ioUseMode` 只实现了 `none`**。`select` / `poll` / `epoll` 三个值在启动时就被拒绝，不会静默走错分支。
- **死配置**（解析了但代码里从未读取）：`config.socket.noBlockReadOrWrite`、`config.socket.noBlockConnect`、`config.tls.noBlockReadOrWrite`、`config.tls.noBlockConnect`、`client.tls.hostname`、`client.tls.cert`。
- **线程池容量换算**：`setMin/setMaxThreadNumber` 内部各 `+1`，`init()` 又 `setPoolSize(minWokers + 1)`，所以
  - 实际初始 worker = **`minWokers + 2`**
  - 实际上限 = **`maxWokers + 1`**
  - 还要扣掉 2 个常驻任务（自动扩缩容 manager + accept 循环）
  - 经验值：**`maxWokers >= 2 × 预期最大并发连接数`**（明文模式每条连接常驻 2 个 worker，TLS 模式 1 个）
  - 容量不足的日志信号：`exec_mission error`（任务被丢弃）、`create_worker error`
- **`readOrWriteTimeoutMs <= 0` 时空闲连接会永久占用 worker**，高并发下容易被大量长连接拖满线程池。
- 任务抛异常会触发 `mission_drop`，此时会**从队列里额外弹掉一个无关任务**（任务出队 FIFO/LIFO 混用，见 `MISTAKE.md`），看到 `exec_mission error` 时要意识到丢的可能不是当前这条连接。
- **没有测试、没有 CI、没有 lint / format 配置**。验证方式 = 干净编译 + 手工冒烟。

## 故障排查

| 现象 | 日志关键字 | 处置 |
| --- | --- | --- |
| 连接被拒 | `SECURITY: Access denied` | 命中 `banIps`，或 `allowedIps` 非空但没放行该 IP |
| 后端建连失败 | `Connect: connect() failed` / `cannot resolve hostname` | 检查 `client.host` / `client.port`、后端是否在监听、DNS 是否可解析 |
| 后端地址异常 | `Connect: getpeername failed` | 通常伴随上一条，先看它前面的错误 |
| 客户端握手失败 | `SSL accept failed for client` | 检查客户端是否信任代理证书、协议版本、SNI 是否匹配 |
| 后端握手失败 | `connectTlsServer: SSL_connect failed` | 后端不是 TLS 服务，或后端证书不在系统信任库里（`client.tls.cert` 是死配置，装进系统信任库才有效）。**若配置里写的是裸键 `sni:`，几乎一定是这个原因** —— 见「已知限制」的 yaml-cpp null 字符串陷阱 |
| 主机名校验被关掉 | `backend certificate hostname verification will be disabled` | `client.tls.sni` 填了地址（`0.0.0.0` / `localhost`），或留空且客户端没带 SNI |
| 请求被静默丢弃 | `exec_mission error` | 线程池打满。调大 `maxWokers`，或减少并发长连接 |
| worker 创建失败 | `create_worker error` | 线程创建失败（通常是 fd 或内存不足） |
| 连接被超时断开 | `idle timeout after ...ms` / `Socket read or write timeout` | 调大 `readOrWriteTimeoutMs`；配成 `<= 0` 则永不超时 |
| 日志写到一半没了 | `log output file path error` / `open log file error` | `filePath` 或父目录不存在、权限不足 |
| 防火墙未生效 | `Firewall disabled - all IPs are allowed` | `banIps` 和 `allowedIps` 都是空列表 |

## 目录结构

```
src/
├── main.cpp                 入口：参数、配置加载校验、启动/关闭
├── headfile.h               统一头（所有 .c/.cpp 只 include 它）
├── define.h                 宏：I/O 模式、日志级别、后端选择策略
├── Global/                  全局状态（C 与 C++ 各一份）
├── Log/                     日志（C 与 C++ 各一套同名 API）
├── ProtocolServer/          裸系统调用封装：nSocket(明文) / nTls(TLS)
├── Threadpool/              ThreadpoolSimple + ThreadpoolAutoCtrlByTime
└── Callback/                业务层：防火墙、后端选择、连接生命周期、转发
```

## 相关文档

- [`AGENTS.md`](AGENTS.md) —— 给 AI agent 的开发约定：构建红线、内存与生命周期红线、配置键位
- [`MISTAKE.md`](MISTAKE.md) —— 本仓库已核实**但尚未修复**的缺陷（含成因与证据）；已修复的缺陷成因保留在 git 历史里
