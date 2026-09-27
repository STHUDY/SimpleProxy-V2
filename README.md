# SimpleProxy-V2

C/C++17 从零实现的 TCP / TLS 端口转发代理。不含任何第三方框架，只依赖 `libyaml-cpp`（配置解析）和 `OpenSSL`（TLS），单 CMake 目标 `SimpleProxy`，单可执行文件。

**支持 Windows 与 Linux**。平台差异全部收敛在 `src/Platform/`（`Linux/` 与 `Windows/` 各一套实现），业务代码里没有 `#ifdef _WIN32`（`main.cpp` 的信号与 `RLIMIT_NOFILE` 处理除外）。详细差异对照见 [`document/platform.md`](document/platform.md)。

## 特性

- **明文转发**：客户端连接经代理连到后端，一条连接 2 个 worker 各负责一个方向
- **TLS 转发**：代理两端各做一次握手（对客户端 `SSL_accept`、对后端 `SSL_connect`），中间转发解密后的明文载荷
- **多后端**：后端 `host` / `port` 支持数组，`roundRobin`（默认）或 `random` 选址
- **IP 黑白名单**：`banIps` 优先，`allowedIps` 非空即白名单
- **自动扩缩容线程池**：一个常驻 manager 线程按积压任务量和空闲时长调整 worker 数量
- **分级日志**：5 个级别，控制台 ANSI 彩色输出，可选写文件，多线程整行加锁
- **地址解析**：`0.0.0.0` / `*` / `127.0.0.1` / `localhost` 走短路，其余交给 `netResolveIpv4()`（`getaddrinfo`，仅 IPv4）

---

## 优势

面向的场景是"把一个后端安全地暴露出去，顺带做负载均衡和访问控制"，在这个定位上比通用代理更省事。

### 部署简单

- **单可执行文件 + 单个 YAML**，没有运行时依赖、没有插件系统、没有配置模板语言。拷过去 `./SimpleProxy -c config.yml` 就起来了，容器里扔进去就能用。
- **第三方依赖只有两个**：`libyaml-cpp` 和 `OpenSSL`（Linux 再链系统自带的 pthread，Windows 走系统自带的 Winsock / CryptoAPI）。对比 nginx 还要 Lua/正则库那一套、HAProxy 还要编译器和运行时版本对齐，审计和换机器的成本都低得多。
- **纯转发，不解析应用层协议**。不识别 HTTP / SSH / 数据库协议，代理本身就没有"某个协议解析错了"这类故障面，也不用为了升级后端协议而重启代理。

### TLS 能力比通用反代更贴合"换后端"这个需求

- **两端独立握手**：对客户端 `SSL_accept`、对后端 `SSL_connect`，两端证书链、协议版本、密码套件可以各自独立配置。既能对外提供一个统一证书，又能连到同样跑 TLS 的内网后端——stunnel 之类的纯 TCP 透传做不到对后端握手，nginx 反代还得单独配上游 `proxy_ssl_*`。
- **客户端 SNI 透传**：`sni` 留空时代理把客户端握手带来的 SNI 原样发给后端。多租户 / CDN / 同证书多域名场景下，后端仍能按主机名分流。
- **后端证书强制校验**：`SSL_VERIFY_PEER` + 系统信任库 + `client.tls.cert` 指定的 CA，并对 SNI 做主机名校验。配置被判定无效时会**显式告警**，不会悄悄降级成"只验链不验主机名"。

### 控制能力是内建的，不是外挂

- **IP 黑白名单前置到连后端之前**：被拒的连接根本不会占用后端连接数，也不会消耗线程池 worker。
- **多后端负载均衡**：`roundRobin` / `random` 两种策略，host/port 一一对应，顺手就能把几个实例挂上去。
- **超时是分层可配的**：监听 socket、后端建连、客户端握手、转发收发、连接空闲各自独立，不会出现"改一个超时把另一个也改了"。

### 工程实现上的几个刻意选择

- **TLS 转发用 1 个 worker + `netWaitSetWait` 同时监听两端 fd**（Linux `epoll` / Windows `WSAPoll`，水平触发），明文转发用 2 个 worker 各管一个方向。前者把每连接的 worker 占用减半。
- **后端选址结果按值往下传**：`selectBackendTarget()` 写入调用方持有的对象，再传给建连函数，选址和建连之间没有任何共享可变状态——多后端并发时不会连到别的后端的端口。
- **转发缓冲区 64 字节对齐**（`netAlignedAlloc(size, 64)` ↔ `netAlignedFree`：Linux `posix_memalign` / Windows `_aligned_malloc`），分配/释放严格配对并判空；收发标志统一走 `SOCKET_SEND_FLAGS`（POSIX 为 `MSG_NOSIGNAL`，Windows 为 0），POSIX 上启动时 `SIG_IGN` 掉 `SIGPIPE`。
- **启动期 fail-fast**：`ioUseMode` 非 `none`、`server.host` 为空、`server.port <= 0`、`client.host` / `client.port` 为空或个数不匹配、YAML 语法错误——这些都在启动时报错退出，不会带着错误配置跑起来再在每条连接上重复失败。证书 / 私钥文件不存在同样在启动时立刻报 ERROR 并清空路径，而不是等到第一条连接才暴露。
- **退出路径经过专门设计**：关闭监听 fd 时先 `shutdown` 再 `close`，用来唤醒阻塞在 `accept()` 上的线程，否则线程池 `join()` 会永久卡死。`exit` 回车保证干净退出；Ctrl+C 在 Linux 上等效，Windows 上可能打断不了阻塞在 `std::cin` 的主线程（见「运行」一节的提示）。
- **日志线程安全**：时间戳用 `localtime_r` + 栈上缓冲，控制台和文件输出都整行加锁，多 worker 并发打日志不会出现时间戳错乱或行内容串接。
- **端口、超时、线程数、日志全部有配置项**，调参不需要改代码；Linux 下启动时还会自动把 `RLIMIT_NOFILE` 提到 65536（受 `rlim_max` 限制，Windows 无此概念）。

> 这些都是设计取向，不代表无代价。并发上限受线程池容量约束（见下方「已知限制」的容量换算），且 `ioUseMode` 目前只实现了 `none`。

---

## 环境依赖

| 依赖       | 用途             | 平台                                      |
| ---------- | ---------------- | ----------------------------------------- |
| `yaml-cpp` | YAML 配置解析    | 两平台必需（`REQUIRED`）                  |
| `OpenSSL`  | `SSL` + `Crypto` | 两平台必需（`REQUIRED`）                  |
| pthreads   | 线程             | 仅 Linux（Windows 走 `CRITICAL_SECTION`） |

Linux：

```bash
sudo apt install build-essential cmake libyaml-cpp-dev libssl-dev
```

Windows 走 vcpkg（见下方编译一节）：

```powershell
C:\vcpkg\scripts\bootstrap-vcpkg.bat -disableMetrics
```

> 仓库里的 `vcpkg.json` / `vcpkg-configuration.json` 是依赖清单（`openssl`、`yaml-cpp`）。Linux 构建走系统包，不经过 vcpkg。

## 编译

**默认构建类型是 Debug**。任何时延 / 吞吐相关的结论都必须显式用 `Release`。

可用构建类型：`Debug` / `Release` / `RelWithDebInfo` / `MinSizeRel`。

> **GLOB 陷阱**：`CMakeLists.txt` 用 `file(GLOB_RECURSE ...)` 收集源文件。新增 / 删除 / 重命名源文件后**必须重新执行 configure**（或删掉 `CMakeCache.txt`），只跑增量构建不会生效。

### Linux

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..    # 省略即 Debug
make -j$(nproc)
```

Debug 用 `-O0 -g`，Release 用 `-O3 -DNDEBUG -funroll-loops -ftree-vectorize -fvect-cost-model=unlimited`。产物 `build/SimpleProxy`。

### Windows（MSVC）

**1. 装依赖**。仓库用 `vcpkg.json` 声明 `openssl` 和 `yaml-cpp`：

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\scripts\bootstrap-vcpkg.bat -disableMetrics
```

依赖装好后产物在 `vcpkg_installed\<triplet>\`，**必须告诉 CMake 去哪找**：

如果遇到网络问题，可以尝试设置GIT镜像

```
git config --global url."https://gh-proxy.org/https://github.com".insteadOf https://github.com
```

```powershell
cd <仓库根目录>

cmake -S . -B build -G "Visual Studio 18 2026" -A x64 `
  "-DCMAKE_PREFIX_PATH=$PWD\vcpkg_installed\x64-windows-static"

cmake --build build                  # Debug（默认）

cmake --build build --config Release # Release
```

**2. 三个容易踩的点**：

- **不要传 `-DCMAKE_BUILD_TYPE`。** Visual Studio 生成器是**多配置**的，构建类型在 build 阶段用 `--config` 选。传了会被记成 `CMAKE_BUILD_TYPE:UNINITIALIZED=Release`，项目根本不认。
- **不要用 `make`。** VS 生成器不产 Makefile，没有 make 可调。`$(nproc)` 也是 bash 语法，PowerShell 不认。
- **PowerShell 里调用带引号的可执行文件路径要加调用运算符 `&`**，否则后面的 `-D...` 会被解析成意外 token。

**3. `CMAKE_PREFIX_PATH` 为什么是必需的**

`CMakeLists.txt` 里 `find_package(yaml-cpp REQUIRED)` / `find_package(OpenSSL REQUIRED)` 需要找到它们的 CMake config。Linux 上这些在系统包路径里，CMake 默认就能找到；Windows 上默认路径是 C 盘 Program Files，**不会自动去 `vcpkg_installed` 里找**。不指就会报：

```
CMake Error at CMakeLists.txt:11 (find_package):
  Could not find a package configuration file provided by "yaml-cpp"
```

**4. `vcpkg_installed\<triplet>` 必须与 CRT 匹配**

`CMakeLists.txt` 显式使用静态 CRT（`/MT` / `/MTd`，运行时直接链进 exe，拷贝即用），所以 triplet 要选同样静态 CRT 的 `x64-windows-static`；选了动态 CRT 的 triplet 会报 `LNK2038 RuntimeLibrary 不匹配`。依赖装好后落在 `vcpkg_installed\x64-windows-static\`，`CMAKE_PREFIX_PATH` 指到它即可。

**5. 编码**：源码是 UTF-8 **无 BOM**，MSVC 默认按系统 ANSI 代码页读（中文系统上是 GBK），中文注释会破坏预处理。`CMakeLists.txt` 里已经加了 `/utf-8`，正常构建不需要额外操作；如果看到满屏 `C4819` 加上"某变量未声明"，就是这一条没生效。

编译期常见错误与更多说明见 [`document/build.md`](document/build.md)。

## 运行

```bash
# Linux
./build/SimpleProxy [-c config.yml]
```

```powershell
# Windows
.\build\Debug\SimpleProxy.exe [-c config.yml]
.\build\Release\SimpleProxy.exe [-c config.yml]
```

- `-c <file>` 指定配置文件，默认 `./config.yml`
- `-h` / `--help` 打印用法
- 启动时读取配置；Linux 下尝试把 `RLIMIT_NOFILE` 提升到 `65536`（受 `rlim_max` 限制；Windows 无此概念）
- 主线程阻塞在 `std::cin`，**输入 `exit` 回车或按 Ctrl+C 优雅退出**：关监听 fd → 等任务排空 → 线程池 shutdown → 释放 TLS 资源

> **Windows 上优先用 `exit` 回车退出。** Ctrl+C 不一定能打断阻塞在 `std::cin` 的主线程，可能表现为进程卡住不退出。
>
> **配置里的相对路径按进程 CWD 解析**，不是按配置文件所在目录。用相对路径时要从那个目录启动代理。测试场景见 [`test/`](test/)。

以下配置错误**启动即 FATAL 退出**，不会静默降级：

| 条件                                                                                           | 表现                                        |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------- |
| `config.socket.ioUseMode` / `config.tls.socketIoUseMode` / `config.tls.sslIoUseMode` 非 `none` | 只有 `none` 被实现，其余报"not implemented" |
| `server.host` 为空                                                                             | `server host is empty`                      |
| `server.port <= 0`                                                                             | `server port is empty`                      |
| `client.host` 或 `client.port` 为空                                                            | `client host/port is empty`                 |
| `client.host` 与 `client.port` 元素个数不一致                                                  | `client host and port count mismatch`       |
| 配置文件 YAML 语法错误                                                                         | `Configuration error in config.yml`         |

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
    cert: cert.pem # 后端用同一张自签证书：自签证书是自己的 CA，指向它即可通过链校验
```

自签测试证书（`-addext` 不能省：OpenSSL 1.0.2 起主机名校验只看 SAN，不再看 CN）：

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

用 `openssl s_server` 当后端验证：

```bash
openssl s_server -accept 8443 -cert cert.pem -key key.pem -www
openssl s_client -connect 127.0.0.1:9800 -servername localhost -CAfile cert.pem
```

---

## TLS 模式要点

**代理是终止 TLS，不是原始字节透传**：对客户端完成 `SSL_accept` 之后，再对后端独立完成一次 `SSL_connect`，两个 `SSL` 之间转发解密后的明文载荷。因此后端也必须是 TLS 服务，且代理需要自己的证书和私钥。

- **证书与私钥**：`server.tls.cert` 和 `server.tls.privkey`（规范键是 `privkey`；旧的 `key` 仍兼容，读到时打 deprecation 警告）。文件不存在会被清空并打 ERROR，随后所有握手失败。
- **后端证书校验**：固定 `SSL_VERIFY_PEER`。信任库 = OpenSSL 默认路径（`SSL_CTX_set_default_verify_paths`）+ `client.tls.cert` 指定的 CA 文件（**追加，不是替换**，所以配了自签 CA 之后公共 CA 依然能用）。内网自签 CA 用 `client.tls.cert` 指向即可，不必装进系统信任库。系统信任库加载失败时**直接拒绝建连**（返回 `-1`），不会退化成"不校验"。
- ⚠️ **`SSL_CTX_set_default_verify_paths()` 只要"目录存在"就返回成功，哪怕里面一张 CA 都没有。** 很多 Windows 部署上它的默认路径（`%COMMONFILES%\SSL\certs`、`cert.pem`）是空的，于是所有后端握手都以 `certificate verify failed` 失败而函数返回成功。遇到这种情况就配 `client.tls.cert`：访问公网指向真正的 CA bundle（几百 KB / 上百张证书），内网自签后端指向它自己的自签证书（自签证书即自己的 CA，见上方最小示例）。
- **SNI**：`client.tls.sni` 为空串 = 透传客户端握手带来的 SNI。同时用于后端证书的主机名校验（`SSL_set1_host`）。
  - **建议显式写 `sni: ""`，不要写裸键 `sni:`**。yaml-cpp 的 `as<std::string>(fallback)` 对 null 节点返回的是字面量 `"null"` 而不是 `fallback`；代理启动时已用 `normalizeConfigString()` 把这类值统一归一成空串兜底（8 处字符串配置），裸键不再致命，但显式空串意图更清楚。
  - `sni` 被填成 `0.0.0.0` / `localhost` → 判为无效（SNI 本来就不能是地址），**主机名校验会失效**，且每条连接打 WARN。
  - `sni` 为空串且客户端握手没带 SNI → 同样只做链校验、不做主机名校验，打 WARN。
  - 任何"被静默丢弃的安全相关配置"都会告警，不会无声降级。
- **缓冲区下限**：`config.tls.enable: true` 时任一 `bufferSize < 8192` 都会打性能告警。
- **转发模型**：一条连接只有 1 个 worker，用 `netWaitSetWait` 同时监听两端 fd（Linux `epoll` / Windows `WSAPoll`，水平触发）。

## 多后端

`client.host` 和 `client.port` 都接受单值或数组，**两者元素个数必须一致**，否则启动失败：

```yaml
client:
  host: ["10.0.0.1", "10.0.0.2", "example.com"]
  port: [10808, 10808, 443]
  selectMode: roundRobin # roundRobin | random
```

- `roundRobin`（默认）：互斥锁保护的循环索引
- `random`：`rand() % n`，并尽量避开上一次用过的索引

选址结果写入每个 worker 自己持有的 `BackendTarget`，再按值传给建连函数 —— 选址与建连之间没有共享可变状态。

## 防火墙

```yaml
server:
  connect:
    banIps: ["192.168.1.100"]
    allowedIps: [] # 非空即白名单
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
> 仓库自带的 `config.yml` 现值与本表也不一致（例如 `minWokers: 10` vs `5`、`maxWokers: 1000` vs `15`、`bufferSize: 1024` vs `8192`、`stepAddThreadNumber: 10` vs `1`），**实际生效的是配置文件里写的值**，本表只代表"该项不写时取什么"。

### `config.socket`（明文路径）

| 键                     | 类型   | 默认    | 说明                                                                                             |
| ---------------------- | ------ | ------- | ------------------------------------------------------------------------------------------------ |
| `ioUseMode`            | string | `none`  | 识别 `none`/`select`/`poll`/`epoll`，**非 `none` 启动即 FATAL 退出**                             |
| `useThreadpoolAccept`  | bool   | `true`  | `false` = 在 accept 任务内同步建连（阻塞监听）                                                   |
| `noBlockReadOrWrite`   | bool   | `false` | **死配置**，从未被读取                                                                           |
| `noBlockConnect`       | bool   | `false` | **死配置**，从未被读取                                                                           |
| `acceptTimeoutMs`      | int    | `-1`    | `> 0` 时给**监听 socket** 设 `SO_SNDTIMEO` / `SO_RCVTIMEO`                                       |
| `connectTimeoutMs`     | int    | `-1`    | `> 0` 时给**后端 socket** 设收发超时                                                             |
| `pollingIntervalMs`    | int    | `500`   | **只被 TLS 转发路径读取**（写阻塞时 `netWaitSetWait` 的超时）；明文路径完全不读                 |
| `readOrWriteTimeoutMs` | int    | `-1`    | `> 0` 时给两端 fd 设收发超时；`<= 0` 空闲连接永久占用 worker                                     |

### `config.tls`

**仅 `config.tls.enable: true` 时才被读取**，其余键全部忽略。

| 键                       | 类型   | 默认    | 说明                                    |
| ------------------------ | ------ | ------- | --------------------------------------- |
| `enable`                 | bool   | `false` | `true` = 对客户端解密、对后端重新加密   |
| `socketIoUseMode`        | string | `none`  | 非 `none` 启动即 FATAL 退出             |
| `sslIoUseMode`           | string | `none`  | 非 `none` 启动即 FATAL 退出             |
| `useThreadpoolAccept`    | bool   | `true`  | TLS 握手（`SSL_accept`）是否交线程池    |
| `useThreadpoolSslAccept` | bool   | `true`  | 连接后端（`SSL_connect`）是否交线程池   |
| `noBlockReadOrWrite`     | bool   | `false` | **死配置**，从未被读取                  |
| `noBlockConnect`         | bool   | `false` | **死配置**，从未被读取                  |
| `acceptTimeoutMs`        | int    | `-1`    | `> 0` 时给客户端 socket 设收发超时      |
| `connectTimeoutMs`       | int    | `-1`    | 写阻塞重试的总超时；`<= 0` 不启用该超时 |
| `pollingIntervalMs`      | int    | `100`   | `netWaitSetWait` 超时（毫秒）           |
| `readOrWriteTimeoutMs`   | int    | `-1`    | 空闲连接超时（毫秒，与上项同单位累加）  |

### `config.log`

| 键         | 类型   | 默认    | 说明                                                     |
| ---------- | ------ | ------- | -------------------------------------------------------- |
| `enable`   | bool   | `true`  | 总开关                                                   |
| `console`  | bool   | `true`  | 控制台输出（带 ANSI 颜色）                               |
| `level`    | string | `debug` | `debug`/`info`/`warn`/`error`/`fatal`，输出该级别及以上  |
| `file`     | bool   | `false` |                                                          |
| `filePath` | string | `""`    | 文件或父目录不存在则降级为不写文件；首次写入时才 `fopen` |

### `config.threadpool`

| 键                    | 类型 | 默认    | 说明                                                              |
| --------------------- | ---- | ------- | ----------------------------------------------------------------- |
| `minWokers`           | int  | `5`     | 拼写是 `Wokers`，属对外契约，不要"修正"；实际初始 worker = 值 + 2 |
| `maxWokers`           | int  | `15`    | 同上；实际上限 = 值 + 1                                           |
| `clearThreadTimeMs`   | int  | `10000` | 空闲多久后开始缩容                                                |
| `pollingIntervalMs`   | int  | `500`   | 扩缩容 manager 循环间隔                                           |
| `stepAddThreadNumber` | int  | `1`     | 每次扩容步长；`<= 0` 时按 `pendingMissions / 2` 自适应（至少 1）  |

### `server`

| 键                   | 类型   | 默认     | 说明                                                                                                           |
| -------------------- | ------ | -------- | -------------------------------------------------------------------------------------------------------------- |
| `host`               | string | **必填** | `0.0.0.0` / `*` = 所有网卡，`127.0.0.1` / `localhost` = 本机，其余交给 `netResolveIpv4()`（`getaddrinfo`，仅 IPv4） |
| `port`               | int    | **必填** | `<= 0` 退出                                                                                                    |
| `socket.maxBacklog`  | int    | `128`    | `<= 0` 降级为 5                                                                                                |
| `socket.bufferSize`  | int    | `8192`   | **后端 → 客户端**方向的转发缓冲                                                                                |
| `tls.cert`           | string | `""`     | 证书 PEM；文件不存在则清空并报错（仅 `enable: true` 时读）                                                     |
| `tls.privkey`        | string | `""`     | 私钥 PEM。**规范键是 `privkey`**；仍兼容旧的 `key`（读到时打 deprecation 警告）。文件不存在则清空并报错        |
| `connect.banIps`     | list   | `[]`     | IP 黑名单，**完整字符串精确比较**，优先级最高                                                                  |
| `connect.allowedIps` | list   | `[]`     | 为空表示不限制；非空则只放行命中项                                                                             |

### `client`

| 键                  | 类型           | 默认         | 说明                                                                                                                                                                                                                   |
| ------------------- | -------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `host`              | string \| list | **必填**     | 单值或数组（多后端）                                                                                                                                                                                                   |
| `port`              | int \| list    | **必填**     | 元素个数必须与 `host` 一致，否则启动失败                                                                                                                                                                               |
| `selectMode`        | string         | `roundRobin` | `roundRobin`（互斥锁保护的循环索引）/ `random`（`rand() % n`）                                                                                                                                                         |
| `socket.bufferSize` | int            | `8192`       | **客户端 → 后端**方向的转发缓冲                                                                                                                                                                                        |
| `tls.sni`           | string         | `""`         | 为空串则透传客户端握手 SNI；同时用于后端证书主机名校验。`0.0.0.0` / `localhost` 会被判为无效并**告警**，此时主机名校验不生效。裸键 `sni:` 会被 yaml-cpp 读成 `"null"`，代码里 `normalizeConfigString()` 已归一为空串    |
| `tls.hostname`      | string         | `""`         | **死配置**，从未被读取                                                                                                                                                                                                 |
| `tls.cert`          | string         | `""`         | 后端 CA 文件路径（**追加**到信任库，不是替换）。文件不存在则清空并报错。留空则只依赖 OpenSSL 默认信任库（`SSL_CERT_FILE` / `OPENSSLDIR`），Windows 上默认为空                                                          |

> 拼写错误同属对外契约，改名会破坏已有配置：`minWokers` / `maxWokers`（配置键）、`gConfigTlsEnbale`（内部标识符）、`server.tls.key`（`privkey` 的兼容别名）。

---

## 已知限制

- **只支持 IPv4**。地址结构是 `sockaddr_in`，没有 IPv6 支持。
- **macOS 未适配**。`src/Platform/` 下只有 `Linux/` 和 `Windows/`，没有第三份实现。
- **Linux 侧编译已通过**（gcc, Debug）。Windows x64 编译与冒烟均已验证。
- **yaml-cpp 的 null 字符串陷阱（代码已兜底）**：`node.as<std::string>(fallback)` 在节点为 null（YAML 里写成裸键 `key:`）时返回的是**字面量字符串 `"null"`**，不是 `fallback`。代理启动时对全部 8 处字符串配置过一遍 `normalizeConfigString()`（`"null"` / `"~"` 等一律归一成空串），裸键不会再被当成真实值使用；配置里显式写 `""` 只是让意图更清楚。
  - 非字符串类型（`int` / `bool`）的 `as<T>(fallback)` 没有这个问题：键缺失或解码失败都会正确回落到 `fallback`。
- **`ioUseMode` 只实现了 `none`**。`select` / `poll` / `epoll` 三个值在启动时就被拒绝，不会静默走错分支。
- **死配置**（解析了但代码里从未读取）：`config.socket.noBlockReadOrWrite`、`config.socket.noBlockConnect`、`config.tls.noBlockReadOrWrite`、`config.tls.noBlockConnect`、`client.tls.hostname`。
- **线程池容量换算**：`setMin/setMaxThreadNumber` 内部各 `+1`，`init()` 又 `setPoolSize(min_thread_number + 1)`（即 `minWokers + 2`），所以
  - 实际初始 worker = **`minWokers + 2`**
  - 实际上限 = **`maxWokers + 1`**
  - 还要扣掉 2 个常驻任务（自动扩缩容 manager + accept 循环）
  - 经验值：**`maxWokers >= 2 × 预期最大并发连接数`**（明文模式每条连接常驻 2 个 worker，TLS 模式 1 个）
  - 容量不足的日志信号：`exec_mission error`（任务被丢弃）、`create_worker error`
- **`readOrWriteTimeoutMs <= 0` 时空闲连接会永久占用 worker**，高并发下容易被大量长连接拖满线程池。
- 任务抛异常会触发 `mission_drop`，此时会**从队列里额外弹掉一个无关任务**（任务出队 FIFO/LIFO 混用，见 `MISTAKE.md`），看到 `exec_mission error` 时要意识到丢的可能不是当前这条连接。
- **没有测试、没有 CI、没有 lint / format 配置**。验证方式 = 干净编译 + 手工冒烟。

## 故障排查

| 现象             | 日志关键字                                                   | 处置                                                                                                                                                                                              |
| ---------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 连接被拒         | `SECURITY: Access denied`                                    | 命中 `banIps`，或 `allowedIps` 非空但没放行该 IP                                                                                                                                                  |
| 后端建连失败     | `Connect: connect() failed` / `cannot resolve hostname`      | 检查 `client.host` / `client.port`、后端是否在监听、DNS 是否可解析                                                                                                                                |
| 后端地址异常     | `Connect: getpeername failed`                                | 通常伴随上一条，先看它前面的错误                                                                                                                                                                  |
| 客户端握手失败   | `SSL accept failed for client`                               | 检查客户端是否信任代理证书、协议版本、SNI 是否匹配                                                                                                                                                |
| 后端握手失败     | `connectTlsServer: SSL_connect failed`                       | 后端不是 TLS 服务，或后端证书不被信任：用 `client.tls.cert` 指向其 CA（内网自签则指向自签证书本身），或把 CA 装进系统信任库                                                      |
| 主机名校验被关掉 | `backend certificate hostname verification will be disabled` | `client.tls.sni` 填了地址（`0.0.0.0` / `localhost`），或留空且客户端没带 SNI                                                                                                                      |
| 请求被静默丢弃   | `exec_mission error`                                         | 线程池打满。调大 `maxWokers`，或减少并发长连接                                                                                                                                                    |
| worker 创建失败  | `create_worker error`                                        | 线程创建失败（通常是 fd 或内存不足）                                                                                                                                                              |
| 连接被超时断开   | `idle timeout after ...ms` / `Socket read or write timeout`  | 调大 `readOrWriteTimeoutMs`；配成 `<= 0` 则永不超时                                                                                                                                               |
| 日志写到一半没了 | `log output file path error` / `open log file error`         | `filePath` 或父目录不存在、权限不足                                                                                                                                                               |
| 防火墙未生效     | `Firewall disabled - all IPs are allowed`                    | `banIps` 和 `allowedIps` 都是空列表                                                                                                                                                               |

## 目录结构

```
src/
├── main.cpp                 入口：参数、配置加载校验、启动/关闭
├── headfile.h               统一头（所有 .c/.cpp 只 include 它）
├── define.h                 宏：I/O 模式、日志级别、后端选择策略
├── Platform/                跨平台适配层：PlatformBase.h + Linux/ + Windows/
├── Global/                  全局状态（C 与 C++ 各一份）
├── Log/                     日志（C 与 C++ 各一套同名 API）
├── ProtocolServer/          裸系统调用封装：nSocket(明文) / nTls(TLS)
├── Threadpool/              ThreadpoolSimple + ThreadpoolAutoCtrlByTime
└── Callback/                业务层：防火墙、后端选择、连接生命周期、转发
```

完整结构与各文件职责见 [document/structure.md](document/structure.md)。

## 相关文档

- [`document/`](document/) —— 技术文档：目录结构、架构与调用链、跨平台适配层、构建、验证
- [`AGENTS.md`](AGENTS.md) —— 给 AI agent 的开发约定：构建红线、内存与生命周期红线、配置键位
- [`MISTAKE.md`](MISTAKE.md) —— 本仓库已核实**但尚未修复**的缺陷（含成因与证据）；已修复的缺陷成因保留在 git 历史里
