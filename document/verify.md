# 验证与冒烟测试

项目**没有单元测试、没有 CI、没有 lint / format 配置**。验证方式 = 干净编译 + 手工冒烟。

## 目录

1. [通用原则](#通用原则)
2. [明文转发冒烟](#明文转发冒烟)
3. [TLS 转发冒烟](#tls-转发冒烟)
4. [日志判读](#日志判读)
5. [代码级验证手段](#代码级验证手段)
6. [grep 闸门](#grep-闸门)

---

## 通用原则

- **证书和配置路径相对进程 CWD 解析**（`main.cpp` 用 `std::filesystem::exists` 判断），所以要从材料所在目录启动代理
- 日志级别设 `debug` 才能看到 `Connect:` / `Init:` 这些定位信息
- 退出输 `exit` 回车。**Windows 上 Ctrl+C 可能表现为卡住**（`signal(SIGINT)` 装了，但主线程阻塞在 `std::cin`，控制台的 Ctrl+C 未必能打断这个读）
- 换端口前先查占用：`Get-NetTCPConnection -State Listen -LocalPort <port>`

---

## 明文转发冒烟

### 1. 后端（窗口 A）—— 回显服务

```powershell
$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,19801);$l.Start()
while($true){$c=$l.AcceptTcpClient();$s=$c.GetStream();$b=New-Object byte[] 4096
while(($n=$s.Read($b,0,$b.Length)) -gt 0){$s.Write($b,0,$n);$s.Flush()};$c.Close()}
```

### 2. 配置（窗口 B）

```yaml
server:
  host: 127.0.0.1
  port: 19800
client:
  host: 127.0.0.1
  port: 19801
  socket:
    bufferSize: 8192
```

`tls.enable` 不写或写 `false`。

### 3. 起代理

```powershell
.\build\Release\SimpleProxy.exe -c 明文配置.yml
```

### 4. 客户端（窗口 C）

```powershell
$c=[System.Net.Sockets.TcpClient]::new("127.0.0.1",19800);$s=$c.GetStream();$s.ReadTimeout=5000
$p=[Text.Encoding]::UTF8.GetBytes("ping");$s.Write($p,0,4);$s.Flush()
$b=New-Object byte[] 64;$n=$s.Read($b,0,64)
"received $n bytes: " + [Text.Encoding]::UTF8.GetString($b,0,$n)
```

回显出 `ping` 即通过。代理日志出现 `New connection established - Client: ... -> Backend: ...`。

### 关于 `client.host: 0.0.0.0`

**Linux 能连，Windows 不能。** Linux 内核把 connect 到 `0.0.0.0` 按 `127.0.0.1` 处理；Windows 返回 `WSAEADDRNOTAVAIL`（"请求的地址无效"）。现在两平台都在 connect 路径把 `0.0.0.0` / `*` 显式映射成 `INADDR_LOOPBACK`，行为一致。

bind 路径**仍然用 `INADDR_ANY`**（`server.host: 0.0.0.0` = 监听所有网卡），不要一起改。

---

## TLS 转发冒烟

TLS 模式有**两个独立握手**：对客户端 `SSL_accept`，对后端 `SSL_connect`。**后端也必须是 TLS 服务**。三个条件要同时成立：

1. `server.tls.cert` / `privkey` 文件存在
2. **后端证书能被信任库验证**
3. `client.tls.sni` 匹配后端证书的 CN/SAN

### 1. 生成证书

```powershell
cd C:\Users\ZYLQQ\Project\C++\SimpleProxy-V2\tlstest
$ossl = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

& $ossl req -x509 -newkey rsa:2048 -nodes -days 365 `
  -keyout proxy.crt -out proxy.key -subj "/CN=localhost" `
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

**`-addext "subjectAltName=..."` 不能省。** OpenSSL 1.0.2 起（Windows 也一样）主机名校验**不再看 CN 字段，只看 SAN**。只写 `-subj "/CN=localhost"` 会导致主机名校验失败。

`openssl s_server` / `s_client` 是子命令（OpenSSL 1.1+ 起不再是独立 exe）：

```powershell
& $ossl s_server -accept 19901 -cert backend.crt -key backend.key -www
& $ossl s_client -connect 127.0.0.1:19900 -servername localhost -CAfile proxy.crt
```

### 2. 后端证书的信任（关键，最容易卡住）

`configureClientContext()` 走 `SSL_VERIFY_PEER` + `SSL_CTX_set_default_verify_paths()`。

**注意：`SSL_CTX_set_default_verify_paths()` 只要"目录存在"就返回 1，哪怕里面一张 CA 都没有。** 很多 Windows 部署上它的默认路径（`%COMMONFILES%\SSL\certs`、`cert.pem`）是空的，于是**所有**后端握手都以 `certificate verify failed` 失败，且函数返回成功看不出问题。

两个解决办法：

**A. 配 `client.tls.cert`（推荐，无环境依赖）**

`client.tls.cert` 是追加不是替换，配了自签 CA 之后公共 CA 依然能用。填一个真正的 CA bundle：

```powershell
Copy-Item "C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt" .\ca-bundle.crt
```

```yaml
client:
  tls:
    cert: C:/Users/.../tlstest/ca-bundle.crt
```

**不能填 `server.tls.cert` 那个自签叶子证书** —— 那是代理自己的证书，验不了公共 CA 签发的后端证书。判断方法：自签证书 1 KB / 1 张，CA bundle 200 KB 上下 / 上百张。

**B. 环境变量**

```powershell
$env:SSL_CERT_FILE = "C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt"
```

不填 `client.tls.cert` 时，启动日志会有一条 INFO 提示这件事。

### 3. 配置（访问公网）

```yaml
config:
  tls:
    enable: true
  log:
    level: debug
server:
  host: 0.0.0.0
  port: 1200
  socket:
    bufferSize: 8192        # TLS 模式低于 8192 会打性能告警
  tls:
    cert: C:/.../tlstest/proxy.crt
    privkey: C:/.../tlstest/proxy.key
client:
  host: "www.baidu.com"
  port: 443                  # 写 80 是明文 HTTP 端口，TLS 握手必然失败
  socket:
    bufferSize: 8192
  tls:
    sni: "www.baidu.com"     # 要和后端证书的 CN/SAN 一致
    cert: C:/.../tlstest/ca-bundle.crt
```

`sni` 写 `""` 也能过（只做链校验、不做主机名校验），但会打一条 WARN。**要写 `""` 而不是裸键** `sni:` —— 裸键会被 yaml-cpp 读成字符串 `"null"`，然后真的拿 `null` 当 SNI 发给后端并按 `null` 校验证书，导致所有握手失败且无告警。代码侧已有 `normalizeConfigString()` 兜底，但配置本身写清楚更好。

`readOrWriteTimeoutMs` 建议 15000，公网 HTTPS 5 秒偏紧。

### 4. 客户端

代理给客户端呈现的是 `proxy.crt`（自签），所以 curl 要显式带上它：

```powershell
curl --cacert C:\Users\ZYLQQ\Project\C++\SimpleProxy-V2\tlstest\proxy.crt https://127.0.0.1:1200
```

`curl -k` 可以跳过校验。

`SEC_E_UNTRUSTED_ROOT` 出现在 **TLS 握手完成之后**的链校验阶段，说明**代理的 `SSL_accept` 已经成功了**，别把它当成代理故障。

---

## 日志判读

### 启动阶段

| 日志 | 含义 |
|---|---|
| `Windows has no RLIMIT_NOFILE...` | 平台降级提示，正常 |
| `server.tls.cert file: ...` | 代理证书已载入 |
| `client.tls.cert file: ...` | 后端 CA bundle 已载入（新实现，缺省不打印） |
| `client.tls.cert is empty: backend certificate verification will only use...` | 没配 CA，只靠 OpenSSL 默认路径，失败时看这条 |
| `Init: binding to IP 0.0.0.0, port N` + `listen success` | 监听就绪 |

### 连接阶段

| 日志 | 含义 |
|---|---|
| `Connect: connecting to 0.0.0.0, treated as localhost` | connect 路径的 0.0.0.0 已按回环处理 |
| `Connect: target IP x.x.x.x, port N` | **端口从 `serverAddr.sin_port` 取**，不是请求值 |
| `Connect: connect() failed - ...` | 建连失败，看错误文本 |
| `Connect to server success` | 后端 TCP 已建立 |
| `TLS Accept success` | 对客户端握手成功 |
| `New TLS connection established - Client: ... (SNI: ...) -> Backend` | 整条链路就绪 |
| `TLS proxy worker started` | 转发循环已启动 |

### 常见故障对照

| 现象 / 日志 | 原因 |
|---| --- |
| `server.tls.cert file not exists` | 路径没解析到 —— 代理不在证书目录启动 |
| `configureClientContext failed` | `SSL_CTX_set_default_verify_paths()` 或 `SSL_CTX_load_verify_locations()` 失败 |
| `SSL_connect failed - ...unable to get local issuer certificate` | 后端 CA bundle 缺失或不含签发者 |
| `...certificate verify failed` + 前面没有 `Connect: target IP` 正常日志 | 检查实际连的端口（日志已改成打印结构体里的真实端口） |
| 主机名不匹配 | `client.tls.sni` 与后端证书 CN/SAN 不一致 |
| `no usable SNI for backend...` | `sni` 读成了空串，只做链校验 |
| `SSL accept failed for client` | 客户端不信任代理证书 |
| `exec_mission error` | 线程池打满，调大 `maxWokers` |
| `Socket read or write timeout` | 空闲超时断开 |
| 静默断开、无超时日志 | `readOrWriteTimeoutMs > 0` 且走 Windows —— 检查 `netIsWouldBlock` 是否包含 `WSAETIMEDOUT` |
| `getpeername failed` | 通常伴随前一个错误，先看它前面那条 |

---

## 代码级验证手段

### 重复展开验证

Platform 头会被展开 5 次（见 [platform.md](platform.md)）。专门 TU 验证：

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
/* 下面 5 组各重复 5 次 */
#include "PlatformBase.h"
#include "PlatformSocketWindows.h"
#include "PlatformErrorWindows.h"
#include "PlatformMutexWindows.h"
#include "PlatformTimeWindows.h"
#include "PlatformWaitWsapol.h"
/* ...再重复 4 遍... */

int main(void) { /* 实际调用一遍 netWsaStartup / netMutex* / netLocalTime / netResolveIpv4 */ }
```

MSVC `/W4` 下要求 **0 error 0 warning**。

### OpenSSL 行为探针

不启动代理就能验证 `configureClientContext()` + `connectTlsServer()` 的行为 —— 用项目实际链接的那份 OpenSSL 写个小程序：

```c
SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
SSL_CTX_set_default_verify_paths(ctx);
SSL_CTX_load_verify_locations(ctx, caBundle, NULL);
// 然后自己 socket() + connect() + SSL_set_fd + SNI + SSL_set1_host + SSL_connect
```

**要自己 `connect()` 再 `SSL_set_fd`，不要用 `BIO_new_ssl_connect()`** —— 后者是 OpenSSL 自己解析域名 + 建连的另一条路径，实测在 Windows 上会以 `wrong version number` 失败，和项目的实际路径行为不一致，容易误判。

统计信任库里的证书数：

```c
STACK_OF(X509) *objs = (STACK_OF(X509) *)X509_STORE_get0_objects(SSL_CTX_get_cert_store(ctx));
printf("certs = %d\n", objs ? sk_X509_num(objs) : 0);
```

判断 bundle 里有没有某个 CA：

```powershell
openssl crl2pkcs7 -nocrl -certfile ca-bundle.crt | openssl pkcs7 -print_certs -noout
```

### 依赖链接检查

```powershell
dumpbin /dependents build\Release\SimpleProxy.exe
```

应能看到 `WS2_32.dll`。`CRYPT32.dll` 会被静态链进去。

---

## grep 闸门

改完代码跑一遍。注意先剥掉注释，否则中文注释里描述规则的字样会被误判。

| 检查 | 期望 | 已知例外 |
| --- | --- | --- |
| `Platform/` 头内 `#pragma once` / `#ifndef` / `__XXX__` guard | 0 | 无 |
| `Platform/` 头内 `#include` | 0 | 无 |
| `Platform/` 头内 `struct` / `enum` **定义**（带 `{`） | 0 | 只有不完整前置声明 `struct PlatformWaitSet;` |
| 裸 `Socket/aSocket/bSocket/clientFd >= 0`、`< 0`、`-> fd = -1` | 0 | `PlatformWaitEpoll.c` 里的 `epollDescriptor` 是 epoll 的 fd 不是套接字，普通 `int`、`-1` 就是它的失效值 |
| `epoll_*` / `WSAPoll` / `POLLRDNORM` / `POLLWRNORM` / `closesocket` / `SD_BOTH` / `WSA*` / `pthread_*` / `posix_memalign` / `_aligned_*` / `localtime_r` / `localtime_s` 在 `src/Platform/` 外 | 0 | `headfile.h` 的系统头包含行（`sys/epoll.h`、`netdb.h`）与 `main.cpp` 里的 `"epoll"` 配置字符串解析属正常 |
| `.cpp` 中 `CharString` | 0 | 锁住 `Log.h` 不加 `extern "C"` 的前提 |
| `inline` 在 `.c` / `.cpp` / 头文件里 | 0 | `ThreadpoolSimple.hpp:138` 和 `ThreadpoolAutoCtrlByTime.hpp:88` 两处**模板函数必须** inline（模板不能放在 `.cpp`），是既有且必要的用法 |
| 每个 `.c`/`.cpp` 的 `#include` 数量 | 1 个 | `src/Platform/*.c` 6 个文件是 2 个（`headfile.h` + 自己模块的头），原因见 [structure.md](structure.md) |
