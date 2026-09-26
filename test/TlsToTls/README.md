# TlsToTls

**TLS 客户端 → 代理 → TLS 后端**（`config.tls.enable: true`）

覆盖 TLS 转发链路：对客户端 `SSL_accept`、对后端 `SSL_connect`、CA 信任、SNI 处理、`netWaitSet` 转发循环。代理这一侧一条连接只占 **1 个 worker**（epoll/WSAPoll 同时监听两端 fd）。

## 文件

| 文件 | 说明 |
| --- | --- |
| `config.tls.yml` | 最小配置 |
| `proxy.crt` / `proxy.key` | 代理自己的自签证书与私钥，给客户端用 |
| `ca-bundle.crt` | 后端 CA bundle（公共 CA 集合，150 张），给代理验后端证书用 |

## 端口

| 角色 | 端口 |
| --- | --- |
| 代理监听 | `1200` |
| 后端 | 公网站点的 `443` |

## 两个独立握手

```
curl  ──TLS──>  代理（SSL_accept，用 proxy.crt）──TLS──>  www.baidu.com（SSL_connect）
```

`tls.enable: true` 时代理**一定**会对后端做 `SSL_connect`，所以后端也必须是 TLS 服务。三个条件要同时成立：

1. `proxy.crt` / `proxy.key` 存在
2. 后端证书能被信任库验证
3. `client.tls.sni` 匹配后端证书的 CN/SAN

## 操作步骤

### 1. 起代理（窗口 A）

**必须在本目录下启动**，因为配置里的证书路径是相对路径：

```powershell
cd C:\Users\ZYLQQ\Project\C++\SimpleProxy-V2\test\TlsToTls
..\..\build\Release\SimpleProxy.exe -c config.tls.yml
```

应看到：

```
server.tls.cert file: proxy.crt
server.tls.privkey file: proxy.key
client.tls.sni: "www.baidu.com"
client.tls.cert file: ca-bundle.crt
Init: binding to IP 0.0.0.0, port 1200
Init: listen success
TLS server started successfully on 0.0.0.0:1200
```

### 2. 打数据（窗口 B）

代理给客户端呈现的是 `proxy.crt`（自签），所以客户端要显式带上它：

```powershell
curl --cacert C:\Users\ZYLQQ\Project\C++\SimpleProxy-V2\test\TlsToTls\proxy.crt https://127.0.0.1:1200
```

或者用 openssl（OpenSSL 1.1+ 起 `s_client` 是子命令，不再是独立 exe）：

```powershell
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" s_client -connect 127.0.0.1:1200 -servername localhost -CAfile proxy.crt
```

### 3. 退出

窗口 A 输 `exit` 回车。

## `SEC_E_UNTRUSTED_ROOT` 不是代理故障

curl / schannel 报这个错时，**说明代理的 `SSL_accept` 已经成功了** —— 链校验发生在 TLS 握手**完成之后**，能报这个错就证明握手通过了。缺 `--cacert` 时的正确命令：

```powershell
curl --cacert ...\proxy.crt https://127.0.0.1:1200
curl -k https://127.0.0.1:1200     # 跳过校验
```

`proxy.crt` 的 SAN 里有 `IP:127.0.0.1` 和 `DNS:localhost`，所以连 `https://127.0.0.1:1200` 能过主机名校验。

## 后端证书的信任（最容易卡住的一步）

`configureClientContext()` 走 `SSL_VERIFY_PEER` + `SSL_CTX_set_default_verify_paths()` + `SSL_CTX_load_verify_locations(client.tls.cert)`。

**坑：`SSL_CTX_set_default_verify_paths()` 只要"目录存在"就返回 1，哪怕里面一张 CA 都没有。** 很多 Windows 部署上它的默认路径（`%COMMONFILES%\SSL\certs`、`cert.pem`）是空的，于是**所有**后端握手都以 `certificate verify failed` 失败，而函数返回成功、看不出问题。

所以 `client.tls.cert` 必须填一个**真正的 CA bundle**：

| 文件 | 大小 | 内含证书数 | 能不能用 |
| --- | --- | --- | --- |
| `ca-bundle.crt`（本目录自带） | 229 KB | 150 | ✅ |
| `proxy.crt` | 1.1 KB | 1 | ❌ 自签叶子证书，验不了公共 CA 签发的后端 |

大小和数量是快速判据。

`client.tls.cert` 是**追加不是替换** —— 配了自签 CA 之后公共 CA 依然能用，所以自签后端和公网后端可以共存。

留空的话只依赖 OpenSSL 默认信任库，Windows 上默认为空。启动日志会有一条 `client.tls.cert is empty: ...` 提示这件事。

## 换成本地自签后端

想不依赖外网时，可以把后端换成本地自签 TLS 服务：

```powershell
cd C:\Users\ZYLQQ\Project\C++\SimpleProxy-V2\test\TlsToTls
$ossl = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

# 后端证书，SAN 必须带 localhost
& $ossl req -x509 -newkey rsa:2048 -nodes -days 365 `
  -keyout backend.key -out backend.crt -subj "/CN=localhost" `
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# 起 TLS 回显后端
& $ossl s_server -accept 19901 -cert backend.crt -key backend.key -www
```

配置改成：

```yaml
client:
  host: "127.0.0.1"
  port: 19901
  tls:
    sni: "localhost"      # 要和后端证书的 CN/SAN 一致
    cert: backend.crt     # 自签 CA，不是 proxy.crt
```

**`-addext "subjectAltName=..."` 不能省。** OpenSSL 1.0.2 起（Windows 也一样）主机名校验**不再看 CN 字段，只看 SAN**。只写 `-subj "/CN=localhost"` 会导致主机名校验失败。

## 故障定位

| 日志关键字 | 含义 |
| --- | --- |
| `server.tls.cert file not exists` | 相对路径没解析到 —— **代理不在本目录启动** |
| `client.tls.cert file not exists` | 同上，`ca-bundle.crt` 没找到 |
| `configureClientContext failed` | CA 文件加载失败，或系统信任库路径完全不可用 |
| `SSL_connect failed - ...unable to get local issuer certificate` | 后端 CA bundle 缺失或不含签发者 |
| `...certificate verify failed` | 同上，信任链建不起来 |
| 主机名不匹配 | `client.tls.sni` 与后端证书 CN/SAN 不一致 |
| `no usable SNI for backend...` | `sni` 读成了空串，只做链校验（不算失败，会打 WARN） |
| `SSL accept failed for client` | 客户端不信任 `proxy.crt` —— 缺 `--cacert` |
| `TLS Accept success` 但后面没 `New TLS connection established` | 客户端握手过了，后端握手没过，看上面几条 |

## 裸键陷阱

YAML 里**只写键名不写值**（裸键）等于 null，而 yaml-cpp 的 `as<std::string>(fallback)` 对 null 节点返回的是字面量字符串 `"null"` 而不是 fallback。所以：

```yaml
sni:      # ✗ 读成 "null"，会真的拿 "null" 当 SNI 发给后端并按它校验证书
sni: ""   # ✓
```

表现是所有握手失败且**没有任何告警**。代码侧已加 `normalizeConfigString()` 兜底，但配置本身写 `""` 更清楚。

`config.tls.enable` 也要写 `false` 而不是裸键，否则会被当成字符串 `"false"` —— `as<bool>` 解析失败会抛 `YAML::Exception` 导致启动失败。

## 已知限制

- `client.host` 的 `0.0.0.0` 在两平台现在行为一致（都按回环处理），但测试里写 `127.0.0.1` 或域名更利于排查
- `connectTimeoutMs` / `acceptTimeoutMs` 实际是通过 `SO_SNDTIMEO` / `SO_RCVTIMEO` 实现的，**对 `connect()` 和 `accept()` 本身不一定生效**，两个平台都是
- Windows 上 Ctrl+C 可能卡住（`std::cin` 阻塞），用 `exit` 回车退出
- 后端换真实公网站点后，`readOrWriteTimeoutMs` 5 秒偏紧，慢响应场景要调大
