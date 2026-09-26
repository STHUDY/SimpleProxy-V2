# SockToSock

**明文客户端 → 代理 → 明文后端**（`config.tls.enable: false`）

覆盖明文转发链路：`accept` → `connectSocketServer` → 双向转发 → 连接清理。代理这一侧一条连接占 **2 个 worker**（两个方向各一个），共享一个 `CallbackShareInfo`。

## 文件

| 文件 | 说明 |
| --- | --- |
| `config.sock.yml` | 最小配置，只写本场景必需的项 |

## 端口

| 角色 | 端口 |
| --- | --- |
| 代理监听 | `19800` |
| 后端 | `19801` |

## 操作步骤

### 1. 起回显后端（窗口 A）

需要任何"收到什么就原样发回什么"的 TCP 服务。可以另开一个 PowerShell 窗口跑：

```powershell
$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,19801);$l.Start()
while($true){$c=$l.AcceptTcpClient();$s=$c.GetStream();$b=New-Object byte[] 65536
while(($n=$s.Read($b,0,$b.Length)) -gt 0){$s.Write($b,0,$n);$s.Flush()};$c.Close()}
```

Linux 下换成 `nc -lk 127.0.0.1 19801 -c /bin/cat` 之类的等价物。

### 2. 起代理（窗口 B）

```powershell
cd C:\Users\ZYLQQ\Project\C++\SimpleProxy-V2\test\SockToSock
..\..\build\Release\SimpleProxy.exe -c config.sock.yml
```

应看到：

```
load config success to filepath : config.sock.yml
Init: binding to IP 127.0.0.1, port 19800
Init: listen success
Plain socket server started successfully on 127.0.0.1:19800
```

### 3. 打数据（窗口 C）

```powershell
$c=[System.Net.Sockets.TcpClient]::new("127.0.0.1",19800);$s=$c.GetStream();$s.ReadTimeout=8000
$p=[Text.Encoding]::UTF8.GetBytes("ping");$s.Write($p,0,4);$s.Flush()
$b=New-Object byte[] 1024;$n=$s.Read($b,0,$b.Length)
"received $n bytes: " + [Text.Encoding]::UTF8.GetString($b,0,$n)
```

回显出 `ping` 即通过。代理日志应出现 `New connection established - Client: ... -> Backend: ...` 和 `Socket proxy worker stopped`。

### 4. 退出

窗口 B 输 `exit` 回车。

## 建议覆盖的用例

`read` 返回的长度**与发送长度无关**（TCP 是字节流），所以每种长度都要单独试，不要只试一次小的：

| 用例 | 关注点 |
| --- | --- |
| 1 字节 | 最小载荷 |
| 4 字节 | 常规短报文 |
| 1 KB | 单次 `recv` 能拿完 |
| **8 KB** | 恰好等于 `bufferSize`，覆盖"一包正好填满缓冲"和"需要多次 `send`" |
| 64 KB | 跨多次 `recv`/`send` 循环，验证循环条件与退出 |
| 含 `\n` / `\r\n` 的文本 | 二进制安全，不被当成行处理 |
| 含非 ASCII（中文） | UTF-8 多字节不被截断 |
| 连续 10~20 次连接 | 连接反复建立/释放，清理路径每次都跑到 |
| 8 条并发 | 多连接并存，共享状态协议不串 |

**大小写的对照**特别重要：曾经出现过"只 `read` 一次 4096 字节就断言收到 8192 字节"这种错误判定 —— 8 KB 的消息在 4 KB 缓冲下第一次 `read` 只能拿到 4096，这是 TCP 语义，不是代理的 bug。验证脚本必须**循环读到攒够长度再比对**。

## 故障定位

| 日志关键字 | 含义 |
| --- | --- |
| `New connection established` | 连接建立，后端已连上 |
| `Socket proxy worker stopped` | 清理路径跑到了 —— 缺这条说明连接没被正常回收 |
| `Connect: target IP 127.0.0.1, port 19801` | **端口从 `serverAddr.sin_port` 取**，不是请求值 |
| `Connect: connect() failed` | 连不上后端，检查后端是否在 19801 监听 |
| `recv error` | 读取出错，数字应该接近 0 |
| `SECURITY: Access denied` | 防火墙拦了（`config.sock.yml` 里两个列表都是空，正常不会出现） |
| `exec_mission error` | 线程池打满。本场景 `maxWokers` 默认 15，8 条并发没问题 |

代理日志里 `Connect: target IP` 那行的端口如果显示 `0`，说明地址结构体里的端口被覆盖了 —— `netResolveIpv4()` 只能填 `sin_family` 和 `sin_addr`，碰 `sin_port` 就是 bug（历史上发生过，见 `../../MISTAKE.md`）。

## 已知限制

- `acceptTimeoutMs` 在两个平台上都**不生效**：给监听 socket 设 `SO_RCVTIMEO` 不会让 `accept()` 超时。这是既有设计问题，不是移植引入的
- 本场景用 `127.0.0.1` 而非 `0.0.0.0` 作为 `client.host`。`0.0.0.0` 在两个平台上现在行为一致（都按回环处理），但测试里写明确的地址更利于排查
- `readOrWriteTimeoutMs` 走代码默认 `-1`（不超时）。测试期间客户端由自己控制收发，不会挂住；但如果要测空闲超时断开，参考 [`../../document/verify.md`](../../document/verify.md) 的「手工检查项」
