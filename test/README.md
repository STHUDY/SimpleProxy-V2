# 测试项目

本目录是 SimpleProxy-V2 的**测试工程**：每个子目录是一个测试场景，含一份最小配置和一份说明文档。

## 命名约定

子目录名是 `客户端协议 To 后端协议`：

| 目录 | 含义 |
| --- | --- |
| `SockToSock/` | 明文客户端 → 代理 → 明文后端 |
| `TlsToTls/` | TLS 客户端 → 代理 → TLS 后端 |

这个命名直接对应代理的两条转发链路（`tls.enable: false` / `true`），便于对照排查。将来要加 `SockToTls`（前端明文、后端 TLS）或 `TlsToSock` 时沿用同一命名。

## 设计约束

**不引入任何测试框架**（无 gtest / catch2 / CTest），原因见 [`../AGENTS.md`](../AGENTS.md)：

> **没有测试、没有 CI、没有 lint / format 配置**。不要擅自引入测试框架。验证方式 = 干净编译 + 手工冒烟。

所以本目录只提供**配置 + 操作说明**，验证动作由人执行。这样做的理由是：本项目能自动判定的只有「字节是否端到端可达」，而连接清理路径、共享状态协议、线程池容量、平台适配层的边界行为都无法用外部脚本可靠判定，硬写只会产出脆弱的假测试。

## 目录结构

```
test/
├── README.md                    本文件
├── SockToSock/
│   ├── README.md                场景说明与操作步骤
│   └── config.sock.yml          最小配置
└── TlsToTls/
    ├── README.md                场景说明与操作步骤
    ├── config.tls.yml           最小配置
    ├── proxy.crt / proxy.key    代理自己的证书与私钥（自签）
    └── ca-bundle.crt            后端 CA bundle
```

配置只写**本场景必需的项**，其余一律走代码默认值（默认值参考见 [`../README.md`](../README.md) 的「配置项参考」）。完整配置样板看仓库根目录的 `config.yml`。

## 前置条件

| 条件 | 用途 |
| --- | --- |
| 已完成编译 | 被测程序 |
| 一个可交互的后端服务 | SockToSock 用回显服务，TlsToTls 用公网站点 |
| `curl` 或 `openssl s_client` | TLS 场景的客户端 |

编译命令见 [`../document/build.md`](../document/build.md)。

## 验证状态

| 场景 | Windows x64 (MSVC) | Linux x64 (gcc) |
| --- | --- | --- |
| SockToSock | 已验证 | **未验证** |
| TlsToTls | 已验证（后端为公网站点） | **未验证** |

Linux 侧改造写成行为等价重构并逐条复核过源码，但**实际编译与冒烟尚未执行**，不能视为已验证。

## 通用注意事项

- **证书和配置里的相对路径都相对进程 CWD 解析**，所以要从场景目录里启动代理（README 里会用 `cd` 明确标出）
- 换端口前先查占用：Windows `Get-NetTCPConnection -State Listen -LocalPort <port>`，Linux `ss -ltnp | grep <port>`
- 退出输 `exit` 回车。**Windows 上 Ctrl+C 可能表现为卡住**（主线程阻塞在 `std::cin`，控制台的 Ctrl+C 未必能打断这个读），见 [`../MISTAKE.md`](../MISTAKE.md)
- 日志级别设 `debug` 才有 `Connect:` / `Init:` 这些定位信息

## 相关文档

| 文档 | 内容 |
| --- | --- |
| [`../document/verify.md`](../document/verify.md) | 完整冒烟流程、故障定位对照表、代码级探针、grep 闸门 |
| [`../document/build.md`](../document/build.md) | Linux / Windows 构建方式与各编译器陷阱 |
| [`../document/platform.md`](../document/platform.md) | 平台差异对照表，排查跨平台行为差异时用 |
| [`../MISTAKE.md`](../MISTAKE.md) | 已核实但未修复的缺陷，行为异常时先查这里 |
| [`../AGENTS.md`](../AGENTS.md) | 开发约定与内存生命周期红线 |
