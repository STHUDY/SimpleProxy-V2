# 技术文档

SimpleProxy-V2 的深度技术资料。这里放**不适合放进 `README.md` 的内容** —— 面向使用者的是 README，面向 AI agent 开发约定的是 `AGENTS.md`，已修复缺陷的成因在 git 历史里。

| 文档 | 内容 |
| --- | --- |
| [structure.md](structure.md) | 目录结构、每个文件职责、命名规范、include 纪律 |
| [architecture.md](architecture.md) | 两条转发链路的完整调用链、线程模型、连接生命周期与内存所有权 |
| [platform.md](platform.md) | 跨平台适配层设计：平台差异对照表、无 guard 约束、接口清单 |
| [build.md](build.md) | Linux / Windows 构建方式与各编译器陷阱 |
| [verify.md](verify.md) | 明文与 TLS 的冒烟验证步骤、故障定位对照表 |

## 配套文档

- [`../README.md`](../README.md) —— 特性、优势、配置项参考、故障排查（面向使用者）
- [`../AGENTS.md`](../AGENTS.md) —— 开发约定与内存生命周期红线（面向改代码的人）
- [`../MISTAKE.md`](../MISTAKE.md) —— 已核实但尚未修复的缺陷及成因

## 当前验证状态

| 平台 | 编译 | 明文转发 | TLS 转发 |
| --- | --- | --- | --- |
| Windows x64 (MSVC 19.51, VS 18 2026) | Debug / Release 均通过 | 已验证 | 已验证（后端为公共 CA 站点） |
| Linux x64 (gcc) | **未验证** | **未验证** | **未验证** |

Linux 侧改造全部写成行为等价重构并逐条复核过源码，但编写本文档时手头没有 gcc，**实际编译与冒烟尚未执行**，不能视为已验证。
