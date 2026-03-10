<<<<<<< HEAD
# AgentShield OS

<p align="center">
  <img src="https://img.shields.io/badge/version-0.3.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/python-3.9+-green" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange" alt="License">
  <a href="https://github.com/ZDY466/AgentShield">
    <img src="https://img.shields.io/github/stars/ZDY466/AgentShield?style=social" alt="GitHub stars">
  </a>
</p>

## 简介

AgentShield OS 是一个**企业级 AI Agent 安全运行层（Security Runtime）**，为 AI Agent 提供全面的安全保护。

它位于 AI Agent 与企业系统之间，负责：
- 控制 AI Agent 的行为
- 管理数据访问权限
- 监控异常行为
- 防止敏感数据泄露
- 阻止恶意指令注入

## 核心特性

| 模块 | 功能 |
|------|------|
| **LLM Data Firewall** | 敏感数据检测、脱敏、阻止 |
| **Prompt Injection Firewall** | Prompt 注入攻击防护 |
| **Tool Guard** | 工具白名单、参数验证、沙盒执行 |
| **Data Gateway** | 字段/行级权限控制、数据脱敏 |
| **Behavior Monitor** | 行为分析、异常检测 |
| **Policy Engine** | 统一策略管理 |
| **Attack Simulation** | 安全攻击模拟测试 |
| **Compliance Manager** | GDPR/HIPAA/SOC2 合规 |
| **Governance System** | 安全、隐私、公平性治理 |

## 快速开始

### 安装

```bash
# 从 GitHub 安装
pip install git+https://github.com/ZDY466/AgentShield.git

# 或从源码安装
git clone https://github.com/ZDY466/AgentShield.git
cd AgentShield
pip install -e .
```

### 基础使用

```python
from agentshield import AgentShieldClient

# 创建客户端
client = AgentShieldClient()

# 处理输入
result = client.process_input("Hello, how are you?")
print(result)
# {'allowed': True, 'data': 'Hello, how are you?'}

# 处理敏感数据
result = client.process_input("My email is test@example.com")
print(result)
# {'allowed': False, 'reason': 'sensitive_data_detected'}
```

### 完整配置

```python
client = AgentShieldClient({
    "firewall": {
        "enabled": True,
        "blocker": {
            "block_critical": True,
            "block_high": True
        }
    },
    "tool_manager": {
        "enabled": True,
        "whitelist": ["search", "calculator"]
    },
    "data_gateway": {
        "enabled": True,
        "enable_field_level_control": True
    },
    "audit_logger": {
        "enabled": True,
        "persist_to_file": True
    }
})
```

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                     AI Agent Layer                          │
│  (LangChain, AutoGPT, 自定义 Agent)                        │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│               AgentShield Security Layer                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  Security   │  │  Firewall   │  │    Tool    │          │
│  │    Layer    │  │             │  │   Guard    │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │    Data     │  │   Policy    │  │    Audit   │          │
│  │   Gateway   │  │   Engine    │  │   Logger   │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│              Enterprise Systems Layer                        │
│  (数据库, API, 文档系统, 大模型服务)                       │
└─────────────────────────────────────────────────────────────┘
```

## 文档

- [快速开始指南](docs/quickstart.md)
- [API 参考](docs/api-reference.md)
- [部署指南](docs/deployment.md)
- [安全配置指南](docs/security-config.md)

## 示例

```bash
# 运行示例
python examples/sdk_usage.py
python examples/enterprise_demo.py

# 运行测试
python -m pytest tests/
```

## 社区

### 参与方式

欢迎加入 AgentShield 社区！您可以通过以下方式参与：

- **GitHub Issues** - 报告 bug 或提出功能请求
- **Pull Requests** - 贡献代码
- **Discussions** - 讨论使用问题
- **文档** - 改进文档

### 联系方式

| 渠道 | 地址 |
|------|------|
| GitHub | https://github.com/ZDY466/AgentShield |
| 问题反馈 | https://github.com/ZDY466/AgentShield/issues |
| 功能请求 | https://github.com/ZDY466/AgentShield/discussions |

### 贡献指南

我们欢迎各种形式的贡献！请查看 [贡献指南](CONTRIBUTING.md) 了解如何参与。

## 许可

MIT License - 查看 [LICENSE](LICENSE) 文件了解详情。

## 版本历史

| 版本 | 日期 | 说明 |
|------|------|------|
| 0.3.0 | 2026-03-10 | 第三阶段：攻击模拟、合规、治理 |
| 0.2.0 | 2026-03-10 | 第二阶段：Prompt注入、行为监控、策略引擎 |
| 0.1.0 | 2026-03-10 | 第一阶段：核心安全模块 |

---

<p align="center">
  如果您觉得 AgentShield 有用，请给我们 ⭐️！
</p>
=======
# Agent-security-planform
>>>>>>> d713130b9ae372ba832ddd24698b1cbd21753970
