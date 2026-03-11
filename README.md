# AgentShield OS

<p align="center">
  <img src="https://img.shields.io/badge/version-0.5.0-blue" alt="Version">
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

### 性能优化 (v0.5.0 新增)

| 模块 | 功能 |
|------|------|
| **Async Support** | 异步任务执行、批处理、事件总线 |
| **Redis Cache** | 高性能缓存、TTL支持、分布式缓存 |
| **Connection Pool** | HTTP/数据库连接池、资源复用 |

### 企业级功能 (v0.5.0 新增)

| 模块 | 功能 |
|------|------|
| **User Auth** | JWT认证、密码哈希、会话管理 |
| **RBAC** | 基于角色的访问控制、权限管理 |
| **Admin Dashboard** | Web管理界面、实时监控、告警管理 |

### 框架适配 (v0.5.0 新增)

| 框架 | 支持 |
|------|------|
| LangChain | ✅ |
| LlamaIndex | ✅ |
| AutoGen | ✅ |
| CrewAI | ✅ |
| Vertex AI | ✅ |

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

### 性能优化使用

```python
import asyncio
from agentshield.utils import AsyncRunner, RedisCache, ConnectionPool

# 异步任务执行
runner = AsyncRunner(max_workers=10)
result = await runner.run_async(coroutine)

# Redis缓存
cache = RedisCache()
await cache.connect(host="localhost", port=6379)
await cache.set("key", "value", ttl=300)

# 连接池
pool = ConnectionPool(factory=http_client_factory)
async with pool.acquire() as client:
    response = await client.get(url)
```

### 企业级认证

```python
from agentshield.enterprise import AuthenticationService, RBACEngine

# 认证服务
auth = AuthenticationService(secret_key="your-secret-key")
user = auth.create_user("username", "email@example.com", "password")
token = await auth.login("username", "password")

# RBAC权限控制
rbac = RBACEngine()
rbac.add_policy(policy)
decision = rbac.check_permission(principal_id, action, resource)
```

## 🚀 5分钟快速入门

### 第1步: 安装

```bash
pip install git+https://github.com/zdy466/Agent-security-planform.git
```

### 第2步: 创建安全客户端

```python
from agentshield import AgentShieldClient

# 创建客户端（使用默认配置）
client = AgentShieldClient()
```

### 第3步: 处理用户输入

```python
# 安全输入（允许通过）
result = client.process_input("你好，请帮我写一首诗")
print(result)
# {'allowed': True, 'data': '你好，请帮我写一首诗'}

# 包含敏感数据（自动拦截）
result = client.process_input("我的邮箱是 admin@company.com")
print(result)
# {'allowed': False, 'reason': 'sensitive_data_detected'}
```

### 第4步: 完整配置（可选）

```python
# 自定义安全配置
config = {
    "firewall": {
        "enabled": True,
        "blocker": {
            "block_critical": True,
            "block_high": True,
            "block_medium": True
        }
    },
    "tool_manager": {
        "enabled": True,
        "whitelist": ["search", "calculator", "weather"]
    },
    "audit_logger": {
        "enabled": True
    }
}

client = AgentShieldClient(config)
```

### 第5步: 运行测试

```bash
python -m pytest tests/test_agentshield.py -v
```

**🎉 恭喜！你已完成AgentShield的基础配置**

## 进阶功能

```
┌─────────────────────────────────────────────────────────────┐
│                     AI Agent Layer                          │
│  (LangChain, LlamaIndex, AutoGen, CrewAI, 自定义 Agent)   │
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
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   Behavior  │  │ Compliance  │  │ Governance  │          │
│  │   Monitor   │  │   Manager   │  │   System    │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│           AgentShield Enterprise Layer                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  Auth/RBAC  │  │    Admin    │  │   Utils    │          │
│  │             │  │  Dashboard  │  │ (Cache/Pool)│          │
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
| 0.4.0 | 2026-03-10 | 性能优化、企业级功能、框架适配 |
| 0.3.0 | 2026-03-10 | 第三阶段：攻击模拟、合规、治理 |
| 0.2.0 | 2026-03-10 | 第二阶段：Prompt注入、行为监控、策略引擎 |
| 0.1.0 | 2026-03-10 | 第一阶段：核心安全模块 |

---

<p align="center">
  如果您觉得 AgentShield 有用，请给我们 ⭐️！
</p>
