# AgentShield OS 安全配置指南

## 概述

本文档提供 AgentShield OS 的详细安全配置指南，帮助企业根据自身需求定制安全策略。

## 快速配置

### 基础安全配置

```python
from agentshield import AgentShieldClient

client = AgentShieldClient({
    "security_level": "high",
    "firewall": {
        "enabled": True,
        "blocker": {
            "block_critical": True,
            "block_high": True,
            "block_medium": False
        }
    }
})
```

## 详细配置

### LLM Data Firewall 配置

#### 敏感数据检测

```python
from agentshield import LLMDataFirewall

firewall = LLMDataFirewall({
    "enabled": True,
    "detector": {
        "min_sensitivity": "low",
        "enabled_categories": [
            "email", "china_phone", "api_key_sk", 
            "id_card_china", "bank_card", "credit_card",
            "sql_injection", "xss_pattern"
        ],
        "custom_patterns": [
            {
                "pattern": r"your-custom-pattern",
                "sensitivity": "high",
                "category": "CUSTOM"
            }
        ]
    },
    "blocker": {
        "block_critical": True,
        "block_high": True,
        "block_medium": False,
        "block_attack_patterns": True,
        "quarantine_enabled": True
    },
    "minimizer": {
        "max_length": 1000,
        "summary_length": 200,
        "enable_compression": True
    },
    "enable_data_minimization": True,
    "enable_caching": True
})
```

#### 支持的检测模式

| 类别 | 模式 | 敏感度 |
|------|------|--------|
| **PII** | 邮箱 | MEDIUM |
| | 中国电话 | MEDIUM |
| | 香港电话 | MEDIUM |
| | 台湾电话 | MEDIUM |
| | 中国身份证 | CRITICAL |
| | 香港身份证 | CRITICAL |
| | 台湾身份证 | CRITICAL |
| | 护照 | HIGH |
| | 银行卡 | CRITICAL |
| | 信用卡 | CRITICAL |
| **SECRET** | OpenAI API Key | CRITICAL |
| | AWS Access Key | CRITICAL |
| | AWS Secret Key | CRITICAL |
| | GitHub Token | CRITICAL |
| | Slack Token | CRITICAL |
| | 私钥 | CRITICAL |
| **FINANCIAL** | 人民币金额 | HIGH |
| | 美元金额 | HIGH |
| | 欧元金额 | HIGH |
| | 比特币地址 | HIGH |
| **NETWORK** | IP 地址 | LOW |
| | MAC 地址 | LOW |
| **ATTACK** | SQL 注入 | HIGH |
| | XSS 攻击 | HIGH |
| | 命令注入 | HIGH |

### Tool Guard 配置

```python
from agentshield import ToolManager

tool_manager = ToolManager({
    "enabled": True,
    "whitelist": ["search", "calculator", "get_weather"],
    "enable_whitelist": True,
    "sandbox": {
        "enabled": True,
        "timeout": 30,
        "max_memory_mb": 256,
        "allowed_paths": ["/data", "/tmp"],
        "blocked_commands": [
            "rm", "del", "format", "fdisk",
            "shutdown", "reboot", "halt",
            "wget", "curl", "nc", "netcat"
        ]
    },
    "validator": {
        "strict_mode": True
    }
})
```

### Data Gateway 配置

```python
from agentshield import DataGateway, DataSourceType

gateway = DataGateway({
    "enabled": True,
    "enable_field_level_control": True,
    "enable_row_level_control": True,
    "enable_data_masking": True,
    "query_validator": {
        "strict_mode": True,
        "allowed_tables": ["users", "products", "orders"]
    }
})

gateway.register_data_source("users", DataSourceType.DATABASE)
gateway.grant_permission("users", read=True, write=False)

gateway.set_field_permissions("users", [
    FieldPermission("id", readable=True),
    FieldPermission("name", readable=True),
    FieldPermission("email", readable=True, maskable=True),
    FieldPermission("phone", readable=True, maskable=True),
    FieldPermission("password", readable=False),
    FieldPermission("ssn", readable=False),
    FieldPermission("credit_card", readable=False)
])
```

### Prompt Injection Firewall 配置

```python
from agentshield import PromptInjectionFirewall

firewall = PromptInjectionFirewall({
    "enabled": True,
    "block_threshold": "medium",
    "log_only": False,
    "auto_sanitize": True,
    "whitelist_sources": ["trusted_internal"],
    "custom_patterns": [
        {
            "pattern": r"your-custom-injection-pattern",
            "description": "Custom injection detection",
            "threat": "high",
            "confidence": 0.8
        }
    ]
})
```

### Behavior Monitor 配置

```python
from agentshield import BehaviorMonitor

monitor = BehaviorMonitor({
    "enabled": True,
    "max_events_per_session": 1000,
    "session_timeout_minutes": 30,
    "enable_auto_response": True,
    "analyzer": {
        "frequency_threshold": 10,
        "time_window_minutes": 5,
        "risk_score_threshold": 0.7
    }
})

def alert_handler(session_id, result):
    print(f"Alert: {result.description}")

monitor.set_alert_callback(alert_handler)
```

### Policy Engine 配置

```python
from agentshield import PolicyEngine, PolicyType, PolicyAction

engine = PolicyEngine({
    "default_action": "deny",
    "enable_audit": True
})

engine.add_policy(PolicyRule(
    rule_id="allow-read-tools",
    name="Allow Read Tools",
    policy_type=PolicyType.TOOL_POLICY,
    action=PolicyAction.ALLOW,
    conditions={"tool_name": ["read_file", "search"]},
    priority=10
))

engine.add_policy(PolicyRule(
    rule_id="deny-admin-tools",
    name="Deny Admin Tools",
    policy_type=PolicyType.TOOL_POLICY,
    action=PolicyAction.DENY,
    conditions={"tool_name": ["delete_file", "format_disk"]},
    priority=100
))
```

## 安全级别

### 低级别 (Low)

```python
config = {
    "firewall": {"blocker": {"block_critical": True}},
    "tool_manager": {"whitelist": []},
    "data_gateway": {"enable_field_level_control": False}
}
```

### 中级别 (Medium)

```python
config = {
    "firewall": {
        "blocker": {
            "block_critical": True,
            "block_high": True
        }
    },
    "tool_manager": {"whitelist": ["search", "calculator"]},
    "data_gateway": {"enable_field_level_control": True}
}
```

### 高级别 (High)

```python
config = {
    "firewall": {
        "blocker": {
            "block_critical": True,
            "block_high": True,
            "block_medium": True,
            "block_attack_patterns": True
        }
    },
    "tool_manager": {
        "whitelist": ["search"],
        "sandbox": {"enabled": True}
    },
    "data_gateway": {
        "enable_field_level_control": True,
        "enable_data_masking": True
    },
    "prompt_injection_firewall": {"block_threshold": "low"}
}
```

## 最佳实践

### 1. 启用所有安全模块

```python
client = AgentShieldClient({
    "security_layer": {"enabled": True},
    "firewall": {"enabled": True},
    "tool_manager": {"enabled": True},
    "data_gateway": {"enabled": True},
    "audit_logger": {"enabled": True}
})
```

### 2. 定期审查日志

```python
events = client.get_audit_events(limit=100)
security_events = [e for e in events if e.event_type == "security_event"]
```

### 3. 持续更新规则

```python
firewall.add_rule(
    name="block-new-attack",
    pattern=r"new-malicious-pattern",
    action="block"
)
```

## 合规配置

### GDPR 合规

```python
from agentshield import ComplianceManager, ComplianceFramework

compliance = ComplianceManager()
report = compliance.run_framework_compliance(ComplianceFramework.GDPR)
```

### HIPAA 合规

```python
report = compliance.run_framework_compliance(ComplianceFramework.HIPAA)
```

### SOC2 合规

```python
report = compliance.run_framework_compliance(ComplianceFramework.SOC2)
```

## 监控与告警

### 配置监控仪表板

```python
from agentshield import MonitoringDashboard

dashboard = MonitoringDashboard()

dashboard.record_request("user1")
dashboard.record_blocked_request("sensitive_data")

summary = dashboard.get_dashboard_summary()
```

### 配置行为告警

```python
def security_alert_handler(session_id, result):
    send_email(
        to="security@company.com",
        subject=f"Security Alert: {result.anomaly_type}",
        body=result.description
    )

monitor.set_alert_callback(security_alert_handler)
```

## 性能优化

### 启用缓存

```python
firewall = LLMDataFirewall({
    "enable_caching": True
})
```

### 异步处理

```python
import asyncio

async def process_async(text):
    return firewall.check_input(text)
```

## 故障排除

### 常见问题

| 问题 | 解决方案 |
|------|----------|
| 误报率高 | 调整 `min_sensitivity` 阈值 |
| 性能下降 | 启用缓存，减少规则数量 |
| 工具无法使用 | 检查白名单配置 |
| 数据访问被拒 | 检查权限配置 |

### 调试模式

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

如需更多帮助，请参考：
- [API 参考](api-reference.md)
- [部署指南](deployment.md)
- [GitHub Issues](https://github.com/zdy466/Agent-security-planform/issues)
