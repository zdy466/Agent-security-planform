# AgentShield OS API 参考文档

## 核心类

### AgentShieldClient

主客户端类，整合所有安全模块。

```python
from agentshield import AgentShieldClient
```

#### 构造函数

```python
AgentShieldClient(config: Optional[Dict[str, Any]] = None)
```

**参数:**
- `config` (Dict, optional): 配置字典

**配置项:**
```python
config = {
    "security_layer": {...},
    "firewall": {...},
    "tool_manager": {...},
    "data_gateway": {...},
    "audit_logger": {...}
}
```

#### 方法

##### process_input

处理用户输入

```python
result = client.process_input(data: str, user: Optional[str] = None) -> Dict[str, Any]
```

**返回:**
```python
{"allowed": True, "data": "processed data"}
# 或
{"allowed": False, "reason": "sensitive_data_detected"}
```

##### process_output

处理 Agent 输出

```python
result = client.process_output(data: str, user: Optional[str] = None) -> Dict[str, Any]
```

##### execute_tool

执行工具

```python
result = client.execute_tool(tool_name: str, params: Dict[str, Any], user: Optional[str] = None) -> Any
```

##### read_data

读取数据

```python
result = client.read_data(source: str, query: Optional[Dict[str, Any]] = None, user: Optional[str] = None) -> Any
```

##### get_audit_events

获取审计事件

```python
events = client.get_audit_events(**kwargs) -> List[AuditEvent]
```

---

## 安全模块

### SecurityLayer

核心安全层

```python
from agentshield import SecurityLayer
```

#### 构造函数

```python
SecurityLayer(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "enabled": True,
    "security_level": "high",  # low, medium, high, critical
    "request_interceptor": {...},
    "response_interceptor": {...},
    "tool_call_interceptor": {...},
    "data_access_interceptor": {...},
    "llm_request_interceptor": {...}
}
```

#### 方法

| 方法 | 说明 |
|------|------|
| `validate_input(data)` | 验证输入 |
| `validate_output(data)` | 验证输出 |
| `intercept_tool_call(data)` | 拦截工具调用 |
| `intercept_data_access(data)` | 拦截数据访问 |
| `intercept_llm_request(request)` | 拦截 LLM 请求 |
| `sanitize(data)` | 消毒数据 |
| `check_permission(action, resource)` | 检查权限 |
| `get_security_events(limit)` | 获取安全事件 |

---

### LLMDataFirewall

LLM 数据防火墙

```python
from agentshield import LLMDataFirewall
```

#### 构造函数

```python
LLMDataFirewall(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "enabled": True,
    "blocker": {
        "block_critical": True,
        "block_high": True,
        "block_medium": False
    },
    "detector": {
        "min_sensitivity": "low"  # low, medium, high, critical
    },
    "minimizer": {
        "max_length": 1000,
        "summary_length": 200
    },
    "enable_data_minimization": False
}
```

#### 方法

| 方法 | 说明 |
|------|------|
| `check_input(data)` | 检查输入 |
| `check_output(data)` | 检查输出 |
| `sanitize(data)` | 消毒数据 |
| `add_rule(name, pattern, action)` | 添加规则 |

---

### PromptInjectionFirewall

Prompt 注入防火墙

```python
from agentshield import PromptInjectionFirewall
```

#### 构造函数

```python
PromptInjectionFirewall(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "enabled": True,
    "block_threshold": "medium",
    "log_only": False,
    "auto_sanitize": True,
    "whitelist_sources": ["trusted_source"],
    "custom_patterns": [...]
}
```

#### 方法

| 方法 | 说明 |
|------|------|
| `check(text, source)` | 检查文本 |
| `check_content(content, type)` | 检查内容 |
| `add_custom_pattern(pattern, description, threat)` | 添加自定义模式 |
| `add_whitelist_source(source)` | 添加白名单源 |

---

### ToolManager

工具管理器

```python
from agentshield import ToolManager
```

#### 构造函数

```python
ToolManager(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "enabled": True,
    "whitelist": ["tool1", "tool2"],
    "enable_whitelist": True,
    "sandbox": {
        "enabled": True,
        "timeout": 30,
        "blocked_commands": [...]
    },
    "validator": {
        "strict_mode": True
    }
}
```

#### 方法

| 方法 | 说明 |
|------|------|
| `register_tool(name, func, ...)` | 注册工具 |
| `unregister_tool(name)` | 注销工具 |
| `can_execute(tool_name)` | 检查是否可执行 |
| `execute(tool_name, params)` | 执行工具 |
| `validate_parameters(tool_name, params)` | 验证参数 |
| `get_history(limit)` | 获取执行历史 |

---

### DataGateway

数据网关

```python
from agentshield import DataGateway
```

#### 构造函数

```python
DataGateway(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "enabled": True,
    "enable_field_level_control": True,
    "enable_row_level_control": True,
    "enable_data_masking": True
}
```

#### 方法

| 方法 | 说明 |
|------|------|
| `register_data_source(name, type)` | 注册数据源 |
| `grant_permission(source, read, write)` | 授予权限 |
| `set_field_permissions(source, fields)` | 设置字段权限 |
| `read_data(source, query)` | 读取数据 |
| `write_data(source, data)` | 写入数据 |
| `execute_query(source, query)` | 执行查询 |

---

### AuditLogger

审计日志

```python
from agentshield import AuditLogger
```

#### 构造函数

```python
AuditLogger(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "enabled": True,
    "max_events": 10000,
    "persist_to_file": False,
    "log_file_path": "audit.log",
    "log_format": "json"
}
```

#### 方法

| 方法 | 说明 |
|------|------|
| `log(event_type, ...)` | 记录事件 |
| `log_request(...)` | 记录请求 |
| `log_tool_execution(...)` | 记录工具执行 |
| `log_data_access(...)` | 记录数据访问 |
| `log_security_event(...)` | 记录安全事件 |
| `get_events(...)` | 查询事件 |
| `get_metrics()` | 获取指标 |
| `export_events(format)` | 导出事件 |

---

### Monitoring 模块

#### MonitoringDashboard

```python
from agentshield import MonitoringDashboard
```

#### BehaviorMonitor

```python
from agentshield import BehaviorMonitor, BehaviorType
```

---

### Policy 模块

#### PolicyEngine

```python
from agentshield import PolicyEngine, PolicyType
```

#### ComplianceManager

```python
from agentshield import ComplianceManager, ComplianceFramework
```

#### GovernanceSystem

```python
from agentshield import GovernanceSystem, GovernanceDomain
```

---

### Security 模块

#### AttackSimulator

```python
from agentshield import AttackSimulator, SecurityTestSuite, AttackType
```

---

## 新增安全模块 (v0.8.0)

### 数据加密模块

#### DataEncryptor

```python
from agentshield.security import DataEncryptor, EncryptionAlgorithm
```

**构造函数:**
```python
DataEncryptor(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "algorithm": EncryptionAlgorithm.FERNET,  # FERNET, AES256
    "key_rotation_days": 30,
    "master_key_path": "/secure/keys/master.key"
}
```

**方法:**

| 方法 | 说明 | 返回类型 |
|------|------|----------|
| `encrypt(data)` | 加密数据 | Dict[str, Any] |
| `decrypt(encrypted_data)` | 解密数据 | Dict[str, Any] |
| `encrypt_field(field_name, value)` | 加密字段 | str |
| `decrypt_field(field_name, value)` | 解密字段 | Any |
| `rotate_keys()` | 轮换密钥 | None |

#### FieldLevelEncryption

```python
from agentshield.security import FieldLevelEncryption
```

**方法:**

| 方法 | 说明 |
|------|------|
| `encrypt_record(record)` | 加密记录 |
| `decrypt_record(encrypted_record)` | 解密记录 |
| `encrypt_field(field_name, value)` | 加密单个字段 |
| `decrypt_field(field_name, value)` | 解密单个字段 |

### 限流模块

#### RateLimiter

```python
from agentshield.security import RateLimiter, RateLimitAction, RateLimitAlgorithm
```

**构造函数:**
```python
RateLimiter(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "default_rate": 100,
    "window_seconds": 60,
    "algorithm": "sliding_window",  # sliding_window, token_bucket
    "storage": "memory"  # memory, redis
}
```

**方法:**

| 方法 | 说明 |
|------|------|
| `check_rate_limit(client_id)` | 检查限流 |
| `add_rule(path, rate, window, action)` | 添加规则 |
| `remove_rule(path)` | 删除规则 |
| `get_remaining(client_id)` | 获取剩余请求数 |
| `reset_client(client_id)` | 重置客户端 |

#### DistributedRateLimiter

```python
from agentshield.security import DistributedRateLimiter
```

**配置项:**
```python
{
    "redis_url": "redis://localhost:6379/0",
    "default_rate": 1000,
    "window_seconds": 60
}
```

### WAF 模块

#### WebApplicationFirewall

```python
from agentshield.security import WebApplicationFirewall, ThreatLevel, AttackType
```

**构造函数:**
```python
WebApplicationFirewall(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "mode": "blocking",  # monitoring, blocking
    "threat_threshold": 5,
    "rules": [...],
    "custom_patterns": [...]
}
```

**方法:**

| 方法 | 说明 |
|------|------|
| `check_request(request)` | 检查请求 |
| `add_rule(rule)` | 添加规则 |
| `remove_rule(rule_id)` | 删除规则 |
| `get_threat_level()` | 获取威胁级别 |

**枚举:**

| 枚举 | 值 |
|------|-----|
| `ThreatLevel` | SAFE, LOW, MEDIUM, HIGH, CRITICAL |
| `AttackType` | SQL_INJECTION, XSS, COMMAND_INJECTION, PATH_TRAVERSAL |
| `WAFAction` | ALLOW, BLOCK, LOG_ONLY |

### 密钥轮换模块

#### KeyRotationManager

```python
from agentshield.security import KeyRotationManager, KeyType, KeyStatus
```

**构造函数:**
```python
KeyRotationManager(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "storage_path": "/secure/keys",
    "auto_rotate": True,
    "rotation_days": 90,
    "notify_before_days": 7
}
```

**方法:**

| 方法 | 说明 |
|------|------|
| `add_key(key_type, key_value, provider, expires_days)` | 添加密钥 |
| `rotate_key(key_id)` | 轮换密钥 |
| `get_key(key_id)` | 获取密钥 |
| `list_keys(provider)` | 列出密钥 |
| `revoke_key(key_id)` | 撤销密钥 |

**枚举:**

| 枚举 | 值 |
|------|-----|
| `KeyType` | API_KEY, SECRET_KEY, ENCRYPTION_KEY |
| `KeyStatus` | ACTIVE, EXPIRED, ROTATING, REVOKED |

### LLM 模块

#### BaseLLMProvider

```python
from agentshield.security import BaseLLMProvider, ProviderType
```

#### LLMProviderFactory

```python
from agentshield.security import LLMProviderFactory, ProviderType
```

**方法:**

| 方法 | 说明 |
|------|------|
| `create_provider(provider_type, config)` | 创建提供商 |
| `list_providers()` | 列出可用提供商 |

**枚举:**

| 枚举 | 值 |
|------|-----|
| `ProviderType` | OPENAI, ANTHROPIC, AZURE_OPENAI, GOOGLE_VERTEX, LOCAL |

#### LLMGateway

```python
from agentshield.security import LLMGateway, LoadBalancingStrategy
```

**构造函数:**
```python
LLMGateway(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "providers": [...],
    "strategy": LoadBalancingStrategy.ROUND_ROBIN,
    "enable_cache": True,
    "cache_ttl": 3600,
    "fallback_enabled": True
}
```

**方法:**

| 方法 | 说明 |
|------|------|
| `chat(messages)` | 发送聊天请求 |
| `complete(prompt)` | 补全文本 |
| `add_provider(provider)` | 添加提供商 |
| `remove_provider(provider_id)` | 移除提供商 |
| `get_metrics()` | 获取指标 |

### SIEM 模块

#### SIEMIntegrator

```python
from agentshield.security import SIEMIntegrator, SIEMProvider
```

**构造函数:**
```python
SIEMIntegrator(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "provider": SIEMProvider.SPLUNK,  # SPLUNK, ELASTICSEARCH
    "hec_url": "https://splunk:8088",
    "hec_token": "token",
    "batch_size": 100,
    "format": "json"  # json, cef
}
```

**方法:**

| 方法 | 说明 |
|------|------|
| `send_log(event)` | 发送日志 |
| `send_batch(events)` | 批量发送 |
| `query_logs(query)` | 查询日志 |

#### SplunkClient

```python
from agentshield.security import SplunkClient
```

#### ElasticsearchClient

```python
from agentshield.security import ElasticsearchClient
```

### 告警模块

#### AlertEscalator

```python
from agentshield.security import AlertEscalator, AlertSeverity, AlertStatus
```

**构造函数:**
```python
AlertEscalator(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "enabled": True,
    "escalation_timeout_minutes": 30,
    "max_escalations": 5
}
```

**方法:**

| 方法 | 说明 |
|------|------|
| `create_alert(title, description, severity, source)` | 创建告警 |
| `escalate(alert)` | 升级告警 |
| `add_channel(notifier)` | 添加通知渠道 |
| `resolve(alert_id)` | 解决告警 |

**枚举:**

| 枚举 | 值 |
|------|-----|
| `AlertSeverity` | LOW, MEDIUM, HIGH, CRITICAL |
| `AlertStatus` | OPEN, IN_PROGRESS, ESCALATED, RESOLVED |
| `NotificationChannel` | EMAIL, SLACK, PAGERDUTY, WEBHOOK |

#### EmailNotifier

```python
from agentshield.security import EmailNotifier
```

**配置项:**
```python
{
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "from": "alerts@company.com",
    "to": ["security@company.com"],
    "use_tls": True
}
```

#### SlackNotifier

```python
from agentshield.security import SlackNotifier
```

**配置项:**
```python
{
    "webhook_url": "https://hooks.slack.com/xxx",
    "channel": "#security-alerts",
    "username": "AgentShield"
}
```

### 安全评分模块

#### SecurityScorer

```python
from agentshield.security import SecurityScorer, ScoreCategory, RiskLevel
```

**构造函数:**
```python
SecurityScorer(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "enabled": True,
    "weights": {...},
    "thresholds": {...}
}
```

**方法:**

| 方法 | 说明 |
|------|------|
| `assess(security_state)` | 评估安全状态 |
| `get_grade()` | 获取评级 |
| `get_score()` | 获取分数 |
| `get_risk_level()` | 获取风险级别 |
| `get_recommendations()` | 获取建议 |

**枚举:**

| 枚举 | 值 |
|------|-----|
| `ScoreCategory` | ENCRYPTION, AUTHENTICATION, ACCESS_CONTROL, AUDITING |
| `RiskLevel` | LOW, MEDIUM, HIGH, CRITICAL |

### 配置模板模块

#### TemplateManager

```python
from agentshield.security import TemplateManager, TemplateCategory
```

**构造函数:**
```python
TemplateManager(config: Optional[Dict[str, Any]] = None)
```

**方法:**

| 方法 | 说明 |
|------|------|
| `get_template(category)` | 获取模板 |
| `list_templates()` | 列出模板 |
| `apply(template, variables)` | 应用模板 |
| `validate_config(config)` | 验证配置 |

**枚举:**

| 枚举 | 值 |
|------|-----|
| `TemplateCategory` | BASIC, ADVANCED, ENTERPRISE, DEV, PROD, SOC2, GDPR, ISO27001 |

### 策略即代码模块

#### PolicyEngine (security)

```python
from agentshield.security import PolicyEngine, PolicyBundle, PolicyRule
```

**构造函数:**
```python
PolicyEngine(config: Optional[Dict[str, Any]] = None)
```

**配置项:**
```python
{
    "default_action": "deny",
    "enable_audit": True
}
```

**方法:**

| 方法 | 说明 |
|------|------|
| `add_bundle(bundle)` | 添加策略包 |
| `remove_bundle(bundle_id)` | 移除策略包 |
| `evaluate(context)` | 评估策略 |
| `validate_policy(policy)` | 验证策略 |

#### PolicyBundle

```python
from agentshield.security import PolicyBundle
```

#### PolicyRule

```python
from agentshield.security import PolicyRule, PolicyEffect
```

**枚举:**

| 枚举 | 值 |
|------|-----|
| `PolicyEffect` | ALLOW, DENY |
| `PolicyResource` | * (通配符) |

---

## ML 模块

### AnomalyDetector

```python
from agentshield.ml import AnomalyDetector

detector = AnomalyDetector({
    "sensitivity": 0.8,
    "model_type": "isolation_forest"
})
```

**方法:**

| 方法 | 说明 |
|------|------|
| `detect(data)` | 检测异常 |
| `train(data)` | 训练模型 |
| `get_score(data)` | 获取异常分数 |

### RiskScorer

```python
from agentshield.ml import RiskScorer

scorer = RiskScorer({
    "model_path": "models/risk_model.pkl"
})
```

**方法:**

| 方法 | 说明 |
|------|------|
| `score(context)` | 评分 |
| `get_level(score)` | 获取级别 |
| `get_factors()` | 获取风险因素 |

### BehaviorAnalyzer

```python
from agentshield.ml import BehaviorAnalyzer
```

---

## 集成模块

### Cloud Integrations

#### AWS

```python
from agentshield.integrations.cloud.aws import (
    S3Client, DynamoDBClient, LambdaClient, CloudWatchClient
)
```

#### Azure

```python
from agentshield.integrations.cloud.azure import (
    BlobClient, CosmosDBClient, FunctionsClient
)
```

#### GCP

```python
from agentshield.integrations.cloud.gcp import (
    GCSClient, BigQueryClient, CloudFunctionsClient
)
```

#### Aliyun

```python
from agentshield.integrations.cloud.aliyun import (
    OSSClient, FCClient, TableStoreClient
)
```

---

## 企业级模块

### AuthenticationService

```python
from agentshield.enterprise import AuthenticationService, UserRole
```

### RBACEngine

```python
from agentshield.enterprise import RBACEngine, Resource, Action
```

### AdminAPIHandler

```python
from agentshield.enterprise import AdminAPIHandler
```

---

## 枚举类

### 数据类型

| 枚举 | 值 |
|------|-----|
| `DataSensitivity` | LOW, MEDIUM, HIGH, CRITICAL |
| `TrustLevel` | SYSTEM, INTERNAL, AGENT, USER, EXTERNAL |
| `ThreatLevel` | SAFE, LOW, MEDIUM, HIGH, CRITICAL |
| `AttackType` | SQL_INJECTION, XSS, COMMAND_INJECTION, PATH_TRAVERSAL |
| `ComplianceFramework` | GDPR, HIPAA, SOC2, ISO27001, PCI_DSS |
| `GovernanceDomain` | SECURITY, PRIVACY, FAIRNESS |

---

## 异常

| 异常 | 说明 |
|------|------|
| `PermissionError` | 权限不足 |
| `ValueError` | 值错误 |
| `RuntimeError` | 运行时错误 |
| `EncryptionError` | 加密错误 |
| `RateLimitExceededError` | 超过限流 |
| `KeyRotationError` | 密钥轮换错误 |
