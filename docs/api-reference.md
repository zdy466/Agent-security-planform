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

## 枚举类

### 数据类型

| 枚举 | 值 |
|------|-----|
| `DataSensitivity` | LOW, MEDIUM, HIGH, CRITICAL |
| `TrustLevel` | SYSTEM, INTERNAL, AGENT, USER, EXTERNAL |
| `ThreatLevel` | LOW, MEDIUM, HIGH, CRITICAL |
| `AttackType` | PROMPT_INJECTION, DATA_LEAKAGE, TOOL_ABUSE, KEY_EXTRACTION |
| `ComplianceFramework` | GDPR, HIPAA, SOC2, ISO27001, PCI_DSS |
| `GovernanceDomain` | SECURITY, PRIVACY, FAIRENCY |

---

## 异常NESS, TRANSPAR

| 异常 | 说明 |
|------|------|
| `PermissionError` | 权限不足 |
| `ValueError` | 值错误 |
| `RuntimeError` | 运行时错误 |
