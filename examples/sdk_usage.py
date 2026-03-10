"""AgentShield OS SDK 使用示例"""

from agentshield import AgentShieldClient
from agentshield.firewall.llm_data_firewall import LLMDataFirewall, SensitiveDataDetector, DataSensitivity
from agentshield.toolguard.tool_manager import ToolManager, ParameterSchema, ParameterType
from agentshield.datagateway.data_gateway import DataGateway, DataSourceType, FieldPermission
from agentshield.audit.audit_logger import AuditLogger
from agentshield.monitoring.dashboard import MonitoringDashboard, DashboardRenderer


def example_basic_usage():
    """基础使用示例"""
    print("=== 基础使用示例 ===")
    
    client = AgentShieldClient()
    
    result = client.process_input("Hello, how are you?")
    print(f"Input processing result: {result}")
    
    result = client.process_output("I'm doing well, thank you!")
    print(f"Output processing result: {result}")


def example_firewall():
    """LLM Data Firewall 示例"""
    print("\n=== LLM Data Firewall 示例 ===")
    
    firewall = LLMDataFirewall()
    
    test_cases = [
        "正常文本内容",
        "请发送邮件到 test@example.com",
        "我的电话是 13812345678",
        "API Key: sk-1234567890abcdefghij",
        "身份证号: 110101199001011234",
    ]
    
    for text in test_cases:
        result = firewall.check_input(text)
        print(f"Input: {text[:30]}...")
        print(f"Result: {result}\n")


def example_tool_guard():
    """Tool Guard 示例"""
    print("\n=== Tool Guard 示例 ===")
    
    tool_manager = ToolManager()
    
    def read_file(path: str) -> str:
        return f"Content of {path}"
    
    def delete_file(path: str) -> bool:
        return True
    
    tool_manager.register_tool(
        name="read_file",
        func=read_file,
        description="Read file content",
        allowed=True,
        parameter_schema=[
            ParameterSchema("path", ParameterType.STRING, required=True, max_length=255)
        ]
    )
    
    tool_manager.register_tool(
        name="delete_file",
        func=delete_file,
        description="Delete file",
        allowed=False
    )
    
    try:
        result = tool_manager.execute("read_file", {"path": "/data/test.txt"})
        print(f"read_file result: {result}")
    except Exception as e:
        print(f"read_file error: {e}")
    
    try:
        result = tool_manager.execute("delete_file", {"path": "/data/test.txt"})
    except PermissionError as e:
        print(f"delete_file blocked: {e}")


def example_data_gateway():
    """Data Gateway 示例"""
    print("\n=== Data Gateway 示例 ===")
    
    gateway = DataGateway()
    
    gateway.register_data_source("users_db", DataSourceType.DATABASE)
    gateway.grant_permission("users_db", read=True, write=False)
    
    gateway.set_field_permissions("users_db", [
        FieldPermission("id", readable=True),
        FieldPermission("name", readable=True),
        FieldPermission("email", readable=True, maskable=True),
        FieldPermission("password", readable=False),
    ])
    
    try:
        result = gateway.read_data("users_db")
        print(f"Data read result: {result}")
    except Exception as e:
        print(f"Data read error: {e}")


def example_audit_logging():
    """审计日志示例"""
    print("\n=== 审计日志示例 ===")
    
    audit = AuditLogger({"enabled": True})
    
    audit.log_request(
        user="user@example.com",
        action="login",
        result="success",
        details={"ip": "192.168.1.1"}
    )
    
    audit.log_security_event(
        event_type="prompt_injection",
        user="attacker@example.com",
        result="blocked",
        severity="warning",
        details={"prompt": "malicious prompt..."}
    )
    
    events = audit.get_events(event_type="security_event")
    print(f"Security events count: {len(events)}")
    for event in events:
        print(f"  - {event.event_type}: {event.result}")


def example_monitoring():
    """监控仪表板示例"""
    print("\n=== 监控仪表板示例 ===")
    
    dashboard = MonitoringDashboard()
    
    dashboard.record_request("user1")
    dashboard.record_request("user2")
    dashboard.record_blocked_request("sensitive_data")
    
    dashboard.record_tool_execution("read_file", True)
    dashboard.record_tool_execution("delete_file", False)
    
    dashboard.record_llm_request(100, 250.5)
    
    summary = dashboard.get_dashboard_summary()
    print(f"Dashboard summary: {summary}")
    
    print("\nText dashboard:")
    print(DashboardRenderer.render_text_summary(dashboard))


def example_full_integration():
    """完整集成示例"""
    print("\n=== 完整集成示例 ===")
    
    client = AgentShieldClient({
        "firewall": {
            "enabled": True,
            "blocker": {
                "block_critical": True,
                "block_high": True,
                "block_medium": False
            }
        },
        "tool_manager": {
            "enabled": True,
            "whitelist": ["search", "calculator"]
        },
        "data_gateway": {
            "enabled": True
        },
        "audit_logger": {
            "enabled": True,
            "persist_to_file": True,
            "log_file_path": "agentshield_audit.log"
        }
    })
    
    def calculator(expr: str) -> str:
        try:
            return str(eval(expr))
        except:
            return "Error"
    
    client.tool_manager.register_tool("calculator", calculator, "Simple calculator")
    client.tool_manager.whitelist.add("calculator")
    
    result = client.process_input("Calculate 2+2")
    print(f"Process input: {result}")
    
    try:
        result = client.execute_tool("calculator", {"expr": "2+2"})
        print(f"Tool execution: {result}")
    except Exception as e:
        print(f"Tool error: {e}")
    
    events = client.get_audit_events()
    print(f"Audit events: {len(events)}")


if __name__ == "__main__":
    example_basic_usage()
    example_firewall()
    example_tool_guard()
    example_data_gateway()
    example_audit_logging()
    example_monitoring()
    example_full_integration()
