"""
AgentShield 基础使用示例

本示例展示如何使用 AgentShieldClient 进行基本的输入/输出处理和配置。
"""

import sys
sys.path.insert(0, 'd:\\security')

from agentshield import AgentShieldClient
from agentshield.datagateway.data_gateway import DataSourceType


def main():
    print("=" * 60)
    print("AgentShield 基础使用示例")
    print("=" * 60)

    config = {
        "security_layer": {
            "enabled": True,
            "strict_mode": True
        },
        "firewall": {
            "enabled": True,
            "detector": {
                "enabled_categories": ["email", "api_key_sk", "password_in_url"],
                "min_sensitivity": "medium"
            },
            "blocker": {
                "block_critical": True,
                "block_high": True,
                "block_medium": False
            }
        },
        "tool_manager": {
            "enabled": True,
            "enable_whitelist": True,
            "whitelist": ["read_file", "write_file", "list_directory"]
        },
        "data_gateway": {
            "enabled": True,
            "enable_field_level_control": True,
            "enable_data_masking": True
        },
        "audit_logger": {
            "enabled": True,
            "max_events": 1000,
            "persist_to_file": False
        }
    }

    print("\n1. 创建 AgentShieldClient")
    print("-" * 40)
    client = AgentShieldClient(config)
    print(f"   Client 创建成功!")
    print(f"   - 安全层: {client.security_layer}")
    print(f"   - 防火墙: {client.firewall}")
    print(f"   - 工具管理器: {client.tool_manager}")
    print(f"   - 数据网关: {client.data_gateway}")
    print(f"   - 审计日志: {client.audit_logger}")

    print("\n2. 处理输入数据")
    print("-" * 40)
    safe_input = "Hello, this is a normal user message."
    result = client.process_input(safe_input, user="user1")
    print(f"   输入: {safe_input}")
    print(f"   结果: {result}")

    print("\n3. 测试敏感数据检测")
    print("-" * 40)
    sensitive_input = "Please contact me at test@example.com or call 13800138000"
    result = client.process_input(sensitive_input, user="user1")
    print(f"   输入: {sensitive_input}")
    print(f"   结果: {result}")

    print("\n4. 测试API密钥检测")
    print("-" * 40)
    api_key_input = "My API key is sk-1234567890abcdefghij"
    result = client.process_input(api_key_input, user="user1")
    print(f"   输入: {api_key_input}")
    print(f"   结果: {result}")

    print("\n5. 处理输出数据")
    print("-" * 40)
    safe_output = "Here is the information you requested."
    result = client.process_output(safe_output, user="user1")
    print(f"   输出: {safe_output}")
    print(f"   结果: {result}")

    print("\n6. 测试输出中的敏感数据")
    print("-" * 40)
    sensitive_output = "Your password is: supersecret123"
    result = client.process_output(sensitive_output, user="user1")
    print(f"   输出: {sensitive_output}")
    print(f"   结果: {result}")

    print("\n7. 注册工具并执行")
    print("-" * 40)

    def read_file_impl(filename, **kwargs):
        return f"Content of {filename}"

    def write_file_impl(filename, content, **kwargs):
        return f"Wrote to {filename}"

    client.tool_manager.register_tool(
        "read_file",
        read_file_impl,
        description="Read content from a file",
        allowed=True,
        parameter_schema=[]
    )
    client.tool_manager.register_tool(
        "write_file",
        write_file_impl,
        description="Write content to a file",
        allowed=True,
        requires_approval=False,
        parameter_schema=[]
    )
    print("   工具已注册: read_file, write_file")

    allowed_tools = client.tool_manager.get_allowed_tools()
    print(f"   允许的工具: {allowed_tools}")

    print("\n8. 执行允许的工具")
    print("-" * 40)
    try:
        result = client.execute_tool("read_file", {"filename": "example.txt"}, user="user1")
        print(f"   read_file 执行结果: {result}")
    except Exception as e:
        print(f"   read_file 执行失败: {e}")

    print("\n9. 尝试执行未授权的工具")
    print("-" * 40)
    try:
        result = client.execute_tool("delete_file", {"filename": "important.txt"}, user="user1")
        print(f"   delete_file 执行结果: {result}")
    except PermissionError as e:
        print(f"   delete_file 被阻止: {e}")

    print("\n10. 数据网关读取")
    print("-" * 40)
    client.data_gateway.register_data_source("users", DataSourceType.API)
    client.data_gateway.grant_permission("users", read=True, write=False)

    try:
        data = client.read_data("users", user="user1")
        print(f"   读取数据: {data}")
    except Exception as e:
        print(f"   读取失败: {e}")

    print("\n11. 查看审计事件")
    print("-" * 40)
    events = client.get_audit_events()
    print(f"   审计事件数量: {len(events)}")
    for event in events[-3:]:
        print(f"   - {event.event_type}: {event.action} - {event.result}")

    print("\n12. 获取防火墙统计")
    print("-" * 40)
    stats = client.firewall.get_statistics()
    print(f"   防火墙统计: {stats}")

    print("\n" + "=" * 60)
    print("示例完成!")
    print("=" * 60)


if __name__ == "__main__":
    main()
