"""Unit tests for AgentShield OS components"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield.firewall.llm_data_firewall import (
    LLMDataFirewall,
    SensitiveDataDetector,
    DataBlocker,
    DataSensitivity
)
from agentshield.toolguard.tool_manager import (
    ToolManager,
    ParameterValidator,
    ParameterType,
    ParameterSchema
)
from agentshield.datagateway.data_gateway import (
    DataGateway,
    DataSourceType,
    FieldPermission,
    DataMasker
)
from agentshield.audit.audit_logger import AuditLogger
from agentshield.core.security_layer import SecurityLayer, TrustLevel


class TestLLMDataFirewall(unittest.TestCase):
    def setUp(self):
        self.firewall = LLMDataFirewall()

    def test_email_detection(self):
        result = self.firewall.check_input("Contact me at test@example.com")
        self.assertFalse(result["allowed"])
        self.assertIn("sensitive_data_detected", result["reason"])

    def test_phone_detection(self):
        result = self.firewall.check_input("Call me at 13812345678")
        self.assertFalse(result["allowed"])

    def test_api_key_detection(self):
        result = self.firewall.check_input("API Key: sk-1234567890abcdefghijklmnop")
        self.assertFalse(result["allowed"])

    def test_normal_text(self):
        result = self.firewall.check_input("Hello, how are you?")
        self.assertTrue(result["allowed"])

    def test_sanitize(self):
        text = "Email: test@example.com"
        sanitized = self.firewall.sanitize(text)
        self.assertNotIn("test@example.com", sanitized)


class TestToolManager(unittest.TestCase):
    def setUp(self):
        self.tool_manager = ToolManager()

    def test_register_tool(self):
        def sample_func(x):
            return x * 2

        self.tool_manager.register_tool("doubler", sample_func, "Doubles input")
        tool = self.tool_manager.get_tool("doubler")
        self.assertIsNotNone(tool)
        self.assertEqual(tool.name, "doubler")

    def test_execute_allowed_tool(self):
        def add(a, b):
            return a + b

        self.tool_manager.register_tool("add", add, "Add two numbers")
        self.tool_manager.whitelist.add("add")

        result = self.tool_manager.execute("add", {"a": 1, "b": 2})
        self.assertEqual(result, 3)

    def test_block_unregistered_tool(self):
        with self.assertRaises(ValueError):
            self.tool_manager.execute("unknown_tool", {})

    def test_parameter_validation(self):
        validator = ParameterValidator()
        
        schema = [
            ParameterSchema("name", ParameterType.STRING, required=True, max_length=50),
            ParameterSchema("age", ParameterType.INTEGER, required=False, min_value=0, max_value=150)
        ]
        
        result = validator.validate({"name": "John", "age": 25}, schema)
        self.assertTrue(result["valid"])
        
        result = validator.validate({}, schema)
        self.assertFalse(result["valid"])


class TestDataGateway(unittest.TestCase):
    def setUp(self):
        self.gateway = DataGateway()

    def test_register_data_source(self):
        self.gateway.register_data_source("test_db", DataSourceType.DATABASE)
        self.assertIn("test_db", self.gateway.data_sources)

    def test_permission_control(self):
        self.gateway.register_data_source("test_db", DataSourceType.DATABASE)
        self.gateway.grant_permission("test_db", read=True, write=False)
        
        self.assertTrue(self.gateway.can_read("test_db"))
        self.assertFalse(self.gateway.can_write("test_db"))

    def test_field_permissions(self):
        self.gateway.register_data_source("users", DataSourceType.DATABASE)
        self.gateway.set_field_permissions("users", [
            FieldPermission("id", readable=True),
            FieldPermission("email", readable=True, maskable=True),
            FieldPermission("password", readable=False)
        ])
        
        self.gateway.grant_permission("users", read=True)
        
        result = self.gateway.read_data("users")
        self.assertIsNotNone(result)


class TestDataMasker(unittest.TestCase):
    def setUp(self):
        self.masker = DataMasker()

    def test_email_masking(self):
        result = self.masker.mask_value("test@example.com", "email")
        self.assertNotIn("test", result)
        self.assertIn("@", result)

    def test_phone_masking(self):
        result = self.masker.mask_value("13812345678", "phone")
        self.assertEqual(result, "138****5678")

    def test_dict_masking(self):
        data = {"email": "test@example.com", "name": "John"}
        result = self.masker.mask_dict(data)
        self.assertNotIn("test@example.com", str(result))


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.audit = AuditLogger({"enabled": True})

    def test_log_event(self):
        self.audit.log(
            event_type="test_event",
            user="test_user",
            action="test_action",
            result="success"
        )
        
        events = self.audit.get_events(event_type="test_event")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].user, "test_user")

    def test_log_security_event(self):
        self.audit.log_security_event(
            event_type="prompt_injection",
            user="attacker",
            severity="warning",
            result="blocked"
        )
        
        events = self.audit.get_security_events()
        self.assertGreater(len(events), 0)

    def test_metrics(self):
        self.audit.log(event_type="test", result="success")
        self.audit.log(event_type="test", result="blocked")
        
        metrics = self.audit.get_metrics()
        self.assertEqual(metrics.total_events, 2)


class TestSecurityLayer(unittest.TestCase):
    def setUp(self):
        self.security = SecurityLayer()

    def test_validate_input(self):
        result = self.security.validate_input("normal text")
        self.assertTrue(result)

    def test_blocked_pattern(self):
        security = SecurityLayer({
            "request_interceptor": {
                "blocked_patterns": ["malicious"]
            }
        })
        
        result = security.validate_input("this is malicious code")
        self.assertFalse(result)

    def test_trust_level(self):
        level = self.security.get_trust_level("external_data")
        self.assertEqual(level, TrustLevel.EXTERNAL)

    def test_sanitize(self):
        result = self.security.sanitize("<script>alert('xss')</script>")
        self.assertNotIn("<script>", result)


class TestIntegration(unittest.TestCase):
    def test_full_workflow(self):
        from agentshield import AgentShieldClient
        
        client = AgentShieldClient({
            "firewall": {"enabled": True},
            "tool_manager": {"enabled": True},
            "data_gateway": {"enabled": True},
            "audit_logger": {"enabled": True}
        })
        
        result = client.process_input("Hello world")
        self.assertTrue(result["allowed"])
        
        events = client.get_audit_events()
        self.assertGreater(len(events), 0)


if __name__ == "__main__":
    unittest.main()
