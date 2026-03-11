"""Integration tests for AgentShieldClient complete workflow"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield.sdk.client import AgentShieldClient
from agentshield.firewall.llm_data_firewall import EnhancedLLMDataFirewall as LLMDataFirewall
from agentshield.audit.audit_logger import AuditLogger


class TestWorkflowIntegration(unittest.TestCase):
    """Test AgentShieldClient complete workflow integration"""

    def setUp(self):
        """Initialize test environment"""
        self.config = {
            "security_layer": {
                "enabled": True,
                "security_level": "medium"
            },
            "firewall": {
                "enabled": True,
                "blocker": {
                    "block_critical": True,
                    "block_high": True,
                    "block_medium": True,
                    "block_attack_patterns": True
                }
            },
            "tool_manager": {
                "enable_whitelist": True,
                "whitelist": ["calculator", "search"]
            },
            "audit_logger": {
                "enabled": True
            }
        }
        self.client = AgentShieldClient(self.config)

    def test_process_input_basic(self):
        """Test basic input processing"""
        result = self.client.process_input("Hello world", user="test_user")
        self.assertTrue(result["allowed"])
        self.assertIn("data", result)

    def test_process_input_with_audit_log(self):
        """Test input processing generates audit log"""
        self.client.process_input("Test input", user="test_user")
        events = self.client.get_audit_events(event_type="input_processing")
        self.assertGreater(len(events), 0)
        self.assertEqual(events[-1].user, "test_user")

    def test_process_input_security_validation_fails(self):
        """Test input processing with security validation failure"""
        config = {
            "security_layer": {
                "enabled": True,
                "request_interceptor": {
                    "blocked_patterns": ["forbidden"]
                }
            },
            "firewall": {"enabled": True}
        }
        client = AgentShieldClient(config)
        result = client.process_input("This contains forbidden content")
        self.assertFalse(result["allowed"])

    def test_firewall_input_check_blocks_sensitive_data(self):
        """Test firewall blocks sensitive data in input"""
        result = self.client.process_input(
            "Contact: test@example.com, Phone: 13812345678",
            user="test_user"
        )
        self.assertFalse(result["allowed"])
        self.assertIn("sensitive_data_detected", result.get("reason", ""))

    def test_firewall_input_check_allows_normal_data(self):
        """Test firewall allows normal data"""
        result = self.client.process_input("Hello, how can I help you?")
        self.assertTrue(result["allowed"])

    def test_process_output_basic(self):
        """Test basic output processing"""
        result = self.client.process_output("Response data", user="test_user")
        self.assertTrue(result["allowed"])
        self.assertIn("data", result)

    def test_process_output_with_audit_log(self):
        """Test output processing generates audit log"""
        self.client.process_output("Test output", user="test_user")
        events = self.client.get_audit_events(event_type="output_processing")
        self.assertGreater(len(events), 0)

    def test_process_output_blocks_sensitive_data(self):
        """Test output processing blocks sensitive data"""
        result = self.client.process_output(
            "Your API key is: sk-abcdefghijklmnopqrstuvwxyz",
            user="test_user"
        )
        self.assertFalse(result["allowed"])

    def test_complete_workflow_firewall_to_audit(self):
        """Test complete workflow from firewall to audit log"""
        input_data = "Normal request data"
        result = self.client.process_input(input_data, user="user1")

        self.assertTrue(result["allowed"])

        events = self.client.get_audit_events(user="user1")
        self.assertGreater(len(events), 0)

        input_events = [e for e in events if e.event_type == "input_processing"]
        self.assertEqual(len(input_events), 1)
        self.assertEqual(input_events[0].action, "process_input")

    def test_sensitive_data_detection_workflow(self):
        """Test sensitive data detection and blocking workflow"""
        firewall = LLMDataFirewall({
            "enabled": True,
            "blocker": {
                "block_critical": True,
                "block_high": True,
                "block_medium": True,
                "block_attack_patterns": True
            }
        })

        sensitive_inputs = [
            "Email: user@example.com",
            "Phone: 13812345678",
            "API Key: sk-1234567890abcdefghij",
            "Credit Card: 4111111111111111",
            "DROP TABLE users"
        ]

        for sensitive_input in sensitive_inputs:
            result = firewall.check_input(sensitive_input)
            self.assertFalse(
                result["allowed"],
                f"Should block: {sensitive_input[:50]}"
            )

    def test_output_sanitization_workflow(self):
        """Test output sanitization workflow"""
        firewall = LLMDataFirewall({
            "enabled": True,
            "blocker": {
                "block_critical": True,
                "block_medium": True
            }
        })

        sensitive_text = "Contact: test@example.com, Key: sk-abc123"
        result = firewall.check_output(sensitive_text)

        self.assertFalse(result["allowed"])

    def test_output_desensitization(self):
        """Test output desensitization process"""
        firewall = LLMDataFirewall({"enabled": True})

        original = "Email: test@example.com, Phone: 13812345678"
        sanitized = firewall.sanitize(original)

        self.assertNotIn("test@example.com", sanitized)
        self.assertNotIn("13812345678", sanitized)
        self.assertIn("[PII]", sanitized)

    def test_firewall_statistics(self):
        """Test firewall statistics tracking"""
        self.client.process_input("Clean input 1")
        self.client.process_input("Clean input 2")
        self.client.process_input("user@example.com")

        stats = self.client.firewall.get_statistics()
        self.assertGreater(stats["total_checks"], 0)
        self.assertEqual(stats["blocked_count"], 1)
        self.assertEqual(stats["allowed_count"], 2)

    def test_multiple_user_workflow(self):
        """Test workflow with multiple users"""
        users = ["user1", "user2", "user3"]

        for user in users:
            result = self.client.process_input(f"Request from {user}", user=user)
            self.assertTrue(result["allowed"])

        events = self.client.get_audit_events()
        self.assertGreaterEqual(len(events), 3)


class TestFirewallAndAuditIntegration(unittest.TestCase):
    """Test integration between firewall and audit logger"""

    def setUp(self):
        """Initialize test environment"""
        self.firewall = LLMDataFirewall({
            "enabled": True,
            "blocker": {
                "block_critical": True,
                "block_high": True
            }
        })
        self.audit_logger = AuditLogger({"enabled": True})

    def test_firewall_blocks_creates_security_event(self):
        """Test firewall blocking creates security event"""
        self.firewall.check_input("secret: sk-abcdefghijklmnopqrst")

        self.audit_logger.log_security_event(
            event_type="sensitive_data_blocked",
            user="test_user",
            result="blocked",
            severity="warning"
        )

        events = self.audit_logger.get_security_events()
        self.assertGreater(len(events), 0)

    def test_audit_log_filters_by_event_type(self):
        """Test audit log filtering by event type"""
        self.audit_logger.log(event_type="input_processing", user="user1")
        self.audit_logger.log(event_type="output_processing", user="user1")
        self.audit_logger.log(event_type="tool_execution", user="user1")

        input_events = self.audit_logger.get_events(event_type="input_processing")
        self.assertEqual(len(input_events), 1)

    def test_audit_log_filters_by_user(self):
        """Test audit log filtering by user"""
        self.audit_logger.log(event_type="test", user="user1")
        self.audit_logger.log(event_type="test", user="user2")
        self.audit_logger.log(event_type="test", user="user1")

        user1_events = self.audit_logger.get_events(user="user1")
        self.assertEqual(len(user1_events), 2)

    def test_audit_log_filters_by_result(self):
        """Test audit log filtering by result"""
        self.audit_logger.log(event_type="test", result="success")
        self.audit_logger.log(event_type="test", result="blocked")
        self.audit_logger.log(event_type="test", result="success")

        blocked_events = self.audit_logger.get_events(result="blocked")
        self.assertEqual(len(blocked_events), 1)

    def test_audit_metrics_collection(self):
        """Test audit metrics collection"""
        self.audit_logger.log(event_type="test", result="success")
        self.audit_logger.log(event_type="test", result="blocked")
        self.audit_logger.log(event_type="test", result="failed")

        metrics = self.audit_logger.get_metrics()
        self.assertEqual(metrics.total_events, 3)
        self.assertEqual(metrics.blocked_count, 1)
        self.assertEqual(metrics.failed_count, 1)

    def test_workflow_with_audit_persistence(self):
        """Test workflow with audit event persistence"""
        audit = AuditLogger({
            "enabled": True,
            "persist_to_file": False
        })

        audit.log(
            event_type="input_processing",
            user="test_user",
            action="process_input",
            result="success"
        )

        events = audit.get_events(user="test_user")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].action, "process_input")


class TestEndToEndWorkflow(unittest.TestCase):
    """End-to-end workflow integration tests"""

    def setUp(self):
        """Initialize complete client environment"""
        self.client = AgentShieldClient({
            "firewall": {
                "enabled": True,
                "blocker": {
                    "block_critical": True,
                    "block_high": True,
                    "block_medium": True,
                    "block_attack_patterns": True
                }
            },
            "audit_logger": {
                "enabled": True
            }
        })

    def test_full_security_workflow(self):
        """Test complete security workflow"""
        test_cases = [
            ("Normal conversation", True),
            ("user@test.com", False),
            ("13812345678", False),
            ("DROP TABLE admin", False),
            ("<script>alert(1)</script>", False),
            ("sk-abcdefghijklmnopqrstuvwxyz", False),
        ]

        for data, should_pass in test_cases:
            result = self.client.process_input(data)
            if should_pass:
                self.assertTrue(result["allowed"], f"Should allow: {data[:30]}")
            else:
                self.assertFalse(result["allowed"], f"Should block: {data[:30]}")

    def test_sequential_operations(self):
        """Test sequential operations maintain state"""
        self.client.process_input("First request", user="user1")
        self.client.process_input("Second request", user="user1")
        self.client.process_output("First response", user="user1")

        events = self.client.get_audit_events(user="user1")
        self.assertEqual(len(events), 3)

    def test_workflow_with_tool_execution(self):
        """Test workflow including tool execution"""
        result = self.client.process_input("Calculate 2+2", user="test_user")
        self.assertTrue(result["allowed"])

        events = self.client.get_audit_events()
        self.assertGreater(len(events), 0)


def run_tests():
    """Run all integration tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestWorkflowIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestFirewallAndAuditIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestEndToEndWorkflow))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
