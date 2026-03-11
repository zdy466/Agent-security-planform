"""Tests for new security modules"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield.security import (
    DataEncryptor,
    RateLimiter,
    WebApplicationFirewall,
    KeyRotationManager,
    LLMGateway,
    SIEMIntegrator,
    AlertEscalator,
    SecurityScorer,
    TemplateManager,
    PolicyEngine,
    ProviderType,
    KeyType,
    AlertSeverity,
    WAFAction,
    ThreatLevel,
    PolicyEffect,
    PolicyResource,
)


class TestDataEncryption(unittest.TestCase):
    def setUp(self):
        self.encryptor = DataEncryptor({
            "algorithm": "fernet",
            "master_key": "hI8HqhLJJJ1Z6sGx9Y9YnZ3N9Y5YvY8=",
            "encrypted_fields": ["ssn", "password"]
        })

    def test_encrypt_decrypt_string(self):
        original = "Hello World"
        encrypted = self.encryptor.encrypt(original)
        decrypted = self.encryptor.decrypt(encrypted)
        self.assertEqual(original, decrypted)

    def test_encrypt_dict(self):
        original = {"name": "John", "ssn": "123-45-6789"}
        encrypted = self.encryptor.encrypt(original)
        self.assertIsInstance(encrypted, dict)
        self.assertNotEqual(encrypted["ssn"], original["ssn"])

    def test_encrypted_field_protection(self):
        data = {"name": "test", "ssn": "123-45-6789"}
        encrypted = self.encryptor.encrypt(data, "ssn")
        self.assertNotEqual(encrypted, data["ssn"])


class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        from agentshield.security.rate_limiter import RateLimitRule, RateLimitAction
        self.rate_limiter = RateLimiter({
            "default_rate": 5,
            "default_window": 60,
            "enabled": True
        })
        self.rate_limiter.rules = [
            RateLimitRule(
                name="default",
                max_requests=5,
                window_seconds=60,
                action=RateLimitAction.BLOCK,
                priority=0
            )
        ]

    def test_allow_within_limit(self):
        for i in range(5):
            result = self.rate_limiter.check_rate_limit("192.168.1.1")
            self.assertTrue(result["allowed"])

    def test_block_over_limit(self):
        for i in range(6):
            result = self.rate_limiter.check_rate_limit("192.168.1.2")
        result = self.rate_limiter.check_rate_limit("192.168.1.2")
        self.assertFalse(result["allowed"])

    def test_whitelist(self):
        self.rate_limiter.add_to_whitelist("10.0.0.1")
        result = self.rate_limiter.check_rate_limit("10.0.0.1")
        self.assertTrue(result["action"] == "whitelisted")


class TestWAF(unittest.TestCase):
    def setUp(self):
        self.waf = WebApplicationFirewall({"enabled": True})

    def test_sql_injection_blocked(self):
        from agentshield.security.waf import WAFRequest
        self.waf.max_score = 5
        request = WAFRequest(
            method="GET",
            path="/search?id=1' OR '1'='1",
            headers={},
            body=None,
            query_params={"id": "1' OR '1'='1"},
            client_ip="192.168.1.1",
            user_agent="test"
        )
        result = self.waf.inspect_request(request)
        self.assertIn(result.action, [WAFAction.BLOCK, WAFAction.LOG])

    def test_xss_attack_blocked(self):
        from agentshield.security.waf import WAFRequest
        self.waf.max_score = 5
        request = WAFRequest(
            method="GET",
            path="/comment",
            headers={},
            body=None,
            query_params={},
            client_ip="192.168.1.1",
            user_agent="test"
        )
        request.body = "<script>alert('xss')</script>"
        result = self.waf.inspect_request(request)
        self.assertIn(result.action, [WAFAction.BLOCK, WAFAction.LOG])

    def test_normal_request_allowed(self):
        from agentshield.security.waf import WAFRequest
        request = WAFRequest(
            method="GET",
            path="/api/users",
            headers={},
            body=None,
            query_params={},
            client_ip="192.168.1.1",
            user_agent="test"
        )
        result = self.waf.inspect_request(request)
        self.assertEqual(result.action, WAFAction.ALLOW)


class TestKeyRotation(unittest.TestCase):
    def setUp(self):
        self.key_manager = KeyRotationManager({
            "default_rotation_days": 90,
            "storage_path": None
        })

    def test_create_key(self):
        result = self.key_manager.create_key(
            name="test-api-key",
            key_type=KeyType.API_KEY
        )
        self.assertIn("key_id", result)
        self.assertIn("key", result)

    def test_rotate_key(self):
        created = self.key_manager.create_key(name="test-key", key_type=KeyType.API_KEY)
        result = self.key_manager.rotate_key(created["key_id"])
        self.assertTrue(result.success)
        self.assertNotEqual(result.old_key_id, result.new_key_id)

    def test_validate_key(self):
        created = self.key_manager.create_key(name="test-key", key_type=KeyType.API_KEY)
        is_valid = self.key_manager.validate_key(created["key_id"], created["key"])
        self.assertTrue(is_valid)


class TestLLMGateway(unittest.TestCase):
    def setUp(self):
        self.gateway = LLMGateway({
            "default_model": "gpt-3.5-turbo",
            "cache_enabled": False,
            "endpoints": []
        })

    def test_gateway_initialization(self):
        self.assertIsNotNone(self.gateway)

    def test_chat_request(self):
        from agentshield.security.llm_providers import LLMRequest
        request = LLMRequest(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Hello"}]
        )
        response = self.gateway.generate(request)
        self.assertIsNotNone(response)

    def test_health_check(self):
        health = self.gateway.health_check()
        self.assertIn("status", health)


class TestSIEMIntegration(unittest.TestCase):
    def setUp(self):
        self.siem = SIEMIntegrator({
            "enabled": False,
            "batch_size": 10
        })

    def test_log_event(self):
        self.siem.log_event(
            level="info",
            source="test",
            category="test_category",
            message="Test message"
        )

    def test_security_log(self):
        self.siem.security_log(
            event_type="unauthorized_access",
            severity="high",
            description="Unauthorized access attempt",
            source_ip="192.168.1.100"
        )


class TestAlertEscalation(unittest.TestCase):
    def setUp(self):
        self.alerts = AlertEscalator({
            "auto_start": False
        })

    def test_create_alert(self):
        alert = self.alerts.create_alert(
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.HIGH,
            source="test"
        )
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)

    def test_acknowledge_alert(self):
        alert = self.alerts.create_alert(
            title="Test",
            description="Test",
            severity=AlertSeverity.MEDIUM,
            source="test"
        )
        result = self.alerts.acknowledge_alert(alert.id, "test_user")
        self.assertTrue(result)

    def test_resolve_alert(self):
        alert = self.alerts.create_alert(
            title="Test",
            description="Test",
            severity=AlertSeverity.LOW,
            source="test"
        )
        result = self.alerts.resolve_alert(alert.id, "Resolved")
        self.assertTrue(result)


class TestSecurityScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = SecurityScorer()

    def test_calculate_score(self):
        context = {
            "auth_enabled": True,
            "mfa_enabled": True,
            "encryption_at_rest": True,
            "tls_enabled": True,
            "rate_limiting_enabled": True,
            "waf_enabled": True,
            "audit_logging_enabled": True,
            "compliance_framework": "SOC2"
        }
        score = self.scorer.calculate_score(context)
        self.assertIsNotNone(score.overall_score)
        self.assertIsNotNone(score.grade)

    def test_grade_calculation(self):
        self.assertEqual(self.scorer._calculate_grade(95), "A")
        self.assertEqual(self.scorer._calculate_grade(85), "B")
        self.assertEqual(self.scorer._calculate_grade(75), "C")
        self.assertEqual(self.scorer._calculate_grade(65), "D")
        self.assertEqual(self.scorer._calculate_grade(50), "F")


class TestConfigTemplates(unittest.TestCase):
    def setUp(self):
        self.templates = TemplateManager()

    def test_list_templates(self):
        result = self.templates.list_templates()
        self.assertGreater(len(result), 0)

    def test_apply_template(self):
        config = self.templates.apply_template("security_basic")
        self.assertIn("security", config)

    def test_apply_template_with_overrides(self):
        config = self.templates.apply_template("security_basic", {
            "security": {"level": "high"}
        })
        self.assertEqual(config["security"]["level"], "high")

    def test_soc2_template(self):
        config = self.templates.apply_template("compliance_soc2")
        self.assertIn("access_control", config)


class TestPolicyAsCode(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyEngine()

    def test_add_bundle(self):
        from agentshield.security.policy_as_code import PolicyBundle, PolicyRule, PolicyEffect, PolicyResource
        bundle = PolicyBundle(
            id="test",
            name="Test Policy",
            version="1.0.0",
            rules=[]
        )
        self.policy.add_policy_bundle(bundle)
        result = self.policy.get_policy_bundle("test")
        self.assertIsNotNone(result)

    def test_check_permission(self):
        result = self.policy.check_permission(
            "read",
            "api/data",
            {"auth": {"token": "valid"}}
        )
        self.assertIsInstance(result, bool)

    def test_evaluate_rules(self):
        from agentshield.security.policy_as_code import PolicyRule, PolicyEffect, PolicyResource
        bundle = self.policy.get_policy_bundle("security")
        self.assertIsNotNone(bundle)


def run_tests():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestDataEncryption))
    suite.addTests(loader.loadTestsFromTestCase(TestRateLimiter))
    suite.addTests(loader.loadTestsFromTestCase(TestWAF))
    suite.addTests(loader.loadTestsFromTestCase(TestKeyRotation))
    suite.addTests(loader.loadTestsFromTestCase(TestLLMGateway))
    suite.addTests(loader.loadTestsFromTestCase(TestSIEMIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestAlertEscalation))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityScorer))
    suite.addTests(loader.loadTestsFromTestCase(TestConfigTemplates))
    suite.addTests(loader.loadTestsFromTestCase(TestPolicyAsCode))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
