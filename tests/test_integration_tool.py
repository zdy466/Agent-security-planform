"""Integration tests for ToolManager tool execution flow"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield.toolguard.tool_manager import (
    ToolManager,
    ParameterValidator,
    ParameterType,
    ParameterSchema,
    ToolStatus,
    SandboxExecutor
)


class TestToolRegistration(unittest.TestCase):
    """Test tool registration and management"""

    def setUp(self):
        """Initialize test environment"""
        self.manager = ToolManager({
            "enable_whitelist": True,
            "whitelist": ["calculator", "search", "doubler"]
        })

    def test_register_tool_with_all_attributes(self):
        """Test registering a tool with all attributes"""
        def sample_func(x):
            return x * 2

        self.manager.register_tool(
            name="custom_tool",
            func=sample_func,
            description="Custom tool for testing",
            allowed=True,
            requires_approval=False,
            sandboxed=False,
            timeout=30
        )

        tool = self.manager.get_tool("custom_tool")
        self.assertIsNotNone(tool)
        self.assertEqual(tool.name, "custom_tool")
        self.assertEqual(tool.description, "Custom tool for testing")
        self.assertTrue(tool.allowed)

    def test_register_multiple_tools(self):
        """Test registering multiple tools"""
        def add(a, b):
            return a + b

        def multiply(a, b):
            return a * b

        self.manager.register_tool("add", add)
        self.manager.register_tool("multiply", multiply)

        self.assertIsNotNone(self.manager.get_tool("add"))
        self.assertIsNotNone(self.manager.get_tool("multiply"))

    def test_unregister_tool(self):
        """Test unregistering a tool"""
        def dummy():
            pass

        self.manager.register_tool("temp_tool", dummy)
        self.assertIsNotNone(self.manager.get_tool("temp_tool"))

        self.manager.unregister_tool("temp_tool")
        self.assertIsNone(self.manager.get_tool("temp_tool"))

    def test_get_allowed_tools(self):
        """Test getting list of allowed tools"""
        def tool1():
            pass

        def tool2():
            pass

        self.manager.register_tool("tool1", tool1)
        self.manager.whitelist.add("tool1")
        self.manager.register_tool("tool2", tool2)
        self.manager.whitelist.add("tool2")

        allowed = self.manager.get_allowed_tools()
        self.assertIn("tool1", allowed)
        self.assertIn("tool2", allowed)


class TestToolExecution(unittest.TestCase):
    """Test tool execution flow"""

    def setUp(self):
        """Initialize test environment"""
        self.manager = ToolManager({
            "enable_whitelist": True,
            "whitelist": ["calculator", "search", "adder"],
            "sandbox": {
                "enabled": False
            }
        })

    def test_execute_whitelisted_tool(self):
        """Test executing a whitelisted tool"""
        def calculator(a, b, operation="add"):
            if operation == "add":
                return a + b
            elif operation == "subtract":
                return a - b
            elif operation == "multiply":
                return a * b
            return 0

        self.manager.register_tool(
            "calculator",
            calculator,
            parameter_schema=[
                ParameterSchema("a", ParameterType.INTEGER, required=True),
                ParameterSchema("b", ParameterType.INTEGER, required=True),
                ParameterSchema("operation", ParameterType.STRING, allowed_values=["add", "subtract", "multiply"])
            ]
        )

        result = self.manager.execute("calculator", {"a": 10, "b": 5, "operation": "add"})
        self.assertEqual(result, 15)

    def test_execute_tool_not_in_whitelist(self):
        """Test executing a tool not in whitelist is blocked"""
        def restricted_func():
            return "secret"

        self.manager.register_tool("restricted_tool", restricted_func)

        with self.assertRaises(PermissionError) as context:
            self.manager.execute("restricted_tool", {})

        self.assertIn("not allowed", str(context.exception))

    def test_execute_unregistered_tool(self):
        """Test executing an unregistered tool raises error"""
        with self.assertRaises(PermissionError):
            self.manager.execute("nonexistent_tool", {})

    def test_execute_with_sandbox_config(self):
        """Test executing tool with sandbox config provided"""
        manager = ToolManager({
            "enable_whitelist": True,
            "whitelist": ["safe_tool"],
            "sandbox": {
                "enabled": False,
                "timeout": 5
            }
        })

        def safe_tool(x):
            return x * 2

        manager.register_tool("safe_tool", safe_tool, sandboxed=False, allowed=True)
        manager.whitelist.add("safe_tool")

        result = manager.execute("safe_tool", {"x": 5})
        self.assertEqual(result, 10)

    def test_tool_execution_history(self):
        """Test tool execution history is recorded"""
        def adder(a, b):
            return a + b

        self.manager.register_tool("adder", adder)

        self.manager.execute("adder", {"a": 3, "b": 7})

        history = self.manager.get_history(limit=10)
        self.assertGreater(len(history), 0)

    def test_execution_status_tracking(self):
        """Test execution status is properly tracked"""
        def slow_tool():
            import time
            time.sleep(0.01)
            return "done"

        self.manager.register_tool("slow_tool", slow_tool, timeout=10, allowed=True)
        self.manager.whitelist.add("slow_tool")
        self.manager.sandbox.enabled = False

        self.manager.execute("slow_tool", {})

        history = self.manager.get_history(limit=1)
        self.assertEqual(history[-1].status, ToolStatus.COMPLETED)


class TestParameterValidation(unittest.TestCase):
    """Test parameter validation flow"""

    def setUp(self):
        """Initialize test environment"""
        self.validator = ParameterValidator()
        self.manager = ToolManager({
            "enable_whitelist": True,
            "whitelist": ["validated_tool"],
            "validator": {
                "strict_mode": True
            }
        })

    def test_validate_required_parameters(self):
        """Test validation of required parameters"""
        schema = [
            ParameterSchema("username", ParameterType.STRING, required=True),
            ParameterSchema("age", ParameterType.INTEGER, required=True)
        ]

        result = self.validator.validate({"username": "john", "age": 25}, schema)
        self.assertTrue(result["valid"])

    def test_validate_missing_required_parameter(self):
        """Test validation fails for missing required parameter"""
        schema = [
            ParameterSchema("username", ParameterType.STRING, required=True),
            ParameterSchema("email", ParameterType.STRING, required=True)
        ]

        result = self.validator.validate({"username": "john"}, schema)
        self.assertFalse(result["valid"])
        self.assertIn("email", str(result.get("errors", [])))

    def test_validate_parameter_type(self):
        """Test parameter type validation"""
        schema = [
            ParameterSchema("count", ParameterType.INTEGER, required=True)
        ]

        result = self.validator.validate({"count": "not_an_integer"}, schema)
        self.assertFalse(result["valid"])

    def test_validate_parameter_range(self):
        """Test parameter value range validation"""
        schema = [
            ParameterSchema("age", ParameterType.INTEGER, required=True, min_value=0, max_value=150)
        ]

        result = self.validator.validate({"age": 200}, schema)
        self.assertFalse(result["valid"])

        result = self.validator.validate({"age": 25}, schema)
        self.assertTrue(result["valid"])

    def test_validate_allowed_values(self):
        """Test parameter allowed values validation"""
        schema = [
            ParameterSchema("status", ParameterType.STRING, allowed_values=["active", "inactive", "pending"])
        ]

        result = self.validator.validate({"status": "active"}, schema)
        self.assertTrue(result["valid"])

        result = self.validator.validate({"status": "unknown"}, schema)
        self.assertFalse(result["valid"])

    def test_validate_max_length(self):
        """Test parameter max length validation"""
        schema = [
            ParameterSchema("name", ParameterType.STRING, max_length=10)
        ]

        result = self.validator.validate({"name": "long_name_exceeding_limit"}, schema)
        self.assertFalse(result["valid"])

    def test_validate_with_tool_manager(self):
        """Test validation integrated with tool manager"""
        def validated_tool(name, age, city="Beijing"):
            return {"name": name, "age": age, "city": city}

        self.manager.register_tool(
            "validated_tool",
            validated_tool,
            parameter_schema=[
                ParameterSchema("name", ParameterType.STRING, required=True, max_length=50),
                ParameterSchema("age", ParameterType.INTEGER, required=True, min_value=0, max_value=150),
                ParameterSchema("city", ParameterType.STRING, allowed_values=["Beijing", "Shanghai", "Guangzhou"])
            ]
        )

        result = self.manager.validate_parameters("validated_tool", {"name": "John", "age": 30, "city": "Beijing"})
        self.assertTrue(result["valid"])

    def test_tool_manager_validates_on_execute(self):
        """Test tool manager validates parameters before execution"""
        def typed_tool(a, b):
            return a + b

        self.manager.register_tool(
            "typed_tool",
            typed_tool,
            parameter_schema=[
                ParameterSchema("a", ParameterType.INTEGER, required=True),
                ParameterSchema("b", ParameterType.INTEGER, required=True)
            ],
            allowed=True
        )
        self.manager.whitelist.add("typed_tool")

        with self.assertRaises(ValueError):
            self.manager.execute("typed_tool", {"a": "not_int", "b": 5})

    def test_validation_errors_include_field_name(self):
        """Test validation errors include field name"""
        schema = [
            ParameterSchema("email", ParameterType.STRING, required=True),
            ParameterSchema("phone", ParameterType.STRING, required=True)
        ]

        result = self.validator.validate({}, schema)
        self.assertFalse(result["valid"])
        errors = result.get("errors", [])
        self.assertTrue(any("email" in str(e).lower() or "phone" in str(e).lower() for e in errors))


class TestWhitelistCheck(unittest.TestCase):
    """Test whitelist checking flow"""

    def setUp(self):
        """Initialize test environment"""
        self.manager = ToolManager({
            "enable_whitelist": True,
            "whitelist": ["allowed_tool1", "allowed_tool2"]
        })

    def test_whitelist_enabled_check(self):
        """Test whitelist is properly enabled"""
        self.assertTrue(self.manager.enable_whitelist)
        self.assertIn("allowed_tool1", self.manager.whitelist)

    def test_can_execute_whitelisted_tool(self):
        """Test can_execute returns True for whitelisted tool"""
        def dummy_tool():
            return "dummy"

        self.manager.register_tool("allowed_tool1", dummy_tool)
        result = self.manager.can_execute("allowed_tool1")
        self.assertTrue(result)

    def test_can_execute_non_whitelisted_tool(self):
        """Test can_execute returns False for non-whitelisted tool"""
        result = self.manager.can_execute("not_allowed_tool")
        self.assertFalse(result)

    def test_whitelist_disabled_mode(self):
        """Test execution when whitelist is disabled"""
        manager = ToolManager({
            "enable_whitelist": False
        })

        def any_tool():
            return "result"

        manager.register_tool("any_tool", any_tool, allowed=True)
        result = manager.can_execute("any_tool")
        self.assertTrue(result)

    def test_blocked_tool_not_in_whitelist(self):
        """Test blocked tool is not in whitelist even if registered"""
        def dangerous_tool():
            return "dangerous"

        self.manager.register_tool("dangerous_tool", dangerous_tool, allowed=False)
        result = self.manager.can_execute("dangerous_tool")
        self.assertFalse(result)

    def test_whitelist_with_empty_list(self):
        """Test whitelist with empty list blocks all tools"""
        manager = ToolManager({
            "enable_whitelist": True,
            "whitelist": []
        })

        def some_tool():
            return "result"

        manager.register_tool("some_tool", some_tool)
        result = manager.can_execute("some_tool")
        self.assertFalse(result)

    def test_dynamic_whitelist_update(self):
        """Test dynamically adding to whitelist"""
        def new_tool():
            return "new"

        self.manager.register_tool("new_tool", new_tool)
        self.assertFalse(self.manager.can_execute("new_tool"))

        self.manager.whitelist.add("new_tool")
        self.assertTrue(self.manager.can_execute("new_tool"))


class TestSandboxExecution(unittest.TestCase):
    """Test sandbox execution flow"""

    def setUp(self):
        """Initialize sandbox executor"""
        self.sandbox = SandboxExecutor({
            "enabled": True,
            "timeout": 5,
            "max_memory_mb": 256,
            "blocked_commands": ["rm", "del", "format"]
        })

    def test_sandbox_blocks_dangerous_commands(self):
        """Test sandbox blocks dangerous commands"""
        can_exec, reason = self.sandbox.can_execute("rm -rf /")
        self.assertFalse(can_exec)
        self.assertIn("blocked", reason.lower())

    def test_sandbox_allows_safe_operations(self):
        """Test sandbox allows safe operations"""
        can_exec, reason = self.sandbox.can_execute("echo hello")
        self.assertTrue(can_exec)

    def test_sandbox_timeout(self):
        """Test sandbox timeout handling"""
        def slow_function():
            import time
            time.sleep(10)
            return "done"

        with self.assertRaises(TimeoutError):
            self.sandbox.execute_in_sandbox(slow_function)

    def test_sandbox_disabled(self):
        """Test execution when sandbox is disabled"""
        sandbox = SandboxExecutor({"enabled": False})

        def safe_func():
            return "safe"

        result = sandbox.execute_in_sandbox(safe_func)
        self.assertEqual(result, "safe")

    def test_sandbox_validates_path_access(self):
        """Test sandbox path access validation"""
        sandbox = SandboxExecutor({
            "enabled": True,
            "allowed_paths": ["/safe/path"]
        })

        self.assertTrue(sandbox.validate_path_access("/safe/path/file.txt"))
        self.assertFalse(sandbox.validate_path_access("/unsafe/path/file.txt"))


class TestToolApprovalFlow(unittest.TestCase):
    """Test tool approval flow"""

    def setUp(self):
        """Initialize test environment"""
        self.manager = ToolManager({
            "enable_whitelist": True,
            "whitelist": ["approval_tool"],
            "sandbox": {"enabled": False}
        })

    def test_tool_requires_approval(self):
        """Test tool that requires approval"""
        def approval_needed_tool():
            return "executed"

        self.manager.register_tool(
            "approval_tool",
            approval_needed_tool,
            requires_approval=True
        )

        with self.assertRaises(PermissionError) as context:
            self.manager.execute("approval_tool", {})

        self.assertIn("approval", str(context.exception).lower())

    def test_approve_pending_tool(self):
        """Test approving and executing pending tool"""
        def approval_tool():
            return "approved_result"

        self.manager.register_tool(
            "approval_tool",
            approval_tool,
            requires_approval=True
        )

        try:
            self.manager.execute("approval_tool", {})
        except PermissionError:
            pass

        result = self.manager.approve_tool("approval_tool", {})
        self.assertEqual(result, "approved_result")


class TestToolIntegration(unittest.TestCase):
    """Integration tests for complete tool flow"""

    def setUp(self):
        """Initialize complete tool environment"""
        self.manager = ToolManager({
            "enable_whitelist": True,
            "whitelist": ["calculator", "search"],
            "validator": {"strict_mode": True},
            "sandbox": {"enabled": False}
        })

    def test_complete_tool_execution_flow(self):
        """Test complete tool execution flow"""
        def calculator(a, b, operation="add"):
            operations = {
                "add": lambda x, y: x + y,
                "subtract": lambda x, y: x - y,
                "multiply": lambda x, y: x * y,
                "divide": lambda x, y: x / y if y != 0 else 0
            }
            return operations.get(operation, lambda x, y: 0)(a, b)

        self.manager.register_tool(
            "calculator",
            calculator,
            parameter_schema=[
                ParameterSchema("a", ParameterType.INTEGER, required=True),
                ParameterSchema("b", ParameterType.INTEGER, required=True),
                ParameterSchema("operation", ParameterType.STRING, allowed_values=["add", "subtract", "multiply", "divide"])
            ]
        )

        result = self.manager.execute("calculator", {"a": 10, "b": 5, "operation": "add"})
        self.assertEqual(result, 15)

        result = self.manager.execute("calculator", {"a": 10, "b": 5, "operation": "multiply"})
        self.assertEqual(result, 50)

        history = self.manager.get_history(limit=5)
        self.assertEqual(len(history), 2)

    def test_parameter_validation_prevents_injection(self):
        """Test parameter validation prevents injection attacks"""
        def safe_query(query):
            return f"Query: {query}"

        self.manager.register_tool(
            "safe_query",
            safe_query,
            parameter_schema=[
                ParameterSchema("query", ParameterType.STRING, max_length=100)
            ]
        )

        result = self.manager.validate_parameters("safe_query", {"query": "normal query"})
        self.assertTrue(result["valid"])

    def test_tool_execution_creates_audit_record(self):
        """Test tool execution creates proper audit record"""
        def audit_tool():
            return "result"

        self.manager.register_tool(
            "audit_tool",
            audit_tool,
            parameter_schema=[],
            allowed=True
        )
        self.manager.whitelist.add("audit_tool")

        self.manager.execute("audit_tool", {})

        history = self.manager.get_history(limit=1)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[-1].tool_name, "audit_tool")


def run_tests():
    """Run all tool integration tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestToolRegistration))
    suite.addTests(loader.loadTestsFromTestCase(TestToolExecution))
    suite.addTests(loader.loadTestsFromTestCase(TestParameterValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestWhitelistCheck))
    suite.addTests(loader.loadTestsFromTestCase(TestSandboxExecution))
    suite.addTests(loader.loadTestsFromTestCase(TestToolApprovalFlow))
    suite.addTests(loader.loadTestsFromTestCase(TestToolIntegration))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
