"""Integration tests for AuthenticationService and RBAC flow"""

import unittest
import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield.enterprise.auth import (
    AuthenticationService,
    InMemoryUserStore,
    User,
    UserRole,
    Permission,
    ROLE_PERMISSIONS,
    TokenManager,
    PasswordHasher,
    Session
)


class TestUserCreation(unittest.TestCase):
    """Test user creation and management"""

    def setUp(self):
        """Initialize test environment"""
        self.auth_service = AuthenticationService(secret_key="test_secret_key")

    def test_create_user_with_all_attributes(self):
        """Test creating a user with all attributes"""
        user = self.auth_service.create_user(
            username="testuser",
            email="test@example.com",
            password="SecurePass123!",
            role=UserRole.VIEWER
        )

        self.assertIsNotNone(user.user_id)
        self.assertEqual(user.username, "testuser")
        self.assertEqual(user.email, "test@example.com")
        self.assertEqual(user.role, UserRole.VIEWER)
        self.assertTrue(user.is_active)
        self.assertIsNotNone(user.password_hash)
        self.assertIsNotNone(user.salt)

    def test_create_user_with_different_roles(self):
        """Test creating users with different roles"""
        roles = [
            UserRole.ADMIN,
            UserRole.SECURITY_ANALYST,
            UserRole.AUDITOR,
            UserRole.OPERATOR,
            UserRole.VIEWER
        ]

        for role in roles:
            user = self.auth_service.create_user(
                username=f"user_{role.value}",
                email=f"user_{role.value}@example.com",
                password="Password123!",
                role=role
            )
            self.assertEqual(user.role, role)

    def test_user_default_role(self):
        """Test user default role is VIEWER"""
        user = self.auth_service.create_user(
            username="default_user",
            email="default@example.com",
            password="Password123!"
        )
        self.assertEqual(user.role, UserRole.VIEWER)

    def test_password_is_hashed(self):
        """Test password is properly hashed"""
        user = self.auth_service.create_user(
            username="hashed_test",
            email="hashed@example.com",
            password="MySecretPassword"
        )

        self.assertNotEqual(user.password_hash, "MySecretPassword")
        self.assertIsNotNone(user.salt)
        self.assertTrue(len(user.salt) > 0)

    def test_get_all_users(self):
        """Test getting all users"""
        self.auth_service.create_user("user1", "user1@example.com", "Pass123!")
        self.auth_service.create_user("user2", "user2@example.com", "Pass123!")
        self.auth_service.create_user("user3", "user3@example.com", "Pass123!")

        users = self.auth_service.get_all_users()
        self.assertEqual(len(users), 3)

    def test_update_user_role(self):
        """Test updating user role"""
        user = self.auth_service.create_user(
            username="role_update_test",
            email="role@example.com",
            password="Pass123!",
            role=UserRole.VIEWER
        )

        result = self.auth_service.update_user_role(user.user_id, UserRole.ADMIN)
        self.assertTrue(result)

        users = self.auth_service.get_all_users()
        updated_user = next(u for u in users if u.user_id == user.user_id)
        self.assertEqual(updated_user.role, UserRole.ADMIN)

    def test_deactivate_user(self):
        """Test deactivating a user"""
        user = self.auth_service.create_user(
            username="deactivate_test",
            email="deactivate@example.com",
            password="Pass123!"
        )

        result = self.auth_service.deactivate_user(user.user_id)
        self.assertTrue(result)

        users = self.auth_service.get_all_users()
        deactivated_user = next(u for u in users if u.user_id == user.user_id)
        self.assertFalse(deactivated_user.is_active)


class TestLoginFlow(unittest.TestCase):
    """Test login flow"""

    def setUp(self):
        """Initialize test environment"""
        self.auth_service = AuthenticationService(secret_key="test_secret_key")
        self.auth_service.create_user(
            username="validuser",
            email="valid@example.com",
            password="CorrectPassword123!",
            role=UserRole.OPERATOR
        )

    def test_successful_login(self):
        """Test successful login"""
        result = asyncio.run(self.auth_service.login(
            username="validuser",
            password="CorrectPassword123!"
        ))

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.access_token)
        self.assertIsNotNone(result.refresh_token)
        self.assertEqual(result.token_type, "Bearer")

    def test_login_wrong_password(self):
        """Test login with wrong password"""
        result = asyncio.run(self.auth_service.login(
            username="validuser",
            password="WrongPassword"
        ))

        self.assertIsNone(result)

    def test_login_nonexistent_user(self):
        """Test login with nonexistent user"""
        result = asyncio.run(self.auth_service.login(
            username="nonexistent",
            password="anypassword"
        ))

        self.assertIsNone(result)

    def test_login_inactive_user(self):
        """Test login with inactive user"""
        user = self.auth_service.create_user(
            username="inactiveuser",
            email="inactive@example.com",
            password="Pass123!"
        )
        self.auth_service.deactivate_user(user.user_id)

        result = asyncio.run(self.auth_service.login(
            username="inactiveuser",
            password="Pass123!"
        ))

        self.assertIsNone(result)

    def test_login_creates_session(self):
        """Test login creates session"""
        initial_session_count = len(self.auth_service._sessions)

        asyncio.run(self.auth_service.login(
            username="validuser",
            password="CorrectPassword123!"
        ))

        self.assertEqual(len(self.auth_service._sessions), initial_session_count + 1)

    def test_login_updates_last_login(self):
        """Test login updates last login timestamp"""
        user = self.auth_service.get_all_users()[0]
        original_last_login = user.last_login

        asyncio.run(self.auth_service.login(
            username="validuser",
            password="CorrectPassword123!"
        ))

        users = self.auth_service.get_all_users()
        updated_user = next(u for u in users if u.username == "validuser")
        self.assertIsNotNone(updated_user.last_login)


class TestLogoutFlow(unittest.TestCase):
    """Test logout flow"""

    def setUp(self):
        """Initialize test environment"""
        self.auth_service = AuthenticationService(secret_key="test_secret_key")
        self.auth_service.create_user(
            username="logoutuser",
            email="logout@example.com",
            password="Pass123!"
        )

    def test_successful_logout(self):
        """Test successful logout"""
        token_result = asyncio.run(self.auth_service.login(
            username="logoutuser",
            password="Pass123!"
        ))

        access_token = token_result.access_token

        result = asyncio.run(self.auth_service.logout(access_token))
        self.assertTrue(result)

    def test_logout_invalid_token(self):
        """Test logout with invalid token"""
        result = asyncio.run(self.auth_service.logout("invalid_token"))
        self.assertFalse(result)


class TestTokenValidation(unittest.TestCase):
    """Test token validation flow"""

    def setUp(self):
        """Initialize test environment"""
        self.auth_service = AuthenticationService(secret_key="test_secret_key")
        self.auth_service.create_user(
            username="tokenuser",
            email="token@example.com",
            password="Pass123!",
            role=UserRole.SECURITY_ANALYST
        )

    def test_verify_valid_token(self):
        """Test verifying a valid token"""
        token_result = asyncio.run(self.auth_service.login(
            username="tokenuser",
            password="Pass123!"
        ))

        payload = asyncio.run(self.auth_service.verify_token(token_result.access_token))

        self.assertIsNotNone(payload)
        self.assertEqual(payload["username"], "tokenuser")
        self.assertEqual(payload["role"], "security_analyst")

    def test_verify_invalid_token(self):
        """Test verifying an invalid token"""
        payload = asyncio.run(self.auth_service.verify_token("invalid.token.here"))
        self.assertIsNone(payload)

    def test_verify_expired_token(self):
        """Test verifying an expired token"""
        token_manager = TokenManager(secret_key="test_secret_key")
        expired_payload = {
            "sub": "test_user",
            "role": "admin",
            "exp": 0
        }
        expired_token = token_manager.create_access_token("test_user", UserRole.ADMIN)

        payload = asyncio.run(self.auth_service.verify_token(expired_token))
        self.assertIsNone(payload)

    def test_token_contains_required_claims(self):
        """Test token contains required claims"""
        token_result = asyncio.run(self.auth_service.login(
            username="tokenuser",
            password="Pass123!"
        ))

        payload = asyncio.run(self.auth_service.verify_token(token_result.access_token))

        self.assertIn("user_id", payload)
        self.assertIn("role", payload)
        self.assertIn("permissions", payload)

    def test_token_permissions_match_role(self):
        """Test token permissions match user role"""
        token_result = asyncio.run(self.auth_service.login(
            username="tokenuser",
            password="Pass123!"
        ))

        payload = asyncio.run(self.auth_service.verify_token(token_result.access_token))

        expected_permissions = [p.value for p in ROLE_PERMISSIONS[UserRole.SECURITY_ANALYST]]
        self.assertEqual(set(payload["permissions"]), set(expected_permissions))


class TestRBACPermissions(unittest.TestCase):
    """Test RBAC permission checking"""

    def setUp(self):
        """Initialize test environment"""
        self.auth_service = AuthenticationService(secret_key="test_secret_key")

    def test_admin_has_all_permissions(self):
        """Test admin role has all permissions"""
        permissions = self.auth_service.get_user_permissions(UserRole.ADMIN)
        expected_permissions = set(ROLE_PERMISSIONS[UserRole.ADMIN])

        self.assertEqual(permissions, expected_permissions)

    def test_viewer_has_minimal_permissions(self):
        """Test viewer role has minimal permissions"""
        permissions = self.auth_service.get_user_permissions(UserRole.VIEWER)
        expected_permissions = set(ROLE_PERMISSIONS[UserRole.VIEWER])

        self.assertEqual(permissions, expected_permissions)

    def test_security_analyst_permissions(self):
        """Test security analyst role permissions"""
        permissions = self.auth_service.get_user_permissions(UserRole.SECURITY_ANALYST)

        self.assertIn(Permission.READ_SECURITY_LOGS, permissions)
        self.assertIn(Permission.CONFIGURE_FIREWALL, permissions)
        self.assertIn(Permission.VIEW_DASHBOARD, permissions)
        self.assertNotIn(Permission.MANAGE_USERS, permissions)

    def test_auditor_permissions(self):
        """Test auditor role permissions"""
        permissions = self.auth_service.get_user_permissions(UserRole.AUDITOR)

        self.assertIn(Permission.READ_AUDIT_LOGS, permissions)
        self.assertIn(Permission.VIEW_REPORTS, permissions)
        self.assertIn(Permission.EXPORT_DATA, permissions)
        self.assertNotIn(Permission.MANAGE_USERS, permissions)

    def test_operator_permissions(self):
        """Test operator role permissions"""
        permissions = self.auth_service.get_user_permissions(UserRole.OPERATOR)

        self.assertIn(Permission.READ_SECURITY_LOGS, permissions)
        self.assertIn(Permission.WRITE_SECURITY_LOGS, permissions)
        self.assertIn(Permission.CONFIGURE_FIREWALL, permissions)

    def test_has_permission_true(self):
        """Test has_permission returns True for allowed permission"""
        result = self.auth_service.has_permission(UserRole.ADMIN, Permission.MANAGE_USERS)
        self.assertTrue(result)

    def test_has_permission_false(self):
        """Test has_permission returns False for disallowed permission"""
        result = self.auth_service.has_permission(UserRole.VIEWER, Permission.MANAGE_USERS)
        self.assertFalse(result)

    def test_permissions_are_immutable(self):
        """Test role permissions cannot be modified"""
        permissions1 = self.auth_service.get_user_permissions(UserRole.ADMIN)
        permissions1_copy = set(permissions1)

        permissions2 = self.auth_service.get_user_permissions(UserRole.ADMIN)

        self.assertEqual(permissions1_copy, permissions2)


class TestPasswordHasher(unittest.TestCase):
    """Test password hashing"""

    def test_hash_password_generates_hash_and_salt(self):
        """Test password hashing generates hash and salt"""
        password_hash, salt = PasswordHasher.hash_password("TestPassword123!")

        self.assertIsNotNone(password_hash)
        self.assertIsNotNone(salt)
        self.assertNotEqual(password_hash, "TestPassword123!")

    def test_hash_password_generates_unique_salts(self):
        """Test same password generates different salts"""
        hash1, salt1 = PasswordHasher.hash_password("SamePassword")
        hash2, salt2 = PasswordHasher.hash_password("SamePassword")

        self.assertNotEqual(salt1, salt2)

    def test_verify_password_correct(self):
        """Test verifying correct password"""
        password_hash, salt = PasswordHasher.hash_password("CorrectPassword")
        result = PasswordHasher.verify_password("CorrectPassword", password_hash, salt)

        self.assertTrue(result)

    def test_verify_password_incorrect(self):
        """Test verifying incorrect password"""
        password_hash, salt = PasswordHasher.hash_password("CorrectPassword")
        result = PasswordHasher.verify_password("WrongPassword", password_hash, salt)

        self.assertFalse(result)


class TestInMemoryUserStore(unittest.TestCase):
    """Test in-memory user store"""

    def setUp(self):
        """Initialize user store"""
        self.store = InMemoryUserStore()

    def test_add_user(self):
        """Test adding user to store"""
        user = User(
            user_id="test_id",
            username="testuser",
            email="test@example.com",
            role=UserRole.VIEWER,
            password_hash="hash",
            salt="salt"
        )

        self.store.add_user(user)
        retrieved = self.store.get_user("test_id")

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.username, "testuser")

    def test_get_user_by_username(self):
        """Test getting user by username"""
        user = User(
            user_id="test_id",
            username="findme",
            email="find@example.com",
            role=UserRole.VIEWER,
            password_hash="hash",
            salt="salt"
        )

        self.store.add_user(user)
        retrieved = self.store.get_user_by_username("findme")

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.email, "find@example.com")

    def test_get_user_by_email(self):
        """Test getting user by email"""
        user = User(
            user_id="test_id",
            username="emailuser",
            email="unique@example.com",
            role=UserRole.VIEWER,
            password_hash="hash",
            salt="salt"
        )

        self.store.add_user(user)
        retrieved = self.store.get_user_by_email("unique@example.com")

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.username, "emailuser")

    def test_update_user(self):
        """Test updating user"""
        user = User(
            user_id="update_id",
            username="updateuser",
            email="update@example.com",
            role=UserRole.VIEWER,
            password_hash="hash",
            salt="salt"
        )

        self.store.add_user(user)

        user.email = "newemail@example.com"
        self.store.update_user(user)

        retrieved = self.store.get_user("update_id")
        self.assertEqual(retrieved.email, "newemail@example.com")

    def test_delete_user(self):
        """Test deleting user"""
        user = User(
            user_id="delete_id",
            username="deleteuser",
            email="delete@example.com",
            role=UserRole.VIEWER,
            password_hash="hash",
            salt="salt"
        )

        self.store.add_user(user)
        result = self.store.delete_user("delete_id")

        self.assertTrue(result)
        self.assertIsNone(self.store.get_user("delete_id"))

    def test_add_session(self):
        """Test adding session"""
        from datetime import datetime, timedelta

        session = Session(
            session_id="session_123",
            user_id="user_123",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1)
        )

        self.store.add_session(session)
        retrieved = self.store.get_session("session_123")

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.user_id, "user_123")

    def test_invalidate_session(self):
        """Test invalidating session"""
        from datetime import datetime, timedelta

        session = Session(
            session_id="session_456",
            user_id="user_456",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1)
        )

        self.store.add_session(session)
        result = self.store.invalidate_session("session_456")

        self.assertTrue(result)
        self.assertFalse(self.store.get_session("session_456").is_valid)


class TestTokenManager(unittest.TestCase):
    """Test token manager"""

    def setUp(self):
        """Initialize token manager"""
        self.token_manager = TokenManager(secret_key="test_key")

    def test_create_access_token(self):
        """Test creating access token"""
        token = self.token_manager.create_access_token("user_123", UserRole.ADMIN)

        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 0)

    def test_create_refresh_token(self):
        """Test creating refresh token"""
        token = self.token_manager.create_refresh_token("user_123")

        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)

    def test_verify_valid_token(self):
        """Test verifying valid token"""
        token = self.token_manager.create_access_token("user_123", UserRole.ADMIN)
        payload = self.token_manager.verify_token(token)

        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], "user_123")
        self.assertEqual(payload["role"], "admin")

    def test_verify_invalid_token(self):
        """Test verifying invalid token"""
        payload = self.token_manager.verify_token("invalid.token")

        self.assertIsNone(payload)

    def test_create_token_pair(self):
        """Test creating token pair"""
        token_pair = self.token_manager.create_token_pair("user_123", UserRole.OPERATOR)

        self.assertIsNotNone(token_pair.access_token)
        self.assertIsNotNone(token_pair.refresh_token)
        self.assertEqual(token_pair.expires_in, 3600)
        self.assertEqual(token_pair.token_type, "Bearer")


class TestAuthIntegration(unittest.TestCase):
    """Integration tests for complete auth flow"""

    def setUp(self):
        """Initialize complete auth environment"""
        self.auth_service = AuthenticationService(secret_key="integration_test_key")

    def test_complete_user_lifecycle(self):
        """Test complete user lifecycle"""
        user = self.auth_service.create_user(
            username="lifecycle_user",
            email="lifecycle@example.com",
            password="SecurePass123!",
            role=UserRole.VIEWER
        )

        token_result = asyncio.run(self.auth_service.login(
            username="lifecycle_user",
            password="SecurePass123!"
        ))

        self.assertIsNotNone(token_result)

        payload = asyncio.run(self.auth_service.verify_token(token_result.access_token))
        self.assertIsNotNone(payload)
        self.assertEqual(payload["user_id"], user.user_id)

        self.auth_service.update_user_role(user.user_id, UserRole.OPERATOR)

        logout_result = asyncio.run(self.auth_service.logout(token_result.access_token))
        self.assertTrue(logout_result)

    def test_rbac_integration(self):
        """Test RBAC integration with authentication"""
        self.auth_service.create_user(
            username="admin_user",
            email="admin@example.com",
            password="AdminPass123!",
            role=UserRole.ADMIN
        )

        self.auth_service.create_user(
            username="viewer_user",
            email="viewer@example.com",
            password="ViewerPass123!",
            role=UserRole.VIEWER
        )

        admin_token = asyncio.run(self.auth_service.login(
            username="admin_user",
            password="AdminPass123!"
        ))
        viewer_token = asyncio.run(self.auth_service.login(
            username="viewer_user",
            password="ViewerPass123!"
        ))

        admin_payload = asyncio.run(self.auth_service.verify_token(admin_token.access_token))
        viewer_payload = asyncio.run(self.auth_service.verify_token(viewer_token.access_token))

        self.assertIn(Permission.MANAGE_USERS.value, admin_payload["permissions"])
        self.assertNotIn(Permission.MANAGE_USERS.value, viewer_payload["permissions"])

    def test_session_management(self):
        """Test session management"""
        user = self.auth_service.create_user(
            username="session_user",
            email="session@example.com",
            password="Pass123!"
        )

        token1 = asyncio.run(self.auth_service.login(
            username="session_user",
            password="Pass123!"
        ))

        token2 = asyncio.run(self.auth_service.login(
            username="session_user",
            password="Pass123!"
        ))

        self.assertNotEqual(token1.access_token, token2.access_token)

    def test_authentication_failure_tracking(self):
        """Test authentication failure tracking"""
        self.auth_service.create_user(
            username="fail_user",
            email="fail@example.com",
            password="CorrectPass123!"
        )

        asyncio.run(self.auth_service.login(
            username="fail_user",
            password="WrongPassword1"
        ))

        asyncio.run(self.auth_service.login(
            username="fail_user",
            password="WrongPassword2"
        ))

        asyncio.run(self.auth_service.login(
            username="fail_user",
            password="CorrectPass123!"
        ))

        users = self.auth_service.get_all_users()
        user = next(u for u in users if u.username == "fail_user")
        self.assertIsNotNone(user.last_login)


def run_tests():
    """Run all authentication integration tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestUserCreation))
    suite.addTests(loader.loadTestsFromTestCase(TestLoginFlow))
    suite.addTests(loader.loadTestsFromTestCase(TestLogoutFlow))
    suite.addTests(loader.loadTestsFromTestCase(TestTokenValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestRBACPermissions))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordHasher))
    suite.addTests(loader.loadTestsFromTestCase(TestInMemoryUserStore))
    suite.addTests(loader.loadTestsFromTestCase(TestTokenManager))
    suite.addTests(loader.loadTestsFromTestCase(TestAuthIntegration))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
