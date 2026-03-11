"""
AgentShield 企业认证示例

本示例展示如何使用 AuthenticationService 进行用户创建、登录和 RBAC 权限管理。
"""

import sys
import asyncio
sys.path.insert(0, 'd:\\security')

from agentshield.enterprise.auth import (
    AuthenticationService,
    UserRole,
    Permission,
    InMemoryUserStore
)


async def main():
    print("=" * 60)
    print("AgentShield 企业认证示例")
    print("=" * 60)

    secret_key = "your-secret-key-change-in-production"

    print("\n1. 创建 AuthenticationService")
    print("-" * 40)
    auth_service = AuthenticationService(secret_key)
    print(f"   AuthenticationService 创建成功!")
    print(f"   - 用户存储: {auth_service.user_store}")
    print(f"   - Token管理器: {auth_service.token_manager}")

    print("\n2. 创建用户")
    print("-" * 40)

    admin_user = auth_service.create_user(
        username="admin",
        email="admin@example.com",
        password="Admin@123456",
        role=UserRole.ADMIN
    )
    print(f"   创建管理员用户: {admin_user.username} ({admin_user.role.value})")

    analyst_user = auth_service.create_user(
        username="analyst",
        email="analyst@example.com",
        password="Analyst@123456",
        role=UserRole.SECURITY_ANALYST
    )
    print(f"   创建安全分析师: {analyst_user.username} ({analyst_user.role.value})")

    auditor_user = auth_service.create_user(
        username="auditor",
        email="auditor@example.com",
        password="Auditor@123456",
        role=UserRole.AUDITOR
    )
    print(f"   创建审计员: {auditor_user.username} ({auditor_user.role.value})")

    operator_user = auth_service.create_user(
        username="operator",
        email="operator@example.com",
        password="Operator@123456",
        role=UserRole.OPERATOR
    )
    print(f"   创建运维人员: {operator_user.username} ({operator_user.role.value})")

    viewer_user = auth_service.create_user(
        username="viewer",
        email="viewer@example.com",
        password="Viewer@123456",
        role=UserRole.VIEWER
    )
    print(f"   创建查看者: {viewer_user.username} ({viewer_user.role.value})")

    print("\n3. 用户登录")
    print("-" * 40)

    token = await auth_service.login(
        username="admin",
        password="Admin@123456",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0"
    )
    if token:
        print(f"   管理员登录成功!")
        print(f"   - Access Token: {token.access_token[:50]}...")
        print(f"   - Refresh Token: {token.refresh_token[:50]}...")
        print(f"   - 过期时间: {token.expires_in}秒")

    token = await auth_service.login(
        username="viewer",
        password="Viewer@123456"
    )
    if token:
        print(f"   查看者登录成功!")

    print("\n4. 测试错误密码登录")
    print("-" * 40)
    token = await auth_service.login(
        username="admin",
        password="WrongPassword"
    )
    if token:
        print(f"   登录成功 (不应该发生)")
    else:
        print(f"   登录失败 (预期行为)")

    print("\n5. Token验证")
    print("-" * 40)
    token = await auth_service.login(username="analyst", password="Analyst@123456")
    if token:
        payload = await auth_service.verify_token(token.access_token)
        if payload:
            print(f"   Token验证成功!")
            print(f"   - 用户ID: {payload['user_id']}")
            print(f"   - 用户名: {payload['username']}")
            print(f"   - 角色: {payload['role']}")
            print(f"   - 权限: {payload['permissions']}")

    print("\n6. 用户权限查看")
    print("-" * 40)

    roles = [
        UserRole.ADMIN,
        UserRole.SECURITY_ANALYST,
        UserRole.AUDITOR,
        UserRole.OPERATOR,
        UserRole.VIEWER
    ]

    for role in roles:
        permissions = auth_service.get_user_permissions(role)
        print(f"   {role.value}: {len(permissions)}个权限")
        for perm in sorted(permissions, key=lambda p: p.value):
            print(f"      - {perm.value}")

    print("\n7. 权限检查")
    print("-" * 40)

    test_cases = [
        (UserRole.ADMIN, Permission.MANAGE_USERS, True),
        (UserRole.ADMIN, Permission.CONFIGURE_FIREWALL, True),
        (UserRole.VIEWER, Permission.MANAGE_USERS, False),
        (UserRole.VIEWER, Permission.VIEW_DASHBOARD, True),
        (UserRole.AUDITOR, Permission.READ_AUDIT_LOGS, True),
        (UserRole.AUDITOR, Permission.WRITE_SECURITY_LOGS, False),
        (UserRole.OPERATOR, Permission.CONFIGURE_FIREWALL, True),
        (UserRole.OPERATOR, Permission.MANAGE_USERS, False),
    ]

    for role, permission, expected in test_cases:
        result = auth_service.has_permission(role, permission)
        status = "✓" if result == expected else "✗"
        print(f"   {status} {role.value} has {permission.value}: {result} (预期: {expected})")

    print("\n8. 获取所有用户")
    print("-" * 40)
    users = auth_service.get_all_users()
    print(f"   总用户数: {len(users)}")
    for user in users:
        print(f"   - {user.username} ({user.email}) - {user.role.value} - 活跃: {user.is_active}")

    print("\n9. 更新用户角色")
    print("-" * 40)
    viewer_user = auth_service.user_store.get_user_by_username("viewer")
    if viewer_user:
        success = auth_service.update_user_role(viewer_user.user_id, UserRole.OPERATOR)
        if success:
            print(f"   已将 viewer 提升为 operator")

    viewer_user = auth_service.user_store.get_user_by_username("viewer")
    print(f"   当前角色: {viewer_user.role.value}")

    print("\n10. 禁用用户")
    print("-" * 40)
    viewer_user = auth_service.user_store.get_user_by_username("viewer")
    if viewer_user:
        success = auth_service.deactivate_user(viewer_user.user_id)
        if success:
            print(f"   已禁用 viewer 用户")

    print("\n11. 尝试登录已禁用的用户")
    print("-" * 40)
    token = await auth_service.login(username="viewer", password="Viewer@123456")
    if token:
        print(f"   登录成功 (不应该发生)")
    else:
        print(f"   登录失败 - 用户已被禁用")

    print("\n12. 用户登出")
    print("-" * 40)
    token = await auth_service.login(username="operator", password="Operator@123456")
    if token:
        logout_result = await auth_service.logout(token.access_token)
        print(f"   登出结果: {logout_result}")

        payload = await auth_service.verify_token(token.access_token)
        if payload:
            print(f"   Token仍然有效 (不应该)")
        else:
            print(f"   Token已失效 (预期行为)")

    print("\n" + "=" * 60)
    print("企业认证示例完成!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
