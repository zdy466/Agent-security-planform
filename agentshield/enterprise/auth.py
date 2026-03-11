import hashlib
import hmac
import json
import base64
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from uuid import uuid4


def _simple_jwt_encode(payload: Dict[str, Any], secret: str) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    message = f"{header}.{payload_b64}"
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return f"{message}.{signature}"


def _simple_jwt_decode(token: str, secret: str) -> Optional[Dict[str, Any]]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload_b64, signature = parts
        message = f"{header}.{payload_b64}"
        expected_sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        if not hmac.compare_digest(signature, expected_sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        if "exp" in payload and payload["exp"] < time.time():
            return None
        return payload
    except Exception:
        return None


class UserRole(Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    AUDITOR = "auditor"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(Enum):
    READ_SECURITY_LOGS = "read:security_logs"
    WRITE_SECURITY_LOGS = "write:security_logs"
    READ_AUDIT_LOGS = "read:audit_logs"
    WRITE_AUDIT_LOGS = "write:audit_logs"
    MANAGE_POLICIES = "manage:policies"
    MANAGE_USERS = "manage:users"
    MANAGE_SETTINGS = "manage:settings"
    VIEW_DASHBOARD = "view:dashboard"
    CONFIGURE_FIREWALL = "configure:firewall"
    VIEW_REPORTS = "view:reports"
    EXPORT_DATA = "export:data"
    RUN_SIMULATIONS = "run:simulations"


ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: {
        Permission.READ_SECURITY_LOGS,
        Permission.WRITE_SECURITY_LOGS,
        Permission.READ_AUDIT_LOGS,
        Permission.WRITE_AUDIT_LOGS,
        Permission.MANAGE_POLICIES,
        Permission.MANAGE_USERS,
        Permission.MANAGE_SETTINGS,
        Permission.VIEW_DASHBOARD,
        Permission.CONFIGURE_FIREWALL,
        Permission.VIEW_REPORTS,
        Permission.EXPORT_DATA,
        Permission.RUN_SIMULATIONS,
    },
    UserRole.SECURITY_ANALYST: {
        Permission.READ_SECURITY_LOGS,
        Permission.READ_AUDIT_LOGS,
        Permission.MANAGE_POLICIES,
        Permission.VIEW_DASHBOARD,
        Permission.CONFIGURE_FIREWALL,
        Permission.VIEW_REPORTS,
        Permission.RUN_SIMULATIONS,
    },
    UserRole.AUDITOR: {
        Permission.READ_SECURITY_LOGS,
        Permission.READ_AUDIT_LOGS,
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_REPORTS,
        Permission.EXPORT_DATA,
    },
    UserRole.OPERATOR: {
        Permission.READ_SECURITY_LOGS,
        Permission.WRITE_SECURITY_LOGS,
        Permission.VIEW_DASHBOARD,
        Permission.CONFIGURE_FIREWALL,
    },
    UserRole.VIEWER: {
        Permission.VIEW_DASHBOARD,
    },
}


@dataclass
class User:
    user_id: str
    username: str
    email: str
    role: UserRole
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    is_active: bool = True
    mfa_enabled: bool = False
    password_hash: Optional[str] = None
    salt: Optional[str] = None


@dataclass
class Session:
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_valid: bool = True


@dataclass
class AuthToken:
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"


class PasswordHasher:
    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
        salt = salt or secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        )
        return password_hash.hex(), salt

    @staticmethod
    def verify_password(password: str, password_hash: str, salt: str) -> bool:
        computed_hash, _ = PasswordHasher.hash_password(password, salt)
        return hmac.compare_digest(computed_hash, password_hash)


class TokenManager:
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_expiry = 3600
        self.refresh_token_expiry = 86400 * 7

    def create_access_token(self, user_id: str, role: UserRole) -> str:
        payload = {
            "sub": user_id,
            "role": role.value,
            "exp": (datetime.now() + timedelta(seconds=self.token_expiry)).timestamp(),
            "iat": datetime.now().timestamp(),
            "type": "access",
        }
        return _simple_jwt_encode(payload, self.secret_key)

    def create_refresh_token(self, user_id: str) -> str:
        payload = {
            "sub": user_id,
            "exp": (datetime.now() + timedelta(seconds=self.refresh_token_expiry)).timestamp(),
            "iat": datetime.now().timestamp(),
            "type": "refresh",
            "jti": uuid4().hex,
        }
        return _simple_jwt_encode(payload, self.secret_key)

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        payload = _simple_jwt_decode(token, self.secret_key)
        return payload

    def create_token_pair(self, user_id: str, role: UserRole) -> AuthToken:
        return AuthToken(
            access_token=self.create_access_token(user_id, role),
            refresh_token=self.create_refresh_token(user_id),
            expires_in=self.token_expiry,
        )

    def refresh_access_token(self, refresh_token: str) -> Optional[AuthToken]:
        payload = self.verify_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            return None
        return None


class AuthProvider(ABC):
    @abstractmethod
    async def authenticate(
        self, username: str, password: str, **kwargs
    ) -> Optional[User]:
        pass

    @abstractmethod
    async def get_user(self, user_id: str) -> Optional[User]:
        pass


class InMemoryUserStore:
    def __init__(self):
        self._users: Dict[str, User] = {}
        self._sessions: Dict[str, Session] = {}
        self._username_index: Dict[str, str] = {}
        self._email_index: Dict[str, str] = {}

    def add_user(self, user: User) -> None:
        self._users[user.user_id] = user
        self._username_index[user.username] = user.user_id
        self._email_index[user.email] = user.user_id

    def get_user(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id)

    def get_user_by_username(self, username: str) -> Optional[User]:
        user_id = self._username_index.get(username)
        return self._users.get(user_id) if user_id else None

    def get_user_by_email(self, email: str) -> Optional[User]:
        user_id = self._email_index.get(email)
        return self._users.get(user_id) if user_id else None

    def update_user(self, user: User) -> None:
        if user.user_id in self._users:
            self._users[user.user_id] = user

    def delete_user(self, user_id: str) -> bool:
        user = self._users.pop(user_id, None)
        if user:
            self._username_index.pop(user.username, None)
            self._email_index.pop(user.email, None)
            return True
        return False

    def add_session(self, session: Session) -> None:
        self._sessions[session.session_id] = session

    def get_session(self, session_id: str) -> Optional[Session]:
        return self._sessions.get(session_id)

    def invalidate_session(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if session:
            session.is_valid = False
            return True
        return False

    def cleanup_expired_sessions(self) -> int:
        now = datetime.now()
        expired = [
            sid
            for sid, session in self._sessions.items()
            if session.expires_at < now or not session.is_valid
        ]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)


class AuthenticationService:
    def __init__(
        self,
        secret_key: str,
        user_store: Optional[InMemoryUserStore] = None,
    ):
        self.user_store = user_store or InMemoryUserStore()
        self.token_manager = TokenManager(secret_key)
        self._sessions: Dict[str, Session] = {}

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: UserRole = UserRole.VIEWER,
    ) -> User:
        password_hash, salt = PasswordHasher.hash_password(password)
        user = User(
            user_id=uuid4().hex,
            username=username,
            email=email,
            role=role,
            password_hash=password_hash,
            salt=salt,
        )
        self.user_store.add_user(user)
        return user

    async def login(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Optional[AuthToken]:
        user = self.user_store.get_user_by_username(username)
        if not user or not user.is_active:
            return None

        if not PasswordHasher.verify_password(
            password, user.password_hash, user.salt
        ):
            return None

        token_pair = self.token_manager.create_token_pair(
            user.user_id, user.role
        )

        session = Session(
            session_id=token_pair.access_token[:32],
            user_id=user.user_id,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(seconds=self.token_manager.token_expiry),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self._sessions[session.session_id] = session

        user.last_login = datetime.now()
        self.user_store.update_user(user)

        return token_pair

    async def logout(self, access_token: str) -> bool:
        payload = self.token_manager.verify_token(access_token)
        if not payload:
            return False

        session_id = access_token[:32]
        session = self._sessions.pop(session_id, None)
        if session:
            session.is_valid = False
            return True
        return False

    async def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        payload = self.token_manager.verify_token(token)
        if not payload:
            return None

        session_id = token[:32]
        session = self._sessions.get(session_id)
        if not session or not session.is_valid:
            return None

        user = self.user_store.get_user(payload.get("sub"))
        if not user or not user.is_active:
            return None

        return {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "permissions": [p.value for p in ROLE_PERMISSIONS[user.role]],
        }

    def get_user_permissions(self, role: UserRole) -> Set[Permission]:
        return ROLE_PERMISSIONS.get(role, set())

    def has_permission(self, role: UserRole, permission: Permission) -> bool:
        return permission in ROLE_PERMISSIONS.get(role, set())

    def get_all_users(self) -> List[User]:
        return list(self.user_store._users.values())

    def update_user_role(self, user_id: str, role: UserRole) -> bool:
        user = self.user_store.get_user(user_id)
        if user:
            user.role = role
            self.user_store.update_user(user)
            return True
        return False

    def deactivate_user(self, user_id: str) -> bool:
        user = self.user_store.get_user(user_id)
        if user:
            user.is_active = False
            self.user_store.update_user(user)
            return True
        return False
