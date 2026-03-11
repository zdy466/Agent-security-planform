"""Key Rotation Module - Automatic API key rotation"""

import os
import time
import logging
import hashlib
import secrets
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import base64


class KeyStatus(Enum):
    ACTIVE = "active"
    ROTATING = "rotating"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"


class KeyType(Enum):
    API_KEY = "api_key"
    SECRET_KEY = "secret_key"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    ENCRYPTION_KEY = "encryption_key"
    SIGNING_KEY = "signing_key"


@dataclass
class KeyMetadata:
    key_id: str
    key_type: KeyType
    name: str
    created_at: datetime
    expires_at: Optional[datetime]
    last_rotated: Optional[datetime]
    last_used: Optional[datetime]
    rotation_period_days: int
    status: KeyStatus
    version: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KeyRotationResult:
    success: bool
    old_key_id: str
    new_key_id: str
    rotated_at: datetime
    message: str = ""


class KeyGenerator:
    @staticmethod
    def generate_api_key(prefix: str = "sk", length: int = 32) -> str:
        random_part = secrets.token_urlsafe(length)
        return f"{prefix}_{random_part}"
    
    @staticmethod
    def generate_secret_key(length: int = 64) -> str:
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_password(length: int = 24) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def hash_key(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()
    
    @staticmethod
    def get_key_fingerprint(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()[:16]


class KeyRotationManager:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        self.default_rotation_days = self.config.get("default_rotation_days", 90)
        self.grace_period_hours = self.config.get("grace_period_hours", 24)
        self.max_keys_per_type = self.config.get("max_keys_per_type", 3)
        
        self.keys: Dict[str, KeyMetadata] = {}
        self.key_values: Dict[str, str] = {}
        self.rotation_queue: List[str] = []
        
        self.storage_path = self.config.get("storage_path")
        self._load_keys()
        
        self.rotation_callbacks: List[Callable] = []
        self.auto_rotate_enabled = self.config.get("auto_rotate", True)
        
        if self.auto_rotate_enabled:
            self._start_rotation_scheduler()
    
    def _load_keys(self):
        if self.storage_path and os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    for key_id, meta in data.get("keys", {}).items():
                        meta["created_at"] = datetime.fromisoformat(meta["created_at"])
                        meta["expires_at"] = datetime.fromisoformat(meta["expires_at"]) if meta.get("expires_at") else None
                        meta["last_rotated"] = datetime.fromisoformat(meta["last_rotated"]) if meta.get("last_rotated") else None
                        meta["last_used"] = datetime.fromisoformat(meta["last_used"]) if meta.get("last_used") else None
                        meta["key_type"] = KeyType(meta["key_type"])
                        meta["status"] = KeyStatus(meta["status"])
                        self.keys[key_id] = KeyMetadata(**meta)
            except Exception as e:
                self.logger.error(f"Failed to load keys: {e}")
    
    def _save_keys(self):
        if not self.storage_path:
            return
        
        data = {
            "keys": {
                key_id: {
                    "key_id": meta.key_id,
                    "key_type": meta.key_type.value,
                    "name": meta.name,
                    "created_at": meta.created_at.isoformat(),
                    "expires_at": meta.expires_at.isoformat() if meta.expires_at else None,
                    "last_rotated": meta.last_rotated.isoformat() if meta.last_rotated else None,
                    "last_used": meta.last_used.isoformat() if meta.last_used else None,
                    "rotation_period_days": meta.rotation_period_days,
                    "status": meta.status.value,
                    "version": meta.version,
                    "metadata": meta.metadata
                }
                for key_id, meta in self.keys.items()
            }
        }
        
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def create_key(
        self,
        name: str,
        key_type: KeyType = KeyType.API_KEY,
        rotation_period_days: Optional[int] = None,
        expires_in_days: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        key_id = secrets.token_hex(16)
        
        if key_type == KeyType.API_KEY:
            key_value = KeyGenerator.generate_api_key()
        elif key_type == KeyType.SECRET_KEY:
            key_value = KeyGenerator.generate_secret_key()
        elif key_type == KeyType.ENCRYPTION_KEY:
            key_value = KeyGenerator.generate_api_key("enckey", 32)
        elif key_type == KeyType.SIGNING_KEY:
            new_key_value = KeyGenerator.generate_api_key("sigkey", 32)
        else:
            key_value = KeyGenerator.generate_api_key()
        
        rotation_days = rotation_period_days or self.default_rotation_days
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now() + timedelta(days=expires_in_days)
        elif rotation_days > 0:
            expires_at = datetime.now() + timedelta(days=rotation_days * 2)
        
        meta = KeyMetadata(
            key_id=key_id,
            key_type=key_type,
            name=name,
            created_at=datetime.now(),
            expires_at=expires_at,
            last_rotated=datetime.now(),
            last_used=None,
            rotation_period_days=rotation_days,
            status=KeyStatus.ACTIVE,
            version=1,
            metadata=metadata or {}
        )
        
        self.keys[key_id] = meta
        self.key_values[key_id] = key_value
        
        self._save_keys()
        
        self.logger.info(f"Created key: {key_id} ({name})")
        
        return {
            "key_id": key_id,
            "key": key_value,
            "key_type": key_type.value,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "rotation_period_days": rotation_days
        }
    
    def rotate_key(self, key_id: str) -> KeyRotationResult:
        if key_id not in self.keys:
            return KeyRotationResult(
                success=False,
                old_key_id=key_id,
                new_key_id="",
                rotated_at=datetime.now(),
                message="Key not found"
            )
        
        old_meta = self.keys[key_id]
        old_meta.status = KeyStatus.ROTATING
        
        old_key_value = self.key_values.get(key_id)
        
        new_key_id = secrets.token_hex(16)
        key_type = old_meta.key_type
        
        if key_type == KeyType.API_KEY:
            new_key_value = KeyGenerator.generate_api_key()
        elif key_type == KeyType.SECRET_KEY:
            new_key_value = KeyGenerator.generate_secret_key()
        else:
            new_key_value = KeyGenerator.generate_api_key()
        
        expires_at = None
        if old_meta.rotation_period_days > 0:
            expires_at = datetime.now() + timedelta(days=old_meta.rotation_period_days)
        
        new_meta = KeyMetadata(
            key_id=new_key_id,
            key_type=key_type,
            name=f"{old_meta.name} (rotated)",
            created_at=datetime.now(),
            expires_at=expires_at,
            last_rotated=datetime.now(),
            last_used=None,
            rotation_period_days=old_meta.rotation_period_days,
            status=KeyStatus.ACTIVE,
            version=old_meta.version + 1,
            metadata=old_meta.metadata.copy()
        )
        
        self.keys[new_key_id] = new_meta
        self.key_values[new_key_id] = new_key_value
        
        old_meta.status = KeyStatus.REVOKED
        old_meta.last_rotated = datetime.now()
        
        self._save_keys()
        
        for callback in self.rotation_callbacks:
            try:
                callback(old_key_id, new_key_id, old_key_value, new_key_value)
            except Exception as e:
                self.logger.error(f"Rotation callback error: {e}")
        
        self.logger.info(f"Rotated key: {key_id} -> {new_key_id}")
        
        return KeyRotationResult(
            success=True,
            old_key_id=key_id,
            new_key_id=new_key_id,
            rotated_at=datetime.now(),
            message="Key rotated successfully"
        )
    
    def auto_rotate_all(self) -> List[KeyRotationResult]:
        results = []
        keys_to_rotate = self.get_keys_needing_rotation()
        
        for key_id in keys_to_rotate:
            result = self.rotate_key(key_id)
            results.append(result)
        
        return results
    
    def get_keys_needing_rotation(self) -> List[str]:
        keys_to_rotate = []
        
        for key_id, meta in self.keys.items():
            if meta.status != KeyStatus.ACTIVE:
                continue
            
            if meta.expires_at and datetime.now() >= meta.expires_at:
                keys_to_rotate.append(key_id)
                continue
            
            if meta.rotation_period_days > 0 and meta.last_rotated:
                days_since_rotation = (datetime.now() - meta.last_rotated).days
                if days_since_rotation >= meta.rotation_period_days:
                    keys_to_rotate.append(key_id)
        
        return keys_to_rotate
    
    def validate_key(self, key_id: str, key_value: str) -> bool:
        if key_id not in self.keys:
            return False
        
        meta = self.keys[key_id]
        
        if meta.status != KeyStatus.ACTIVE:
            return False
        
        if meta.expires_at and datetime.now() >= meta.expires_at:
            meta.status = KeyStatus.EXPIRED
            return False
        
        stored_value = self.key_values.get(key_id)
        if not stored_value or stored_value != key_value:
            return False
        
        meta.last_used = datetime.now()
        self._save_keys()
        
        return True
    
    def revoke_key(self, key_id: str) -> bool:
        if key_id not in self.keys:
            return False
        
        self.keys[key_id].status = KeyStatus.REVOKED
        
        if key_id in self.key_values:
            self.key_values[key_id] = ""
        
        self._save_keys()
        
        self.logger.info(f"Revoked key: {key_id}")
        return True
    
    def get_key_info(self, key_id: str) -> Optional[Dict[str, Any]]:
        if key_id not in self.keys:
            return None
        
        meta = self.keys[key_id]
        
        return {
            "key_id": meta.key_id,
            "name": meta.name,
            "key_type": meta.key_type.value,
            "status": meta.status.value,
            "created_at": meta.created_at.isoformat(),
            "expires_at": meta.expires_at.isoformat() if meta.expires_at else None,
            "last_rotated": meta.last_rotated.isoformat() if meta.last_rotated else None,
            "last_used": meta.last_used.isoformat() if meta.last_used else None,
            "rotation_period_days": meta.rotation_period_days,
            "version": meta.version,
            "metadata": meta.metadata
        }
    
    def list_keys(
        self,
        key_type: Optional[KeyType] = None,
        status: Optional[KeyStatus] = None
    ) -> List[Dict[str, Any]]:
        result = []
        
        for key_id, meta in self.keys.items():
            if key_type and meta.key_type != key_type:
                continue
            if status and meta.status != status:
                continue
            
            result.append(self.get_key_info(key_id))
        
        return result
    
    def register_rotation_callback(self, callback: Callable):
        self.rotation_callbacks.append(callback)
    
    def _start_rotation_scheduler(self):
        def scheduler():
            while True:
                check_interval = 3600
                time.sleep(check_interval)
                
                if self.auto_rotate_enabled:
                    self.auto_rotate_all()
        
        thread = threading.Thread(target=scheduler, daemon=True)
        thread.start()
    
    def get_expiring_keys(self, days: int = 7) -> List[Dict[str, Any]]:
        expiring = []
        cutoff = datetime.now() + timedelta(days=days)
        
        for key_id, meta in self.keys.items():
            if meta.status != KeyStatus.ACTIVE:
                continue
            
            if meta.expires_at and meta.expires_at <= cutoff:
                expiring.append(self.get_key_info(key_id))
        
        return expiring


import string
