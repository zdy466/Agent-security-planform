"""Data Encryption Module - Sensitive data at-rest encryption"""

import os
import base64
import hashlib
import logging
from typing import Any, Dict, Optional, Union
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class EncryptionAlgorithm:
    AES_256_GCM = "aes_256_gcm"
    FERNET = "fernet"
    AES_256_CBC = "aes_256_cbc"


class KeyDerivation:
    @staticmethod
    def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))


class DataEncryptor:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.algorithm = self.config.get("algorithm", EncryptionAlgorithm.FERNET)
        self.master_key = self.config.get("master_key")
        self.key_rotation_days = self.config.get("key_rotation_days", 90)
        self.last_rotation = self.config.get("last_rotation")
        
        if self.master_key:
            self._init_cipher()
        else:
            self._cipher = None
            
        self.encrypted_fields = self.config.get("encrypted_fields", [])
        self.field_keys: Dict[str, str] = {}

    def _init_cipher(self):
        if self.algorithm == EncryptionAlgorithm.FERNET:
            if isinstance(self.master_key, str):
                try:
                    self.master_key = self.master_key.encode()
                    self._cipher = Fernet(self.master_key)
                except Exception:
                    self._cipher = Fernet(Fernet.generate_key())
            else:
                self._cipher = Fernet(Fernet.generate_key())
        else:
            self._cipher = self.master_key

    def encrypt(self, data: Any, field_name: Optional[str] = None) -> Any:
        if self._cipher is None:
            self.logger.warning("Encryption not configured, returning raw data")
            return data

        if field_name and field_name in self.encrypted_fields:
            return self._encrypt_field(data, field_name)
        
        if isinstance(data, dict):
            return {k: self.encrypt(v, k) for k, v in data.items()}
        elif isinstance(data, str):
            return self._encrypt_string(data)
        elif isinstance(data, bytes):
            return self._encrypt_bytes(data)
        
        return data

    def _encrypt_field(self, data: Any, field_name: str) -> Any:
        if field_name not in self.field_keys:
            field_key = self._generate_field_key(field_name)
            self.field_keys[field_name] = field_key
        
        cipher = Fernet(self.field_keys[field_name].encode())
        
        if isinstance(data, str):
            encrypted = cipher.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        
        return data

    def _encrypt_string(self, data: str) -> str:
        if self.algorithm == EncryptionAlgorithm.FERNET:
            encrypted = self._cipher.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        return data

    def _encrypt_bytes(self, data: bytes) -> str:
        if self.algorithm == EncryptionAlgorithm.FERNET:
            encrypted = self._cipher.encrypt(data)
            return base64.urlsafe_b64encode(encrypted).decode()
        return base64.b64encode(data).decode()

    def decrypt(self, data: Any, field_name: Optional[str] = None) -> Any:
        if self._cipher is None:
            return data

        if field_name and field_name in self.encrypted_fields:
            return self._decrypt_field(data, field_name)
        
        if isinstance(data, dict):
            return {k: self.decrypt(v, k) for k, v in data.items()}
        elif isinstance(data, str) and self._is_encrypted(data):
            return self._decrypt_string(data)
        
        return data

    def _decrypt_field(self, data: Any, field_name: str) -> Any:
        if field_name not in self.field_keys:
            return data
            
        try:
            cipher = Fernet(self.field_keys[field_name].encode())
            decoded = base64.urlsafe_b64decode(data.encode())
            decrypted = cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            self.logger.error(f"Decryption failed for field {field_name}: {e}")
            return data

    def _decrypt_string(self, data: str) -> str:
        try:
            if self.algorithm == EncryptionAlgorithm.FERNET:
                decoded = base64.urlsafe_b64decode(data.encode())
                decrypted = self._cipher.decrypt(decoded)
                return decrypted.decode()
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
        return data

    def _is_encrypted(self, data: str) -> bool:
        try:
            decoded = base64.urlsafe_b64decode(data.encode())
            return len(decoded) > 0
        except:
            return False

    def _generate_field_key(self, field_name: str) -> str:
        if not self.master_key:
            return Fernet.generate_key().decode()
        
        salt = hashlib.sha256(field_name.encode()).digest()
        derived = KeyDerivation.derive_key(
            self.master_key.decode() if isinstance(self.master_key, bytes) else self.master_key,
            salt
        )
        return derived.decode()

    def rotate_keys(self) -> bool:
        try:
            if self.algorithm == EncryptionAlgorithm.FERNET:
                new_key = Fernet.generate_key()
                self.master_key = new_key
                self._init_cipher()
                
                for field_name in self.field_keys:
                    self.field_keys[field_name] = self._generate_field_key(field_name)
                
                self.last_rotation = datetime.now()
                self.logger.info("Keys rotated successfully")
                return True
        except Exception as e:
            self.logger.error(f"Key rotation failed: {e}")
        return False

    def should_rotate(self) -> bool:
        if not self.last_rotation:
            return True
        
        days_since_rotation = (datetime.now() - self.last_rotation).days
        return days_since_rotation >= self.key_rotation_days


class FieldLevelEncryption:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.encryptor = DataEncryptor(config.get("encryptor", {}))
        self.encrypted_fields = config.get("fields", [])
        self.exclusions = config.get("exclusions", [])

    def encrypt_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        encrypted = {}
        for field, value in record.items():
            if field in self.encrypted_fields and field not in self.exclusions:
                encrypted[field] = self.encryptor.encrypt(value, field)
            else:
                encrypted[field] = value
        return encrypted

    def decrypt_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        decrypted = {}
        for field, value in record.items():
            if field in self.encrypted_fields and field not in self.exclusions:
                decrypted[field] = self.encryptor.decrypt(value, field)
            else:
                decrypted[field] = value
        return decrypted


class TransparentDataEncryption:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.encryptor = DataEncryptor(self.config.get("encryptor", {}))
        self.sensitive_patterns = self.config.get("sensitive_patterns", [
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"\b\d{16}\b",
            r"sk-[a-zA-Z0-9]{20,}",
            r"api_key[=:]\s*\S+",
            r"password[=:]\s*\S+",
        ])
        self.auto_encrypt = self.config.get("auto_encrypt", True)

    def protect(self, data: Any) -> Any:
        if not self.auto_encrypt:
            return data
        
        if isinstance(data, str):
            return self._protect_string(data)
        elif isinstance(data, dict):
            return self._protect_dict(data)
        
        return data

    def _protect_string(self, text: str) -> str:
        import re
        protected = text
        for pattern in self.sensitive_patterns:
            if re.search(pattern, protected, re.IGNORECASE):
                match = re.search(r"(api_key|password)[=:]\s*(\S+)", protected, re.IGNORECASE)
                if match:
                    replacement = f"{match.group(1)}=***REDACTED***"
                    protected = protected[:match.start()] + replacement + protected[match.end():]
        return protected

    def _protect_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        protected = {}
        for key, value in data.items():
            if isinstance(value, str):
                protected[key] = self._protect_string(value)
            elif isinstance(value, dict):
                protected[key] = self._protect_dict(value)
            elif isinstance(value, list):
                protected[key] = [self._protect_string(v) if isinstance(v, str) else v for v in value]
            else:
                protected[key] = value
        return protected
