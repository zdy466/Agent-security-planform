"""Data Gateway - Controls data flow between LLM agents and external data sources"""

import logging
import re
import json
from typing import Any, Callable, Dict, List, Optional, Set
from enum import Enum
from dataclasses import dataclass


class DataSourceType(Enum):
    API = "api"
    DATABASE = "database"
    FILE = "file"
    MEMORY = "memory"


class TrustLevel(Enum):
    SYSTEM = "system"
    INTERNAL = "internal"
    AGENT = "agent"
    USER = "user"
    EXTERNAL = "external"


@dataclass
class FieldPermission:
    field_name: str
    readable: bool = True
    writable: bool = False
    maskable: bool = False
    mask_pattern: Optional[str] = None


@dataclass
class RowPermission:
    condition: str
    readable: bool = True
    writable: bool = False


@dataclass
class DataPermission:
    source: str
    read: bool = True
    write: bool = False
    trust_level: TrustLevel = TrustLevel.USER


class DataMasker:
    MASK_PATTERNS = {
        "email": lambda v: v.replace(v.split('@')[0], '***') if '@' in v else '***@***',
        "phone": lambda v: v[:3] + '****' + v[-4:] if len(v) >= 7 else '***-****-****',
        "id_card": lambda v: v[:6] + '********' + v[-4:] if len(v) >= 14 else '************',
        "bank_card": lambda v: v[:4] + ' **** **** ' + v[-4:] if len(v) >= 16 else '**** **** **** ****',
        "api_key": lambda v: v[:4] + '***' + v[-4:] if len(v) >= 8 else '***',
        "password": lambda v: '***' if v else '',
        "token": lambda v: v[:8] + '***' if len(v) >= 8 else '***',
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.default_mask_fields = self.config.get("default_mask_fields", [
            "password", "secret", "token", "api_key", "apikey", "credit_card"
        ])

    def mask_value(self, value: str, field_name: str, mask_type: Optional[str] = None) -> str:
        if not self.enabled or not value:
            return value

        field_lower = field_name.lower()
        
        if mask_type and mask_type in self.MASK_PATTERNS:
            return self.MASK_PATTERNS[mask_type](value)
        
        for key, mask_func in self.MASK_PATTERNS.items():
            if key in field_lower:
                return mask_func(value)
        
        return value

    def mask_dict(self, data: Dict[str, Any], fields_to_mask: Optional[Set[str]] = None) -> Dict[str, Any]:
        if not self.enabled or not isinstance(data, dict):
            return data

        fields = fields_to_mask or set()
        result = {}
        
        for key, value in data.items():
            if key.lower() in [f.lower() for f in fields] or key.lower() in self.default_mask_fields:
                if isinstance(value, str):
                    result[key] = self.mask_value(value, key)
                elif isinstance(value, dict):
                    result[key] = self.mask_dict(value, fields)
                elif isinstance(value, list):
                    result[key] = [self.mask_dict(item, fields) if isinstance(item, dict) else item for item in value]
                else:
                    result[key] = "***"
            else:
                result[key] = value
        
        return result


class SQLQueryValidator:
    FORBIDDEN_PATTERNS = [
        r"\bDROP\b",
        r"\bDELETE\b",
        r"\bTRUNCATE\b",
        r"\bALTER\b",
        r"\bCREATE\b",
        r"\bGRANT\b",
        r"\bREVOKE\b",
        r";\s*--",
        r"UNION\s+ALL",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.strict_mode = self.config.get("strict_mode", True)
        self.allowed_tables = self.config.get("allowed_tables", [])
        self._compile_patterns()

    def _compile_patterns(self):
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.FORBIDDEN_PATTERNS]

    def validate(self, query: str) -> Dict[str, Any]:
        errors = []
        warnings = []

        for pattern in self.compiled_patterns:
            if pattern.search(query):
                if self.strict_mode:
                    errors.append(f"Forbidden pattern detected: {pattern.pattern}")
                else:
                    warnings.append(f"Suspicious pattern detected: {pattern.pattern}")

        if self.allowed_tables:
            table_pattern = re.compile(r"FROM\s+(\w+)|JOIN\s+(\w+)", re.IGNORECASE)
            for match in table_pattern.finditer(query):
                table_name = match.group(1) or match.group(2)
                if table_name.lower() not in [t.lower() for t in self.allowed_tables]:
                    errors.append(f"Table '{table_name}' is not in allowed list")

        if errors:
            return {"valid": False, "errors": errors}
        elif warnings:
            return {"valid": True, "warnings": warnings}
        return {"valid": True}


class DataGateway:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.enabled = self.config.get("enabled", True)
        self.data_sources: Dict[str, DataSourceType] = {}
        self.permissions: List[DataPermission] = []
        
        self.field_permissions: Dict[str, List[FieldPermission]] = {}
        self.row_permissions: Dict[str, List[RowPermission]] = {}
        
        self.masker = DataMasker(self.config.get("masker", {}))
        self.query_validator = SQLQueryValidator(self.config.get("query_validator", {}))
        
        self.enable_field_level_control = self.config.get("enable_field_level_control", True)
        self.enable_row_level_control = self.config.get("enable_row_level_control", True)
        self.enable_data_masking = self.config.get("enable_data_masking", True)

    def register_data_source(self, name: str, source_type: DataSourceType):
        self.data_sources[name] = source_type
        self.logger.info(f"Registered data source: {name} ({source_type.value})")

    def register_data_source_with_permissions(
        self,
        name: str,
        source_type: DataSourceType,
        field_permissions: Optional[List[FieldPermission]] = None,
        row_permissions: Optional[List[RowPermission]] = None
    ):
        self.register_data_source(name, source_type)
        if field_permissions:
            self.field_permissions[name] = field_permissions
        if row_permissions:
            self.row_permissions[name] = row_permissions

    def grant_permission(
        self,
        source: str,
        read: bool = True,
        write: bool = False,
        trust_level: TrustLevel = TrustLevel.USER
    ):
        permission = DataPermission(source, read, write, trust_level)
        self.permissions.append(permission)

    def revoke_permission(self, source: str):
        self.permissions = [p for p in self.permissions if p.source != source]

    def can_read(self, source: str) -> bool:
        for permission in self.permissions:
            if permission.source == source:
                return permission.read
        return False

    def can_write(self, source: str) -> bool:
        for permission in self.permissions:
            if permission.source == source:
                return permission.write
        return False

    def set_field_permissions(self, source: str, fields: List[FieldPermission]):
        self.field_permissions[source] = fields

    def set_row_permissions(self, source: str, rows: List[RowPermission]):
        self.row_permissions[source] = rows

    def _apply_field_permissions(self, source: str, data: Any) -> Any:
        if not self.enable_field_level_control or source not in self.field_permissions:
            return data

        if not isinstance(data, dict):
            return data

        fields = self.field_permissions[source]
        result = {}
        
        for field_perm in fields:
            if field_perm.field_name in data:
                if field_perm.readable:
                    if field_perm.maskable and self.enable_data_masking:
                        value = data[field_perm.field_name]
                        if isinstance(value, str):
                            result[field_perm.field_name] = self.masker.mask_value(
                                value, field_perm.field_name, field_perm.mask_pattern
                            )
                        else:
                            result[field_perm.field_name] = value
                    else:
                        result[field_perm.field_name] = data[field_perm.field_name]
                else:
                    pass
            else:
                result[field_perm.field_name] = None
        
        for key, value in data.items():
            if key not in [f.field_name for f in fields]:
                result[key] = value
        
        return result

    def _apply_row_permissions(self, source: str, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self.enable_row_level_control or source not in self.row_permissions:
            return data

        row_perms = self.row_permissions[source]
        filtered_data = []

        for row in data:
            allowed = True
            for row_perm in row_perms:
                try:
                    for key, value in row.items():
                        if key in row_perm.condition:
                            if not eval(row_perm.condition, {"__builtins__": {}}, {key: value}):
                                allowed = False
                                break
                except:
                    pass
            
            if allowed:
                filtered_data.append(row)

        return filtered_data

    def read_data(
        self,
        source: str,
        query: Optional[Dict[str, Any]] = None,
        fields: Optional[List[str]] = None
    ) -> Any:
        if not self.enabled:
            raise RuntimeError("DataGateway is disabled")

        if not self.can_read(source):
            raise PermissionError(f"Read permission denied for source: {source}")

        self.logger.info(f"Reading data from source: {source}")

        if query:
            sql_query = query.get("sql")
            if sql_query:
                validation = self.query_validator.validate(sql_query)
                if not validation.get("valid"):
                    raise ValueError(f"Query validation failed: {validation.get('errors')}")

        mock_data = [{"id": 1, "name": "Sample Data", "email": "test@example.com"}]
        
        result = mock_data
        
        if fields:
            result = [{k: v for k, v in row.items() if k in fields} for row in result]
        
        if self.enable_field_level_control and source in self.field_permissions:
            result = [self._apply_field_permissions(source, row) for row in result]
        
        if self.enable_row_level_control and source in self.row_permissions:
            result = self._apply_row_permissions(source, result)

        return result if len(result) > 1 else result[0] if result else None

    def write_data(self, source: str, data: Any) -> bool:
        if not self.enabled:
            raise RuntimeError("DataGateway is disabled")

        if not self.can_write(source):
            raise PermissionError(f"Write permission denied for source: {source}")

        self.logger.info(f"Writing data to source: {source}")
        return True

    def execute_query(self, source: str, query: str) -> Any:
        if not self.enabled:
            raise RuntimeError("DataGateway is disabled")

        if not self.can_read(source):
            raise PermissionError(f"Query permission denied for source: {source}")

        validation = self.query_validator.validate(query)
        if not validation.get("valid"):
            raise ValueError(f"Query validation failed: {validation.get('errors')}")

        self.logger.info(f"Executing query on source: {source}")
        return []

    def get_field_permissions(self, source: str) -> List[FieldPermission]:
        return self.field_permissions.get(source, [])

    def get_row_permissions(self, source: str) -> List[RowPermission]:
        return self.row_permissions.get(source, [])
