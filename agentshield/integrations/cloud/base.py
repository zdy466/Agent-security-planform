"""Cloud adapter base classes and interfaces"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALIYUN = "aliyun"
    LOCAL = "local"


@dataclass
class CloudConfig:
    """Cloud provider configuration"""
    provider: CloudProvider
    region: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    project_id: Optional[str] = None
    tenant_id: Optional[str] = None
    subscription_id: Optional[str] = None
    credentials_path: Optional[str] = None
    endpoint: Optional[str] = None
    timeout: int = 30
    retry_count: int = 3
    custom_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudResource:
    """Cloud resource representation"""
    resource_id: str
    resource_type: str
    name: str
    region: Optional[str] = None
    arn: Optional[str] = None
    created_at: Optional[datetime] = None
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudDataResult:
    """Result from cloud data operation"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    operation: str = ""
    resource_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


class CloudAdapter(ABC):
    """Base class for cloud provider adapters"""

    def __init__(self, config: CloudConfig):
        self.config = config
        self._connected = False

    @property
    def provider(self) -> CloudProvider:
        """Get cloud provider type"""
        return self.config.provider

    @property
    def connected(self) -> bool:
        """Check if adapter is connected"""
        return self._connected

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to cloud provider"""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from cloud provider"""
        pass

    @abstractmethod
    def list_buckets(self) -> List[CloudResource]:
        """List storage buckets/containers"""
        pass

    @abstractmethod
    def list_objects(self, bucket: str, prefix: str = "") -> List[CloudResource]:
        """List objects in a bucket"""
        pass

    @abstractmethod
    def read_data(self, bucket: str, key: str) -> CloudDataResult:
        """Read data from cloud storage"""
        pass

    @abstractmethod
    def write_data(self, bucket: str, key: str, data: Any, metadata: Optional[Dict] = None) -> CloudDataResult:
        """Write data to cloud storage"""
        pass

    @abstractmethod
    def delete_data(self, bucket: str, key: str) -> CloudDataResult:
        """Delete data from cloud storage"""
        pass

    @abstractmethod
    def check_connection(self) -> bool:
        """Check if connection is alive"""
        pass


class StorageConnector(CloudAdapter):
    """Base class for cloud storage services"""

    @abstractmethod
    def get_object_metadata(self, bucket: str, key: str) -> Dict[str, Any]:
        """Get object metadata"""
        pass

    @abstractmethod
    def generate_presigned_url(self, bucket: str, key: str, expiration: int = 3600) -> str:
        """Generate presigned URL for temporary access"""
        pass

    @abstractmethod
    def copy_object(self, source_bucket: str, source_key: str, dest_bucket: str, dest_key: str) -> CloudDataResult:
        """Copy object within or between buckets"""
        pass


class ComputeConnector(CloudAdapter):
    """Base class for cloud compute services"""

    @abstractmethod
    def list_functions(self) -> List[CloudResource]:
        """List compute functions"""
        pass

    @abstractmethod
    def invoke_function(self, function_name: str, payload: Dict[str, Any]) -> CloudDataResult:
        """Invoke a compute function"""
        pass

    @abstractmethod
    def get_function_logs(self, function_name: str, limit: int = 100) -> List[str]:
        """Get function execution logs"""
        pass


class DatabaseConnector(CloudAdapter):
    """Base class for cloud database services"""

    @abstractmethod
    def execute_query(self, query: str, params: Optional[Dict] = None) -> CloudDataResult:
        """Execute database query"""
        pass

    @abstractmethod
    def list_tables(self) -> List[str]:
        """List database tables"""
        pass

    @abstractmethod
    def get_table_schema(self, table_name: str) -> Dict[str, Any]:
        """Get table schema"""
        pass
