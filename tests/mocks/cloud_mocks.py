"""Mock implementations for cloud services testing"""

from typing import Any, Dict, List, Optional
from datetime import datetime
import json

from agentshield.integrations.cloud.base import (
    CloudAdapter, CloudConfig, CloudDataResult, CloudProvider, CloudResource
)


class MockCloudAdapter(CloudAdapter):
    """Base mock adapter for testing"""

    def __init__(self, config: CloudConfig):
        super().__init__(config)
        self._storage: Dict[str, Dict[str, Any]] = {}
        self._calls: List[str] = []

    def connect(self) -> bool:
        self._calls.append("connect")
        self._connected = True
        return True

    def disconnect(self) -> None:
        self._calls.append("disconnect")
        self._connected = False

    def list_buckets(self) -> List[CloudResource]:
        self._calls.append("list_buckets")
        return [
            CloudResource(
                resource_id="mock-bucket-1",
                resource_type="bucket",
                name="mock-bucket-1",
                region=self.config.region or "us-east-1"
            ),
            CloudResource(
                resource_id="mock-bucket-2",
                resource_type="bucket",
                name="mock-bucket-2",
                region=self.config.region or "us-east-1"
            )
        ]

    def list_objects(self, bucket: str, prefix: str = "") -> List[CloudResource]:
        self._calls.append(f"list_objects({bucket}, {prefix})")
        return []

    def read_data(self, bucket: str, key: str) -> CloudDataResult:
        self._calls.append(f"read_data({bucket}, {key})")
        if bucket in self._storage and key in self._storage[bucket]:
            return CloudDataResult(
                success=True,
                data=self._storage[bucket][key],
                operation="mock_read",
                resource_id=f"{bucket}/{key}"
            )
        return CloudDataResult(
            success=False,
            error="Key not found",
            operation="mock_read",
            resource_id=f"{bucket}/{key}"
        )

    def write_data(self, bucket: str, key: str, data: Any, metadata: Optional[Dict] = None) -> CloudDataResult:
        self._calls.append(f"write_data({bucket}, {key})")
        if bucket not in self._storage:
            self._storage[bucket] = {}
        self._storage[bucket][key] = {
            "data": data,
            "metadata": metadata or {},
            "timestamp": datetime.now().isoformat()
        }
        return CloudDataResult(
            success=True,
            operation="mock_write",
            resource_id=f"{bucket}/{key}"
        )

    def delete_data(self, bucket: str, key: str) -> CloudDataResult:
        self._calls.append(f"delete_data({bucket}, {key})")
        if bucket in self._storage and key in self._storage[bucket]:
            del self._storage[bucket][key]
            return CloudDataResult(
                success=True,
                operation="mock_delete",
                resource_id=f"{bucket}/{key}"
            )
        return CloudDataResult(
            success=False,
            error="Key not found",
            operation="mock_delete",
            resource_id=f"{bucket}/{key}"
        )

    def check_connection(self) -> bool:
        self._calls.append("check_connection")
        return self._connected

    def get_calls(self) -> List[str]:
        """Get list of method calls for testing"""
        return self._calls.copy()

    def clear_calls(self) -> None:
        """Clear call history"""
        self._calls.clear()

    def clear_storage(self) -> None:
        """Clear storage data"""
        self._storage.clear()


class MockS3Connector(MockCloudAdapter):
    """Mock AWS S3 connector for testing"""

    def __init__(self, config: CloudConfig):
        super().__init__(config)
        self.config.provider = CloudProvider.AWS

    def get_object_metadata(self, bucket: str, key: str) -> Dict[str, Any]:
        if bucket in self._storage and key in self._storage[bucket]:
            return self._storage[bucket][key].get("metadata", {})
        return {}

    def generate_presigned_url(self, bucket: str, key: str, expiration: int = 3600) -> str:
        return f"https://{bucket}.s3.amazonaws.com/{key}?signed=true&expires={expiration}"

    def copy_object(self, source_bucket: str, source_key: str, dest_bucket: str, dest_key: str) -> CloudDataResult:
        result = self.read_data(source_bucket, source_key)
        if result.success:
            return self.write_data(dest_bucket, dest_key, result.data)
        return CloudDataResult(success=False, error="Source not found")


class MockBlobConnector(MockCloudAdapter):
    """Mock Azure Blob connector for testing"""

    def __init__(self, config: CloudConfig):
        super().__init__(config)
        self.config.provider = CloudProvider.AZURE

    def get_object_metadata(self, container: str, blob: str) -> Dict[str, Any]:
        if container in self._storage and blob in self._storage[container]:
            return self._storage[container][blob].get("metadata", {})
        return {}

    def generate_presigned_url(self, container: str, blob: str, expiration: int = 3600) -> str:
        return f"https://mockaccount.blob.core.windows.net/{container}/{blob}?sig=xxx"


class MockGCSConnector(MockCloudAdapter):
    """Mock GCP GCS connector for testing"""

    def __init__(self, config: CloudConfig):
        super().__init__(config)
        self.config.provider = CloudProvider.GCP

    def get_object_metadata(self, bucket: str, key: str) -> Dict[str, Any]:
        if bucket in self._storage and key in self._storage[bucket]:
            return self._storage[bucket][key].get("metadata", {})
        return {}

    def generate_presigned_url(self, bucket: str, key: str, expiration: int = 3600) -> str:
        return f"https://storage.googleapis.com/{bucket}/{key}?signed=true"


class MockOSSConnector(MockCloudAdapter):
    """Mock Aliyun OSS connector for testing"""

    def __init__(self, config: CloudConfig):
        super().__init__(config)
        self.config.provider = CloudProvider.ALIYUN

    def get_object_metadata(self, bucket: str, key: str) -> Dict[str, Any]:
        if bucket in self._storage and key in self._storage[bucket]:
            return self._storage[bucket][key].get("metadata", {})
        return {}

    def generate_presigned_url(self, bucket: str, key: str, expiration: int = 3600) -> str:
        return f"https://{bucket}.oss-cn-hangzhou.aliyuncs.com/{key}?sig=xxx"


class MockLambdaConnector(MockCloudAdapter):
    """Mock AWS Lambda connector for testing"""

    def __init__(self, config: CloudConfig):
        super().__init__(config)
        self._functions: Dict[str, Any] = {}

    def list_buckets(self) -> List[CloudResource]:
        return [
            CloudResource(
                resource_id=fn_name,
                resource_type="lambda",
                name=fn_name,
                region=self.config.region or "us-east-1"
            )
            for fn_name in self._functions.keys()
        ]

    def list_functions(self) -> List[CloudResource]:
        return self.list_buckets()

    def invoke_function(self, function_name: str, payload: Dict[str, Any]) -> CloudDataResult:
        if function_name in self._functions:
            fn = self._functions[function_name]
            return CloudDataResult(
                success=True,
                data={"result": fn.get("response", "Function executed")},
                operation="lambda_invoke",
                resource_id=f"lambda://{function_name}"
            )
        return CloudDataResult(
            success=False,
            error="Function not found",
            operation="lambda_invoke"
        )

    def register_function(self, name: str, response: Any = None) -> None:
        self._functions[name] = {"response": response}

    def get_function_logs(self, function_name: str, limit: int = 100) -> List[str]:
        return [f"Log entry {i} for {function_name}" for i in range(min(limit, 5))]


class MockDynamoDBConnector(MockCloudAdapter):
    """Mock AWS DynamoDB connector for testing"""

    def __init__(self, config: CloudConfig):
        super().__init__(config)
        self._tables: Dict[str, List[Dict]] = {}

    def list_buckets(self) -> List[CloudResource]:
        return [
            CloudResource(
                resource_id=table_name,
                resource_type="dynamodb_table",
                name=table_name,
                region=self.config.region or "us-east-1"
            )
            for table_name in self._tables.keys()
        ]

    def list_tables(self) -> List[str]:
        return list(self._tables.keys())

    def execute_query(self, query: str, params: Optional[Dict] = None) -> CloudDataResult:
        return CloudDataResult(
            success=True,
            data={"items": [], "count": 0},
            operation="dynamodb_query"
        )

    def get_table_schema(self, table_name: str) -> Dict[str, Any]:
        return {
            "table_name": table_name,
            "key_schema": [{"attribute_name": "id", "key_type": "HASH"}]
        }

    def put_item(self, table: str, item: Dict) -> CloudDataResult:
        if table not in self._tables:
            self._tables[table] = []
        self._tables[table].append(item)
        return CloudDataResult(success=True, operation="dynamodb_put")

    def get_item(self, table: str, key: Dict) -> CloudDataResult:
        if table in self._tables:
            for item in self._tables[table]:
                if all(item.get(k) == v for k, v in key.items()):
                    return CloudDataResult(success=True, data=item, operation="dynamodb_get")
        return CloudDataResult(success=False, error="Item not found")
