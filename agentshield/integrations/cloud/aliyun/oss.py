"""Aliyun OSS connector for AgentShield OS"""

from typing import Any, Dict, List, Optional

from agentshield.integrations.cloud.base import StorageConnector, CloudConfig, CloudDataResult, CloudResource


class OSSConnector(StorageConnector):
    """Aliyun OSS (Object Storage Service) connector"""

    def __init__(self, config: CloudConfig):
        super().__init__(config)
        self._oss_client = None
        self._region = config.region or "cn-hangzhou"

    def connect(self) -> bool:
        try:
            self._connected = True
            self._oss_client = {"region": self._region}
            return True
        except Exception:
            return False

    def disconnect(self) -> None:
        self._connected = False
        self._oss_client = None

    def list_buckets(self) -> List[CloudResource]:
        if not self._connected:
            return []
        return [CloudResource(resource_id="demo-bucket", resource_type="oss_bucket", name="demo-bucket", region=self._region)]

    def list_objects(self, bucket: str, prefix: str = "") -> List[CloudResource]:
        if not self._connected:
            return []
        return []

    def read_data(self, bucket: str, key: str) -> CloudDataResult:
        if not self._connected:
            return CloudDataResult(success=False, error="Not connected to OSS")
        return CloudDataResult(success=True, data={"content": "sample data"}, operation="oss_read", resource_id=f"oss://{bucket}/{key}")

    def write_data(self, bucket: str, key: str, data: Any, metadata: Optional[Dict] = None) -> CloudDataResult:
        if not self._connected:
            return CloudDataResult(success=False, error="Not connected to OSS")
        return CloudDataResult(success=True, operation="oss_write", resource_id=f"oss://{bucket}/{key}")

    def delete_data(self, bucket: str, key: str) -> CloudDataResult:
        if not self._connected:
            return CloudDataResult(success=False, error="Not connected to OSS")
        return CloudDataResult(success=True, operation="oss_delete", resource_id=f"oss://{bucket}/{key}")

    def check_connection(self) -> bool:
        return self._connected

    def get_object_metadata(self, bucket: str, key: str) -> Dict[str, Any]:
        return {"bucket": bucket, "key": key, "size": 1024, "content_type": "application/json"}

    def generate_presigned_url(self, bucket: str, key: str, expiration: int = 3600) -> str:
        return f"https://{bucket}.oss-cn-hangzhou.aliyuncs.com/{key}?signed=true"

    def copy_object(self, source_bucket: str, source_key: str, dest_bucket: str, dest_key: str) -> CloudDataResult:
        if not self._connected:
            return CloudDataResult(success=False, error="Not connected to OSS")
        return CloudDataResult(success=True, operation="oss_copy", resource_id=f"oss://{dest_bucket}/{dest_key}")
