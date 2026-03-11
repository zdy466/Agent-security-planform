"""GCP Cloud Functions connector for AgentShield OS"""

from typing import Any, Dict, List, Optional

from agentshield.integrations.cloud.base import ComputeConnector, CloudConfig, CloudDataResult, CloudResource


class CloudFunctionsConnector(ComputeConnector):
    """Google Cloud Functions connector"""

    def __init__(self, config: CloudConfig):
        super().__init__(config)
        self._func_client = None
        self._region = config.region or "us-central1"

    def connect(self) -> bool:
        try:
            self._connected = True
            self._func_client = {"region": self._region}
            return True
        except Exception:
            return False

    def disconnect(self) -> None:
        self._connected = False
        self._func_client = None

    def list_buckets(self) -> List[CloudResource]:
        if not self._connected:
            return []
        return [CloudResource(resource_id="demo-function", resource_type="cloud_function", name="demo-function", region=self._region)]

    def list_objects(self, bucket: str, prefix: str = "") -> List[CloudResource]:
        return self.list_functions()

    def read_data(self, bucket: str, key: str) -> CloudDataResult:
        return self.invoke_function(key, {})

    def write_data(self, bucket: str, key: str, data: Any, metadata: Optional[Dict] = None) -> CloudDataResult:
        return CloudDataResult(success=False, error="Use invoke_function instead")

    def delete_data(self, bucket: str, key: str) -> CloudDataResult:
        return CloudDataResult(success=False, error="Use delete_function instead")

    def check_connection(self) -> bool:
        return self._connected

    def list_functions(self) -> List[CloudResource]:
        if not self._connected:
            return []
        return []

    def invoke_function(self, function_name: str, payload: Dict[str, Any]) -> CloudDataResult:
        if not self._connected:
            return CloudDataResult(success=False, error="Not connected to Cloud Functions")
        return CloudDataResult(success=True, data={"result": "function executed"}, operation="function_invoke", resource_id=f"gcf://{self._region}/{function_name}")

    def get_function_logs(self, function_name: str, limit: int = 100) -> List[str]:
        if not self._connected:
            return []
        return [f"Log entry {i}" for i in range(min(limit, 10))]
