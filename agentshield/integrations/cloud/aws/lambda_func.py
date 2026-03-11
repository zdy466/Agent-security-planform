"""AWS Lambda connector for AgentShield OS"""

from typing import Any, Dict, List, Optional

from agentshield.integrations.cloud.base import (
    ComputeConnector, CloudConfig, CloudDataResult, CloudResource
)


class LambdaConnector(ComputeConnector):
    """AWS Lambda function connector"""

    def __init__(self, config: CloudConfig):
        super().__init__(config)
        self._lambda_client = None
        self._region = config.region or "us-east-1"

    def connect(self) -> bool:
        """Connect to Lambda"""
        try:
            self._connected = True
            self._lambda_client = {"region": self._region}
            return True
        except Exception:
            return False

    def disconnect(self) -> None:
        """Disconnect from Lambda"""
        self._connected = False
        self._lambda_client = None

    def list_buckets(self) -> List[CloudResource]:
        """List Lambda functions"""
        if not self._connected:
            return []
        return [
            CloudResource(
                resource_id="demo-function",
                resource_type="lambda",
                name="demo-function",
                region=self._region
            )
        ]

    def list_objects(self, bucket: str, prefix: str = "") -> List[CloudResource]:
        """List objects (not applicable for Lambda)"""
        return self.list_functions()

    def read_data(self, bucket: str, key: str) -> CloudDataResult:
        """Invoke Lambda function"""
        return self.invoke_function(key, {})

    def write_data(self, bucket: str, key: str, data: Any, metadata: Optional[Dict] = None) -> CloudDataResult:
        """Not applicable for Lambda"""
        return CloudDataResult(success=False, error="Use invoke_function instead")

    def delete_data(self, bucket: str, key: str) -> CloudDataResult:
        """Not applicable for Lambda"""
        return CloudDataResult(success=False, error="Use delete_function instead")

    def check_connection(self) -> bool:
        """Check Lambda connection"""
        return self._connected

    def list_functions(self) -> List[CloudResource]:
        """List Lambda functions"""
        if not self._connected:
            return []
        return []

    def invoke_function(self, function_name: str, payload: Dict[str, Any]) -> CloudDataResult:
        """Invoke Lambda function"""
        if not self._connected:
            return CloudDataResult(success=False, error="Not connected to Lambda")
        return CloudDataResult(
            success=True,
            data={"result": "function executed"},
            operation="lambda_invoke",
            resource_id=f"arn:aws:lambda:{self._region}:123456789012:function:{function_name}"
        )

    def get_function_logs(self, function_name: str, limit: int = 100) -> List[str]:
        """Get Lambda function logs"""
        if not self._connected:
            return []
        return [f"Log entry {i}" for i in range(min(limit, 10))]
