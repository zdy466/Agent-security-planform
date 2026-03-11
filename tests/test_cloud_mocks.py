"""Tests for cloud service mocks"""

import unittest

from agentshield.integrations.cloud.base import CloudConfig, CloudProvider
from tests.mocks.cloud_mocks import (
    MockS3Connector,
    MockBlobConnector,
    MockGCSConnector,
    MockOSSConnector,
    MockLambdaConnector,
    MockDynamoDBConnector
)


class TestMockS3Connector(unittest.TestCase):
    def setUp(self):
        self.config = CloudConfig(provider=CloudProvider.AWS, region="us-east-1")
        self.connector = MockS3Connector(self.config)

    def test_connect(self):
        result = self.connector.connect()
        self.assertTrue(result)
        self.assertTrue(self.connector.connected)

    def test_list_buckets(self):
        self.connector.connect()
        buckets = self.connector.list_buckets()
        self.assertEqual(len(buckets), 2)
        self.assertEqual(buckets[0].resource_type, "bucket")

    def test_write_and_read(self):
        self.connector.connect()
        write_result = self.connector.write_data("test-bucket", "test-key", {"message": "hello"})
        self.assertTrue(write_result.success)
        
        read_result = self.connector.read_data("test-bucket", "test-key")
        self.assertTrue(read_result.success)
        self.assertIn("message", read_result.data["data"])

    def test_delete(self):
        self.connector.connect()
        self.connector.write_data("test-bucket", "test-key", {"data": "test"})
        delete_result = self.connector.delete_data("test-bucket", "test-key")
        self.assertTrue(delete_result.success)
        
        read_result = self.connector.read_data("test-bucket", "test-key")
        self.assertFalse(read_result.success)

    def test_presigned_url(self):
        url = self.connector.generate_presigned_url("test-bucket", "test-key")
        self.assertIn("test-bucket", url)
        self.assertIn("s3.amazonaws.com", url)


class TestMockBlobConnector(unittest.TestCase):
    def setUp(self):
        self.config = CloudConfig(provider=CloudProvider.AZURE, region="eastus")
        self.connector = MockBlobConnector(self.config)

    def test_connect(self):
        result = self.connector.connect()
        self.assertTrue(result)

    def test_list_containers(self):
        self.connector.connect()
        containers = self.connector.list_buckets()
        self.assertEqual(len(containers), 2)


class TestMockGCSConnector(unittest.TestCase):
    def setUp(self):
        self.config = CloudConfig(provider=CloudProvider.GCP, region="us-central1")
        self.connector = MockGCSConnector(self.config)

    def test_connect(self):
        result = self.connector.connect()
        self.assertTrue(result)

    def test_list_buckets(self):
        self.connector.connect()
        buckets = self.connector.list_buckets()
        self.assertEqual(len(buckets), 2)


class TestMockOSSConnector(unittest.TestCase):
    def setUp(self):
        self.config = CloudConfig(provider=CloudProvider.ALIYUN, region="cn-hangzhou")
        self.connector = MockOSSConnector(self.config)

    def test_connect(self):
        result = self.connector.connect()
        self.assertTrue(result)


class TestMockLambdaConnector(unittest.TestCase):
    def setUp(self):
        self.config = CloudConfig(provider=CloudProvider.AWS, region="us-east-1")
        self.connector = MockLambdaConnector(self.config)

    def test_invoke_function(self):
        self.connector.connect()
        self.connector.register_function("test-function", {"result": "success"})
        
        result = self.connector.invoke_function("test-function", {"input": "test"})
        self.assertTrue(result.success)
        self.assertIn("result", result.data)

    def test_function_not_found(self):
        self.connector.connect()
        result = self.connector.invoke_function("nonexistent", {})
        self.assertFalse(result.success)


class TestMockDynamoDBConnector(unittest.TestCase):
    def setUp(self):
        self.config = CloudConfig(provider=CloudProvider.AWS, region="us-east-1")
        self.connector = MockDynamoDBConnector(self.config)

    def test_put_and_get_item(self):
        self.connector.connect()
        
        item = {"id": "1", "name": "Test"}
        put_result = self.connector.put_item("test-table", item)
        self.assertTrue(put_result.success)
        
        get_result = self.connector.get_item("test-table", {"id": "1"})
        self.assertTrue(get_result.success)
        self.assertEqual(get_result.data["name"], "Test")

    def test_execute_query(self):
        self.connector.connect()
        result = self.connector.execute_query("SELECT * FROM test")
        self.assertTrue(result.success)


if __name__ == "__main__":
    unittest.main()
