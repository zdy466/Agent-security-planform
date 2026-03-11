"""Tests for ML models"""

import unittest
from unittest.mock import patch, MagicMock


class TestMLAnomalyDetector(unittest.TestCase):
    """Test MLAnomalyDetector with sklearn"""

    def setUp(self):
        self.mock_sklearn()

    def mock_sklearn(self):
        """Mock sklearn to avoid dependency"""
        self.patcher = patch('agentshield.ml.models.anomaly_models.SKLEARN_AVAILABLE', True)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    @patch('agentshield.ml.models.anomaly_models.IsolationForest')
    @patch('agentshield.ml.models.anomaly_models.StandardScaler')
    def test_train(self, mock_scaler, mock_forest):
        from agentshield.ml.models import MLAnomalyDetector

        detector = MLAnomalyDetector(contamination=0.1)
        mock_forest.return_value.fit.return_value = None
        mock_scaler.return_value.fit_transform.return_value = [[1, 2], [3, 4]]

        result = detector.train([[1, 2], [3, 4], [5, 6]])

        self.assertTrue(result["success"])
        self.assertTrue(detector._is_trained)

    def test_predict_without_training(self):
        from agentshield.ml.models import MLAnomalyDetector

        detector = MLAnomalyDetector()

        with self.assertRaises(ValueError):
            detector.predict([[1, 2]])


class TestTextAnomalyClassifier(unittest.TestCase):
    """Test TextAnomalyClassifier"""

    def test_available_check(self):
        from agentshield.ml.models import TextAnomalyClassifier

        classifier = TextAnomalyClassifier()
        self.assertIn(classifier.is_available, [True, False])


class TestBehaviorSequenceModel(unittest.TestCase):
    """Test BehaviorSequenceModel"""

    def test_train(self):
        from agentshield.ml.models import BehaviorSequenceModel

        model = BehaviorSequenceModel()
        sequences = [
            ["login", "view_data", "logout"],
            ["login", "view_data", "export", "logout"],
        ]

        result = model.train(sequences)

        self.assertTrue(result["success"])
        self.assertGreater(result["n_unique_events"], 0)

    def test_predict_next(self):
        from agentshield.ml.models import BehaviorSequenceModel

        model = BehaviorSequenceModel()
        sequences = [
            ["login", "view_data", "logout"],
            ["login", "view_data", "export", "logout"],
        ]
        model.train(sequences)

        predictions = model.predict_next(["login", "view_data"])

        self.assertIsInstance(predictions, list)

    def test_detect_anomaly(self):
        from agentshield.ml.models import BehaviorSequenceModel

        model = BehaviorSequenceModel()
        sequences = [
            ["login", "view_data", "logout"],
        ]
        model.train(sequences)

        score = model.detect_anomaly(["login", "logout"])
        self.assertIsInstance(score, float)


class TestPyTorchModels(unittest.TestCase):
    """Test PyTorch models availability"""

    def test_torch_available_check(self):
        from agentshield.ml.models import PyTorchAnomalyDetector

        detector = PyTorchAnomalyDetector(input_dim=10)
        self.assertIn(detector.is_available, [True, False])


class TestSecurityPentester(unittest.TestCase):
    """Test SecurityPentester"""

    def setUp(self):
        from agentshield.security.pentest import SecurityPentester
        from agentshield import LLMDataFirewall

        self.pentester = SecurityPentester()
        self.firewall = LLMDataFirewall()

    def test_pentester_creation(self):
        from agentshield.security.pentest import SecurityPentester

        pentester = SecurityPentester()
        self.assertIsNotNone(pentester.prompt_tester)
        self.assertIsNotNone(pentester.exfiltration_tester)
        self.assertIsNotNone(pentester.abuse_tester)

    def test_run_prompt_injection_tests(self):
        findings = self.pentester.prompt_tester.run_tests(self.firewall)
        self.assertIsInstance(findings, list)

    def test_run_full_assessment(self):
        report = self.pentester.run_full_assessment(self.firewall)

        self.assertIsNotNone(report.target)
        self.assertIsNotNone(report.summary)
        self.assertIn("total", report.summary)


if __name__ == "__main__":
    unittest.main()
