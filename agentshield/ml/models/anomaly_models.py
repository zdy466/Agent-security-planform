"""ML-based anomaly detection using scikit-learn"""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from agentshield.ml.features import FeatureExtractor


class MLAnomalyDetector:
    """Machine Learning based anomaly detector using Isolation Forest"""

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self._model = None
        self._scaler = StandardScaler()
        self._is_trained = False
        self._feature_names: List[str] = []

    @property
    def is_available(self) -> bool:
        return SKLEARN_AVAILABLE

    def train(
        self,
        X: List[List[float]],
        y: Optional[List[int]] = None,
        feature_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Train the anomaly detection model"""
        if not SKLEARN_AVAILABLE:
            return {
                "success": False,
                "error": "scikit-learn not installed. Install with: pip install scikit-learn"
            }

        try:
            X_array = np.array(X)
            if len(X_array.shape) == 1:
                X_array = X_array.reshape(-1, 1)

            X_scaled = self._scaler.fit_transform(X_array)

            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=self.random_state,
                n_jobs=-1
            )
            self._model.fit(X_scaled)

            if feature_names:
                self._feature_names = feature_names
            else:
                self._feature_names = [f"feature_{i}" for i in range(X_array.shape[1])]

            self._is_trained = True

            return {
                "success": True,
                "message": "Model trained successfully",
                "n_samples": X_array.shape[0],
                "n_features": X_array.shape[1]
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def predict(self, X: List[List[float]]) -> List[int]:
        """Predict anomalies (-1 for anomaly, 1 for normal)"""
        if not self._is_trained or self._model is None:
            raise ValueError("Model not trained yet")

        X_array = np.array(X)
        if len(X_array.shape) == 1:
            X_array = X_array.reshape(-1, 1)

        X_scaled = self._scaler.transform(X_array)
        return self._model.predict(X_scaled).tolist()

    def predict_proba(self, X: List[List[float]]) -> List[Dict[str, float]]:
        """Predict anomaly probability"""
        if not self._is_trained or self._model is None:
            raise ValueError("Model not trained yet")

        X_array = np.array(X)
        if len(X_array.shape) == 1:
            X_array = X_array.reshape(-1, 1)

        X_scaled = self._scaler.transform(X_array)
        scores = self._model.score_samples(X_scaled)

        results = []
        for score in scores:
            anomaly_score = -score
            normal_score = score
            results.append({
                "anomaly_score": float(anomaly_score),
                "normal_score": float(normal_score),
                "is_anomaly": bool(anomaly_score > 0.5)
            })

        return results

    def evaluate(
        self,
        X_test: List[List[float]],
        y_test: List[int]
    ) -> Dict[str, Any]:
        """Evaluate model performance"""
        predictions = self.predict(X_test)

        y_true = np.array(y_test)
        y_pred = np.array(predictions)

        y_true_binary = (y_true == -1).astype(int)
        y_pred_binary = (y_pred == -1).astype(int)

        return {
            "confusion_matrix": confusion_matrix(y_true_binary, y_pred_binary).tolist(),
            "classification_report": classification_report(
                y_true_binary, y_pred_binary, output_dict=True
            ),
            "accuracy": float(np.mean(y_true_binary == y_pred_binary))
        }

    def save_model(self, path: str) -> bool:
        """Save model to disk"""
        import pickle
        try:
            model_data = {
                "model": self._model,
                "scaler": self._scaler,
                "feature_names": self._feature_names,
                "contamination": self.contamination,
                "n_estimators": self.n_estimators
            }
            with open(path, "wb") as f:
                pickle.dump(model_data, f)
            return True
        except Exception:
            return False

    def load_model(self, path: str) -> bool:
        """Load model from disk"""
        import pickle
        try:
            with open(path, "rb") as f:
                model_data = pickle.load(f)

            self._model = model_data["model"]
            self._scaler = model_data["scaler"]
            self._feature_names = model_data["feature_names"]
            self.contamination = model_data["contamination"]
            self.n_estimators = model_data["n_estimators"]
            self._is_trained = True

            return True
        except Exception:
            return False


class TextAnomalyClassifier:
    """Text-based anomaly classifier using sklearn"""

    def __init__(
        self,
        max_features: int = 1000,
        n_estimators: int = 100
    ):
        self.max_features = max_features
        self.n_estimators = n_estimators
        self._vectorizer = None
        self._classifier = None
        self._label_encoder = LabelEncoder()
        self._is_trained = False
        self._classes: List[str] = []

    @property
    def is_available(self) -> bool:
        return SKLEARN_AVAILABLE

    def train(
        self,
        texts: List[str],
        labels: List[str]
    ) -> Dict[str, Any]:
        """Train text classifier"""
        if not SKLEARN_AVAILABLE:
            return {
                "success": False,
                "error": "scikit-learn not installed"
            }

        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.ensemble import RandomForestClassifier

            self._vectorizer = TfidfVectorizer(
                max_features=self.max_features,
                ngram_range=(1, 2)
            )

            X = self._vectorizer.fit_transform(texts)
            y = self._label_encoder.fit_transform(labels)
            self._classes = self._label_encoder.classes_.tolist()

            self._classifier = RandomForestClassifier(
                n_estimators=self.n_estimators,
                random_state=42,
                n_jobs=-1
            )
            self._classifier.fit(X, y)

            self._is_trained = True

            return {
                "success": True,
                "message": "Text classifier trained",
                "n_samples": len(texts),
                "n_classes": len(self._classes),
                "classes": self._classes
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def predict(self, texts: List[str]) -> List[str]:
        """Predict text labels"""
        if not self._is_trained:
            raise ValueError("Model not trained yet")

        X = self._vectorizer.transform(texts)
        predictions = self._classifier.predict(X)

        return self._label_encoder.inverse_transform(predictions).tolist()

    def predict_proba(self, texts: List[str]) -> List[Dict[str, float]]:
        """Predict label probabilities"""
        if not self._is_trained:
            raise ValueError("Model not trained yet")

        X = self._vectorizer.transform(texts)
        probas = self._classifier.predict_proba(X)

        results = []
        for proba in probas:
            result = {
                self._classes[i]: float(p)
                for i, p in enumerate(proba)
            }
            results.append(result)

        return results


class BehaviorSequenceModel:
    """Sequence-based behavior analysis model"""

    def __init__(
        self,
        window_size: int = 10,
        threshold: float = 0.7
    ):
        self.window_size = window_size
        self.threshold = threshold
        self._transition_matrix: Dict[str, Dict[str, float]] = {}
        self._event_counts: Dict[str, int] = {}
        self._is_trained = False

    def train(self, sequences: List[List[str]]) -> Dict[str, Any]:
        """Train behavior sequence model"""
        try:
            self._transition_matrix = {}
            self._event_counts = {}

            for seq in sequences:
                for i in range(len(seq) - 1):
                    current = seq[i]
                    next_event = seq[i + 1]

                    self._event_counts[current] = self._event_counts.get(current, 0) + 1

                    if current not in self._transition_matrix:
                        self._transition_matrix[current] = {}

                    self._transition_matrix[current][next_event] = \
                        self._transition_matrix[current].get(next_event, 0) + 1

            for current in self._transition_matrix:
                total = sum(self._transition_matrix[current].values())
                for next_event in self._transition_matrix[current]:
                    self._transition_matrix[current][next_event] /= total

            self._is_trained = True

            return {
                "success": True,
                "n_sequences": len(sequences),
                "n_unique_events": len(self._event_counts)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def predict_next(self, events: List[str]) -> List[Tuple[str, float]]:
        """Predict next events and probabilities"""
        if not self._is_trained:
            raise ValueError("Model not trained yet")

        if not events:
            return []

        last_event = events[-1]

        if last_event not in self._transition_matrix:
            return []

        predictions = self._transition_matrix[last_event]
        sorted_preds = sorted(
            predictions.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [(event, prob) for event, prob in sorted_preds[:3]]

    def detect_anomaly(self, sequence: List[str]) -> float:
        """Detect if sequence is anomalous"""
        if not self._is_trained or len(sequence) < 2:
            return 0.0

        anomaly_score = 0.0
        count = 0

        for i in range(len(sequence) - 1):
            current = sequence[i]
            next_event = sequence[i + 1]

            if current in self._transition_matrix:
                if next_event in self._transition_matrix[current]:
                    prob = self._transition_matrix[current][next_event]
                    anomaly_score += (1 - prob)
                else:
                    anomaly_score += 1.0

                count += 1

        if count == 0:
            return 0.0

        return anomaly_score / count
