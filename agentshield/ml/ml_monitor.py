from typing import Any, Dict, List, Optional
from datetime import datetime

from .features import FeatureExtractor
from .anomaly_detector import StatisticalAnomalyDetector
from .behavior_analyzer import BehaviorSequenceAnalyzer
from .risk_scorer import RiskScorer


class MLMonitor:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.feature_extractor = FeatureExtractor(self.config.get('feature_extractor', {}))
        
        anomaly_config = self.config.get('anomaly_detector', {})
        self.anomaly_detector = StatisticalAnomalyDetector(
            method=anomaly_config.get('method', 'zscore'),
            config=anomaly_config
        )
        
        behavior_config = self.config.get('behavior_analyzer', {})
        self.behavior_analyzer = BehaviorSequenceAnalyzer(behavior_config)
        
        risk_config = self.config.get('risk_scorer', {})
        self.risk_scorer = RiskScorer(risk_config)
        
        self._user_event_history: Dict[str, List[Dict[str, Any]]] = {}
        self._feature_history: Dict[str, List[float]] = {}
        self._is_trained = False

    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        user_id = event.get('user_id', event.get('session_id', 'default'))
        
        self._add_to_history(user_id, event)
        event['_event_history'] = self._user_event_history.get(user_id, [])[-50:]
        
        features = self.feature_extractor.extract_from_event(event)
        
        self.behavior_analyzer.add_event(user_id, event)
        behavior_analysis = self.behavior_analyzer.analyze_sequence(user_id)
        
        feature_values = list(features.values())
        if feature_values:
            self._feature_history.setdefault(user_id, []).extend(feature_values)
            if len(self._feature_history[user_id]) > 1000:
                self._feature_history[user_id] = self._feature_history[user_id][-1000:]
        
        anomaly_result = self._detect_anomaly(features, user_id)
        
        risk_score = self.risk_scorer.calculate_score(features, behavior_analysis, anomaly_result)
        
        risk_details = self.risk_scorer.get_risk_details(risk_score, features, behavior_analysis, anomaly_result)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'features': features,
            'behavior_analysis': behavior_analysis,
            'anomaly_detected': anomaly_result[0],
            'anomaly_score': anomaly_result[1],
            'risk_score': risk_score,
            'risk_level': risk_details['risk_level'],
            'recommendations': risk_details['recommendations'],
            'details': risk_details,
        }

    def _add_to_history(self, user_id: str, event: Dict[str, Any]) -> None:
        if user_id not in self._user_event_history:
            self._user_event_history[user_id] = []
        
        event_copy = event.copy()
        if 'timestamp' not in event_copy:
            event_copy['timestamp'] = datetime.now().isoformat()
        
        self._user_event_history[user_id].append(event_copy)
        
        if len(self._user_event_history[user_id]) > 1000:
            self._user_event_history[user_id] = self._user_event_history[user_id][-1000:]

    def _detect_anomaly(self, features: Dict[str, float], user_id: str) -> tuple:
        feature_values = list(features.values())
        
        if not self._is_trained and len(self._feature_history.get(user_id, [])) >= 30:
            history = self._feature_history.get(user_id, [])
            self.anomaly_detector.train(history[-100:])
            self._is_trained = True
        
        composite_score = self._calculate_composite_score(features)
        
        is_anomaly, anomaly_score = self.anomaly_detector.detect(composite_score)
        
        return is_anomaly, anomaly_score, {}

    def _calculate_composite_score(self, features: Dict[str, float]) -> float:
        weights = {
            'prompt_injection_score': 0.4,
            'event_frequency_per_minute': 0.2,
            'event_frequency_per_hour': 0.1,
            'repeated_event_ratio': 0.15,
            'special_char_ratio': 0.15,
        }
        
        score = 0.0
        total_weight = 0.0
        
        for feature, weight in weights.items():
            value = features.get(feature, 0.0)
            score += value * weight
            total_weight += weight
        
        return score / total_weight if total_weight > 0 else 0.0

    def train_on_history(self, user_id: str) -> None:
        history = self._feature_history.get(user_id, [])
        if len(history) >= 30:
            self.anomaly_detector.train(history)
            self._is_trained = True

    def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        events = self._user_event_history.get(user_id, [])
        features = self._feature_history.get(user_id, [])
        
        if not events:
            return {
                'user_id': user_id,
                'event_count': 0,
                'is_trained': self._is_trained,
                'average_risk_score': 0.0,
            }
        
        behavior_analysis = self.behavior_analyzer.analyze_sequence(user_id)
        is_anomaly, anomaly_score, _ = self.behavior_analyzer.detect_anomaly(user_id)
        
        detector_stats = self.anomaly_detector.get_statistics() if self._is_trained else {}
        
        return {
            'user_id': user_id,
            'event_count': len(events),
            'is_trained': self._is_trained,
            'behavior_analysis': behavior_analysis,
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'feature_count': len(features),
            'detector_stats': detector_stats,
        }

    def reset_user(self, user_id: str) -> None:
        if user_id in self._user_event_history:
            self._user_event_history[user_id].clear()
        if user_id in self._feature_history:
            self._feature_history[user_id].clear()
        self.behavior_analyzer.reset_user(user_id)

    def get_system_status(self) -> Dict[str, Any]:
        return {
            'is_trained': self._is_trained,
            'active_users': len(self._user_event_history),
            'total_events': sum(len(events) for events in self._user_event_history.values()),
            'feature_extractor_features': self.feature_extractor.get_feature_names(),
            'anomaly_detector_method': self.anomaly_detector.method,
            'anomaly_threshold': self.anomaly_detector.get_threshold(),
        }

    def batch_analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        for event in events:
            result = self.analyze_event(event)
            results.append(result)
        return results
