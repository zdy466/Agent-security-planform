import math
import hashlib
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import Counter


class FeatureExtractor:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._feature_names: List[str] = []
        self._text_patterns = {
            'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'url': r'https?://[^\s]+',
            'command': r'(?:bash|sh|cmd|powershell|python|perl|ruby|rw|nc|curl|wget)\b',
            'dangerous_action': r'\b(?:rm\s+-rf|del\s+\/|format|shutdown|reboot|kill\s+-9|chmod\s+777|chown)\b',
        }
        self._init_feature_names()

    def _init_feature_names(self):
        self._feature_names = [
            'hour_of_day',
            'day_of_week',
            'is_weekend',
            'is_business_hours',
            'event_frequency_per_minute',
            'event_frequency_per_hour',
            'unique_events_count',
            'event_diversity',
            'repeated_event_ratio',
            'text_length',
            'special_char_ratio',
            'uppercase_ratio',
            'digit_ratio',
            'ip_mention_count',
            'email_mention_count',
            'url_mention_count',
            'command_mention_count',
            'prompt_injection_score',
            'dangerous_action_score',
            'sequence_length',
            'token_count',
        ]

    def get_feature_names(self) -> List[str]:
        return self._feature_names.copy()

    def extract_from_event(self, event: Dict[str, Any]) -> Dict[str, float]:
        features = {}
        features.update(self._extract_temporal_features(event))
        features.update(self._extract_frequency_features(event))
        features.update(self._extract_sequence_features(event))
        features.update(self._extract_text_features(event))
        return features

    def extract_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, float]]:
        return [self.extract_from_event(event) for event in events]

    def _extract_temporal_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        features = {}
        timestamp = event.get('timestamp')
        if isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                dt = datetime.now()
        elif isinstance(timestamp, datetime):
            dt = timestamp
        else:
            dt = datetime.now()

        features['hour_of_day'] = float(dt.hour)
        features['day_of_week'] = float(dt.weekday())
        features['is_weekend'] = 1.0 if dt.weekday() >= 5 else 0.0
        features['is_business_hours'] = 1.0 if 9 <= dt.hour <= 17 else 0.0

        return features

    def _extract_frequency_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        features = {}
        event_history = event.get('_event_history', [])

        if event_history:
            recent_events = event_history[-60:]
            recent_hour_events = event_history[-3600:] if len(event_history) >= 3600 else event_history

            features['event_frequency_per_minute'] = len(recent_events) / max(len(recent_events), 1)
            features['event_frequency_per_hour'] = len(recent_hour_events) / max(len(recent_hour_events), 1)

            event_types = [e.get('event_type', 'unknown') for e in event_history]
            type_counter = Counter(event_types)
            features['unique_events_count'] = float(len(type_counter))
            features['event_diversity'] = float(len(type_counter)) / max(len(event_history), 1)

            repeated = sum(1 for count in type_counter.values() if count > 1)
            features['repeated_event_ratio'] = repeated / max(len(type_counter), 1)
        else:
            features['event_frequency_per_minute'] = 0.0
            features['event_frequency_per_hour'] = 0.0
            features['unique_events_count'] = 1.0
            features['event_diversity'] = 1.0
            features['repeated_event_ratio'] = 0.0

        return features

    def _extract_sequence_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        features = {}
        event_history = event.get('_event_history', [])
        features['sequence_length'] = float(len(event_history))

        prompt = event.get('prompt', '') or event.get('message', '') or ''
        tokens = self._simple_tokenize(prompt)
        features['token_count'] = float(len(tokens))

        return features

    def _extract_text_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        features = {}
        text = event.get('prompt', '') or event.get('message', '') or ''

        if not text:
            return {
                'text_length': 0.0,
                'special_char_ratio': 0.0,
                'uppercase_ratio': 0.0,
                'digit_ratio': 0.0,
                'ip_mention_count': 0.0,
                'email_mention_count': 0.0,
                'url_mention_count': 0.0,
                'command_mention_count': 0.0,
                'prompt_injection_score': 0.0,
            }

        features['text_length'] = float(len(text))

        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        features['special_char_ratio'] = special_chars / max(len(text), 1)

        uppercase = sum(1 for c in text if c.isupper())
        features['uppercase_ratio'] = uppercase / max(len(text), 1)

        digits = sum(1 for c in text if c.isdigit())
        features['digit_ratio'] = digits / max(len(text), 1)

        features['ip_mention_count'] = float(len(re.findall(self._text_patterns['ip'], text)))
        features['email_mention_count'] = float(len(re.findall(self._text_patterns['email'], text)))
        features['url_mention_count'] = float(len(re.findall(self._text_patterns['url'], text)))
        features['command_mention_count'] = float(len(re.findall(self._text_patterns['command'], text, re.IGNORECASE)))
        
        features['prompt_injection_score'] = self._calculate_injection_score(text)
        features['dangerous_action_score'] = self._calculate_dangerous_action_score(text)

        return features

    def _calculate_injection_score(self, text: str) -> float:
        injection_patterns = [
            r'ignore\s+(?:previous|all|above)\s+(?:instructions?|commands?|rules?)',
            r'(?:system|prompt)\s*:\s*',
            r'<\/?(?:system|prompt|instruct)',
            r'you\s+are\s+(?:now\s+)?(?:a|an)\s+(?:different|new|alternative)',
            r'forget\s+(?:everything|all|your)',
            r'define\s+(?:the\s+)?(?:new|following)\s+rules?',
            r'skip\s+(?:the\s+)?(?:above|previous)',
            r'as\s+(?:an?|the)\s+(?:AI|assistant|model)',
            r'(?:pretend|imagine)\s+(?:you|that\s+you)',
        ]

        score = 0.0
        text_lower = text.lower()
        for pattern in injection_patterns:
            if re.search(pattern, text_lower):
                score += 1.0

        return min(score / len(injection_patterns), 1.0)

    def _calculate_dangerous_action_score(self, text: str) -> float:
        dangerous_patterns = [
            r'rm\s+-rf',
            r'del\s+[A-Za-z]:\\',
            r'format\s+',
            r'shutdown',
            r'reboot',
            r'kill\s+-9',
            r'chmod\s+777',
            r'chown\s+',
            r'drop\s+table',
            r'delete\s+from',
            r'truncate\s+',
            r'--',
            r'exec\s+',
            r'system\s*\(',
        ]
        
        score = 0.0
        text_lower = text.lower()
        for pattern in dangerous_patterns:
            if re.search(pattern, text_lower):
                score += 1.0
        
        return min(score / len(dangerous_patterns), 1.0)

    def _simple_tokenize(self, text: str) -> List[str]:
        return re.findall(r'\b\w+\b', text.lower())
