import math
from typing import Dict, List, Any, Optional, Tuple
from collections import deque, defaultdict
from datetime import datetime, timedelta


class BehaviorSequenceAnalyzer:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.sequence_window = self.config.get('sequence_window', 50)
        self.min_sequence_length = self.config.get('min_sequence_length', 3)
        self.anomaly_threshold = self.config.get('anomaly_threshold', 0.7)
        self.markov_order = self.config.get('markov_order', 2)

        self._event_sequences: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.sequence_window))
        self._transition_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._event_counts: Dict[str, int] = defaultdict(int)
        self._total_transitions: Dict[str, int] = defaultdict(int)
        self._session_windows: Dict[str, List[datetime]] = defaultdict(list)

    def add_event(self, user_id: str, event: Dict[str, Any]) -> None:
        event_type = event.get('event_type', 'unknown')
        timestamp = event.get('timestamp')
        
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                timestamp = datetime.now()
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now()

        self._event_sequences[user_id].append((event_type, timestamp))
        self._event_counts[event_type] += 1
        self._update_transition_probabilities(user_id, event_type)
        self._session_windows[user_id].append(timestamp)

    def _update_transition_probabilities(self, user_id: str, current_event: str) -> None:
        sequence = list(self._event_sequences[user_id])
        if len(sequence) < 2:
            return

        for i in range(len(sequence) - 1):
            prev_event = sequence[i][0]
            next_event = sequence[i + 1][0]
            self._transition_counts[prev_event][next_event] += 1
            self._total_transitions[prev_event] += 1

    def analyze_sequence(self, user_id: str) -> Dict[str, Any]:
        sequence = list(self._event_sequences[user_id])
        
        if len(sequence) < self.min_sequence_length:
            return {
                'sequence_length': len(sequence),
                'unusual_pattern_score': 0.0,
                'transition_entropy': 0.0,
                'burst_score': 0.0,
                'session_duration': 0.0,
                'event_diversity': 0.0,
                'patterns': [],
            }

        unusual_score = self._calculate_unusual_score(sequence)
        entropy = self._calculate_transition_entropy(sequence)
        burst_score = self._calculate_burst_score(sequence)
        session_duration = self._calculate_session_duration(sequence)
        event_diversity = self._calculate_event_diversity(sequence)
        patterns = self._detect_patterns(sequence)

        return {
            'sequence_length': len(sequence),
            'unusual_pattern_score': unusual_score,
            'transition_entropy': entropy,
            'burst_score': burst_score,
            'session_duration': session_duration,
            'event_diversity': event_diversity,
            'patterns': patterns,
        }

    def _calculate_unusual_score(self, sequence: List[Tuple[str, datetime]]) -> float:
        if len(sequence) < 2:
            return 0.0

        unusual_count = 0
        for i in range(len(sequence) - 1):
            prev_event = sequence[i][0]
            next_event = sequence[i + 1][0]
            
            if prev_event in self._transition_counts:
                transitions = self._transition_counts[prev_event]
                total = self._total_transitions[prev_event]
                if total > 0:
                    prob = transitions.get(next_event, 0) / total
                    if prob < 0.1:
                        unusual_count += 1

        return unusual_count / max(len(sequence) - 1, 1)

    def _calculate_transition_entropy(self, sequence: List[Tuple[str, datetime]]) -> float:
        if len(sequence) < 2:
            return 0.0

        entropies = []
        for i in range(len(sequence) - 1):
            prev_event = sequence[i][0]
            if prev_event in self._transition_counts:
                transitions = self._transition_counts[prev_event]
                total = sum(transitions.values())
                if total > 0:
                    entropy = 0.0
                    for count in transitions.values():
                        p = count / total
                        if p > 0:
                            entropy -= p * math.log2(p)
                    entropies.append(entropy)

        return sum(entropies) / max(len(entropies), 1)

    def _calculate_burst_score(self, sequence: List[Tuple[str, datetime]]) -> float:
        if len(sequence) < 2:
            return 0.0

        event_types = [e[0] for e in sequence]
        max_consecutive = 1
        current_consecutive = 1

        for i in range(1, len(event_types)):
            if event_types[i] == event_types[i - 1]:
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 1

        avg_events_per_second = len(sequence) / max(self._calculate_session_duration(sequence), 1)
        
        burst_score = (max_consecutive / len(sequence)) * math.log1p(avg_events_per_second)
        return min(burst_score, 1.0)

    def _calculate_session_duration(self, sequence: List[Tuple[str, datetime]]) -> float:
        if not sequence:
            return 0.0
        timestamps = [e[1] for e in sequence]
        duration = (max(timestamps) - min(timestamps)).total_seconds()
        return max(duration, 1.0)

    def _calculate_event_diversity(self, sequence: List[Tuple[str, datetime]]) -> float:
        if not sequence:
            return 0.0
        unique_events = len(set(e[0] for e in sequence))
        return unique_events / len(sequence)

    def _detect_patterns(self, sequence: List[Tuple[str, datetime]]) -> List[Dict[str, Any]]:
        patterns = []
        event_types = [e[0] for e in sequence]
        
        repeated = self._find_repeated_subsequences(event_types)
        if repeated:
            patterns.append({
                'type': 'repeated_sequence',
                'count': len(repeated),
                'details': repeated[:5],
            })

        rapid_events = self._find_rapid_events(sequence)
        if rapid_events:
            patterns.append({
                'type': 'rapid_events',
                'count': rapid_events,
            })

        return patterns

    def _find_repeated_subsequences(self, event_types: List[str]) -> List[str]:
        repeated = []
        n = len(event_types)
        
        for length in range(2, min(5, n // 2 + 1)):
            subsequences = defaultdict(list)
            for i in range(n - length + 1):
                seq = tuple(event_types[i:i + length])
                subsequences[seq].append(i)
            
            for seq, positions in subsequences.items():
                if len(positions) >= 2:
                    repeated.append('->'.join(seq))
        
        return repeated[:10]

    def _find_rapid_events(self, sequence: List[Tuple[str, datetime]]) -> int:
        if len(sequence) < 2:
            return 0
        
        rapid_count = 0
        for i in range(len(sequence) - 1):
            time_diff = (sequence[i + 1][1] - sequence[i][1]).total_seconds()
            if 0 < time_diff < 1.0:
                rapid_count += 1
        
        return rapid_count

    def detect_anomaly(self, user_id: str) -> Tuple[bool, float, Dict[str, Any]]:
        analysis = self.analyze_sequence(user_id)
        
        anomaly_score = (
            analysis['unusual_pattern_score'] * 0.3 +
            analysis['burst_score'] * 0.3 +
            (1.0 - analysis['event_diversity']) * 0.2 +
            (1.0 - min(analysis['transition_entropy'] / 4.0, 1.0)) * 0.2
        )
        
        is_anomaly = anomaly_score > self.anomaly_threshold
        
        return is_anomaly, anomaly_score, analysis

    def get_transition_probability(self, from_event: str, to_event: str) -> float:
        if from_event not in self._transition_counts:
            return 0.0
        
        transitions = self._transition_counts[from_event]
        total = self._total_transitions[from_event]
        
        if total == 0:
            return 0.0
        
        return transitions.get(to_event, 0) / total

    def reset_user(self, user_id: str) -> None:
        if user_id in self._event_sequences:
            self._event_sequences[user_id].clear()
        if user_id in self._session_windows:
            self._session_windows[user_id].clear()
