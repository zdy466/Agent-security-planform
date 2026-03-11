import math
from typing import Dict, List, Any, Optional, Tuple
from collections import deque


class StatisticalAnomalyDetector:
    def __init__(self, method: str = 'zscore', config: Optional[Dict[str, Any]] = None):
        self.method = method
        self.config = config or {}
        self.threshold = self.config.get('threshold', 3.0)
        self.percentile = self.config.get('percentile', 95)
        self.iqr_multiplier = self.config.get('iqr_multiplier', 1.5)
        self.window_size = self.config.get('window_size', 100)

        self._mean: Optional[float] = None
        self._std: Optional[float] = None
        self._median: Optional[float] = None
        self._q1: Optional[float] = None
        self._q3: Optional[float] = None
        self._percentile_value: Optional[float] = None
        self._history: deque = deque(maxlen=self.window_size)
        self._is_trained = False

    def _mean_calc(self, data: List[float]) -> float:
        return sum(data) / len(data) if data else 0.0

    def _std_calc(self, data: List[float]) -> float:
        if len(data) < 2:
            return 1.0
        mean = self._mean_calc(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        return math.sqrt(variance)

    def train(self, data: List[float]) -> None:
        if not data:
            return

        self._history = deque(data[-self.window_size:] if len(data) > self.window_size else data, maxlen=self.window_size)
        self._mean = self._mean_calc(data)
        self._std = self._std_calc(data)

        sorted_data = sorted(data)
        n = len(sorted_data)
        self._median = sorted_data[n // 2] if n % 2 == 1 else (sorted_data[n // 2 - 1] + sorted_data[n // 2]) / 2

        self._q1 = self._percentile_calc(sorted_data, 25)
        self._q3 = self._percentile_calc(sorted_data, 75)

        self._percentile_value = self._percentile_calc(sorted_data, self.percentile)

        self._is_trained = True

    def _percentile_calc(self, sorted_data: List[float], p: float) -> float:
        n = len(sorted_data)
        k = (n - 1) * p / 100
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_data[int(k)]
        d0 = sorted_data[int(f)] * (c - k)
        d1 = sorted_data[int(c)] * (k - f)
        return d0 + d1

    def detect(self, value: float) -> Tuple[bool, float]:
        if not self._is_trained:
            self._history.append(value)
            return False, 0.0

        self._history.append(value)

        if self.method == 'zscore':
            return self._detect_zscore(value)
        elif self.method == 'iqr':
            return self._detect_iqr(value)
        elif self.method == 'percentile':
            return self._detect_percentile(value)
        else:
            return self._detect_zscore(value)

    def _detect_zscore(self, value: float) -> Tuple[bool, float]:
        if self._std == 0:
            zscore = 0.0
        else:
            zscore = abs(value - self._mean) / self._std
        is_anomaly = zscore > self.threshold
        return is_anomaly, zscore

    def _detect_iqr(self, value: float) -> Tuple[bool, float]:
        if self._q1 is None or self._q3 is None:
            return False, 0.0
        iqr = self._q3 - self._q1
        lower_bound = self._q1 - self.iqr_multiplier * iqr
        upper_bound = self._q3 + self.iqr_multiplier * iqr
        is_anomaly = value < lower_bound or value > upper_bound

        if iqr == 0:
            deviation = abs(value - self._median) if self._median else 0.0
        else:
            deviation = abs(value - self._median) / iqr if iqr != 0 else 0.0
        return is_anomaly, deviation

    def _detect_percentile(self, value: float) -> Tuple[bool, float]:
        if self._percentile_value is None:
            return False, 0.0
        is_anomaly = value > self._percentile_value
        if self._percentile_value == 0:
            deviation = value
        else:
            deviation = value / self._percentile_value if self._percentile_value != 0 else 0.0
        return is_anomaly, deviation

    def get_threshold(self) -> float:
        if self.method == 'zscore':
            return self.threshold
        elif self.method == 'iqr':
            if self._q1 is not None and self._q3 is not None:
                iqr = self._q3 - self._q1
                return self._q3 + self.iqr_multiplier * iqr
            return 0.0
        elif self.method == 'percentile':
            return self._percentile_value if self._percentile_value is not None else 0.0
        return self.threshold

    def get_statistics(self) -> Dict[str, float]:
        return {
            'mean': self._mean if self._mean is not None else 0.0,
            'std': self._std if self._std is not None else 0.0,
            'median': self._median if self._median is not None else 0.0,
            'q1': self._q1 if self._q1 is not None else 0.0,
            'q3': self._q3 if self._q3 is not None else 0.0,
            'percentile_value': self._percentile_value if self._percentile_value is not None else 0.0,
            'threshold': self.get_threshold(),
        }

    def detect_batch(self, values: List[float]) -> List[Tuple[bool, float]]:
        self.train(values)
        return [self.detect(v) for v in values]
