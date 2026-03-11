from typing import Dict, List, Any, Optional, Tuple


class RiskScorer:
    RISK_LEVELS = {
        (0, 20): 'low',
        (20, 40): 'low_medium',
        (40, 60): 'medium',
        (60, 80): 'medium_high',
        (80, 100): 'high',
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.feature_weights = self.config.get('feature_weights', {
            'prompt_injection_score': 0.20,
            'dangerous_action_score': 0.20,
            'event_frequency_score': 0.15,
            'unusual_pattern_score': 0.15,
            'burst_score': 0.10,
            'anomaly_score': 0.10,
            'text_suspicion_score': 0.10,
        })
        self.custom_rules = self.config.get('custom_rules', [])

    def calculate_score(self, features: Dict[str, float], analysis: Dict[str, Any], anomaly_result: Tuple[bool, float, Dict[str, Any]]) -> float:
        is_anomaly, anomaly_score, _ = anomaly_result

        prompt_injection = features.get('prompt_injection_score', 0.0) * 100
        event_frequency = min(features.get('event_frequency_per_hour', 0) * 10, 100)
        unusual_pattern = analysis.get('unusual_pattern_score', 0.0) * 100
        burst_score = analysis.get('burst_score', 0.0) * 100

        text_suspicion = self._calculate_text_suspicion(features)

        total_score = 0.0
        total_weight = 0.0

        score_components = {
            'prompt_injection_score': prompt_injection,
            'dangerous_action_score': features.get('dangerous_action_score', 0.0) * 100,
            'event_frequency_score': event_frequency,
            'unusual_pattern_score': unusual_pattern,
            'burst_score': burst_score,
            'anomaly_score': anomaly_score * 100 if is_anomaly else anomaly_score * 30,
            'text_suspicion_score': text_suspicion,
        }

        for feature_name, weight in self.feature_weights.items():
            score = score_components.get(feature_name, 0.0)
            total_score += score * weight
            total_weight += weight

        if total_weight > 0:
            final_score = total_score / total_weight
        else:
            final_score = 0.0

        if is_anomaly:
            final_score = min(final_score * 1.2, 100.0)

        for rule in self.custom_rules:
            final_score = self._apply_custom_rule(final_score, features, analysis, rule)

        return min(max(final_score, 0.0), 100.0)

    def _calculate_text_suspicion(self, features: Dict[str, float]) -> float:
        suspicion = 0.0

        if features.get('special_char_ratio', 0) > 0.3:
            suspicion += 20

        if features.get('uppercase_ratio', 0) > 0.5:
            suspicion += 15

        if features.get('ip_mention_count', 0) > 0:
            suspicion += 25

        if features.get('url_mention_count', 0) > 0:
            suspicion += 20

        if features.get('command_mention_count', 0) > 0:
            suspicion += 30

        if features.get('email_mention_count', 0) > 0:
            suspicion += 10

        if features.get('dangerous_action_score', 0) > 0:
            suspicion += 40

        return min(suspicion, 100.0)

    def _apply_custom_rule(self, score: float, features: Dict[str, Any], analysis: Dict[str, Any], rule: Dict[str, Any]) -> float:
        rule_type = rule.get('type', '')
        threshold = rule.get('threshold', 0)
        modifier = rule.get('modifier', 1.0)
        condition = rule.get('condition', 'above')

        value = features.get(rule_type, analysis.get(rule_type, 0))

        if condition == 'above' and value > threshold:
            return score * modifier
        elif condition == 'below' and value < threshold:
            return score * modifier
        elif condition == 'equals' and value == threshold:
            return score * modifier

        return score

    def get_risk_level(self, score: float) -> str:
        for (low, high), level in self.RISK_LEVELS.items():
            if low <= score < high:
                return level
        return 'high' if score >= 80 else 'low'

    def get_recommendations(self, score: float, features: Dict[str, float], analysis: Dict[str, Any]) -> List[str]:
        recommendations = []
        risk_level = self.get_risk_level(score)

        if risk_level in ['medium_high', 'high']:
            recommendations.append('立即审查此请求，可能存在安全风险')
        
        if features.get('prompt_injection_score', 0) > 0.3:
            recommendations.append('检测到提示注入风险，建议拒绝或重写提示词')
        
        if features.get('dangerous_action_score', 0) > 0.1:
            recommendations.append('检测到危险操作风险，请验证操作合法性')
        
        if features.get('command_mention_count', 0) > 0:
            recommendations.append('检测到命令执行请求，验证操作合法性')
        
        if features.get('ip_mention_count', 0) > 0:
            recommendations.append('检测到IP地址，可能存在敏感信息泄露')
        
        if features.get('url_mention_count', 0) > 0:
            recommendations.append('检测到URL链接，验证链接安全性')
        
        if analysis.get('burst_score', 0) > 0.5:
            recommendations.append('检测到异常快速的连续请求，检查是否为自动化攻击')
        
        if analysis.get('unusual_pattern_score', 0) > 0.5:
            recommendations.append('检测到异常行为模式，需要人工审核')
        
        if features.get('event_frequency_per_hour', 0) > 50:
            recommendations.append('请求频率异常高，考虑限流或验证码')
        
        if risk_level == 'low' and not recommendations:
            recommendations.append('风险较低，可正常处理')

        return recommendations

    def get_risk_details(self, score: float, features: Dict[str, float], analysis: Dict[str, Any], anomaly_result: Tuple[bool, float, Dict[str, Any]]) -> Dict[str, Any]:
        is_anomaly, anomaly_score, _ = anomaly_result

        score_breakdown = {
            'prompt_injection': features.get('prompt_injection_score', 0) * 100,
            'dangerous_action': features.get('dangerous_action_score', 0) * 100,
            'event_frequency': min(features.get('event_frequency_per_hour', 0) * 10, 100),
            'unusual_pattern': analysis.get('unusual_pattern_score', 0) * 100,
            'burst_score': analysis.get('burst_score', 0) * 100,
            'anomaly': anomaly_score * 100 if is_anomaly else anomaly_score * 30,
            'text_suspicion': self._calculate_text_suspicion(features),
        }

        return {
            'score': score,
            'risk_level': self.get_risk_level(score),
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'score_breakdown': score_breakdown,
            'recommendations': self.get_recommendations(score, features, analysis),
        }
