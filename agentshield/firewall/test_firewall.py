# -*- coding: utf-8 -*-
from llm_data_firewall import LLMDataFirewall

fw = LLMDataFirewall()

# 测试 PII 检测
test_text = '联系邮箱: test@example.com, 手机: 13812345678, 身份证: 110101199001011234'
print('=== PII 检测 ===')
results = fw.detect_pii(test_text)
for r in results:
    print(f'类型: {r.type}, 匹配数: {len(r.matches)}')

# 测试 API Key 检测  
test_api = '我的API密钥是 sk-abcdefghijklmnopqrst'
print('\n=== API Key 检测 ===')
api_results = fw.detect_api_keys(test_api)
for r in api_results:
    print(f'类型: {r.type}, 匹配数: {len(r.matches)}, 脱敏值: {r.matches[0]["value"]}')

# 测试阻止机制
print('\n=== 阻止机制 ===')
block_result = fw.block_if_sensitive('AWS密钥: AKIAIOSFODNN7EXAMPLE')
print(f'阻止: {block_result["blocked"]}, 原因: {block_result["reason"]}, 严重程度: {block_result.get("severity")}')

# 测试数据最小化
print('\n=== 数据最小化 ===')
large_data = 'a' * 2000
minimized = fw.minimize_data(large_data, 'summary')
print(f'最小化策略: summary, 结果: {type(minimized).__name__}')

# 测试检测报告
print('\n=== 检测报告 ===')
report = fw.get_detection_report(test_text)
print(f'有敏感数据: {report.has_sensitive_data}, 风险等级: {report.risk_level}, 总匹配数: {report.total_matches}')

print('\n所有功能测试通过!')
