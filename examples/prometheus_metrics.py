"""
AgentShield Prometheus 监控示例

本示例展示如何使用 MetricsCollector、SecurityMetrics 进行指标收集，
以及如何导出 Prometheus 格式的指标和配置健康检查端点。
"""

import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
sys.path.insert(0, 'd:\\security')

from agentshield.monitoring.metrics import (
    MetricsCollector,
    SecurityMetrics,
    MetricsExporter,
    Timer
)
from agentshield.monitoring.metrics.health import HealthServer


def main():
    print("=" * 60)
    print("AgentShield Prometheus 监控示例")
    print("=" * 60)

    print("\n" + "=" * 60)
    print("1. MetricsCollector 基础使用")
    print("=" * 60)

    print("\n创建 MetricsCollector...")
    collector = MetricsCollector()

    collector.counter("requests_total", 1)
    collector.counter("requests_total", 1, {"method": "GET"})
    collector.counter("requests_total", 1, {"method": "POST"})
    collector.counter("errors_total", 1, {"type": "timeout"})

    collector.gauge("active_connections", 42)
    collector.gauge("memory_usage_bytes", 1024 * 1024 * 256)
    collector.gauge("cpu_usage_percent", 75.5)

    collector.histogram("request_duration_seconds", 0.1)
    collector.histogram("request_duration_seconds", 0.25)
    collector.histogram("request_duration_seconds", 0.5)
    collector.histogram("request_duration_seconds", 1.0)
    collector.histogram("request_duration_seconds", 2.5)

    print("   计数器: requests_total, errors_total")
    print("   仪表: active_connections, memory_usage_bytes, cpu_usage_percent")
    print("   直方图: request_duration_seconds")

    metrics = collector.get_metrics()
    print(f"\n收集到的指标数量: {len(metrics)}")
    for metric in metrics:
        print(f"   - {metric.name}: {metric.value}")

    print("\n" + "=" * 60)
    print("2. SecurityMetrics 安全指标")
    print("=" * 60)

    print("\n创建 SecurityMetrics...")
    security_metrics = SecurityMetrics(collector)

    print("\n记录请求指标:")
    security_metrics.record_request(allowed=True, latency=0.15)
    security_metrics.record_request(allowed=True, latency=0.25)
    security_metrics.record_request(allowed=False, latency=0.05)

    print("   - 记录3个请求 (2个允许, 1个阻止)")

    print("\n记录阻止事件:")
    security_metrics.record_blocked("sensitive_data_detected")
    security_metrics.record_blocked("prompt_injection")
    security_metrics.record_blocked("sensitive_data_detected")

    print("   - 记录3个阻止事件")

    print("\n记录敏感数据检测:")
    security_metrics.record_sensitive_data(["email", "phone"])
    security_metrics.record_sensitive_data(["api_key", "password"])

    print("   - 记录2次敏感数据检测")

    print("\n记录提示注入检测:")
    security_metrics.record_prompt_injection(detected=False, risk_level="low")
    security_metrics.record_prompt_injection(detected=True, risk_level="high")
    security_metrics.record_prompt_injection(detected=True, risk_level="critical")

    print("   - 记录3次提示注入检测")

    print("\n记录工具执行:")
    security_metrics.record_tool_execution("read_file", allowed=True)
    security_metrics.record_tool_execution("write_file", allowed=True)
    security_metrics.record_tool_execution("delete_file", allowed=False)

    print("   - 记录3次工具执行")

    print("\n记录策略违规:")
    security_metrics.record_policy_violation("rate_limit_exceeded")
    security_metrics.record_policy_violation("invalid_api_key")

    print("   - 记录2次策略违规")

    print("\n记录合规检查:")
    security_metrics.record_compliance_check("SOC2", passed=True)
    security_metrics.record_compliance_check("SOC2", passed=True)
    security_metrics.record_compliance_check("GDPR", passed=False)
    security_metrics.record_compliance_check("HIPAA", passed=True)

    print("   - 记录4次合规检查")

    print("\n设置会话和安全评分:")
    security_metrics.set_active_sessions(15)
    security_metrics.set_security_score(0.92)

    print("   - 活跃会话: 15")
    print("   - 安全评分: 0.92")

    print("\n" + "=" * 60)
    print("3. Prometheus 格式导出")
    print("=" * 60)

    print("\n使用 MetricsExporter 导出...")
    exporter = MetricsExporter(collector)

    print("\nPrometheus 格式输出:")
    print("-" * 40)
    prometheus_output = exporter.export_prometheus()
    print(prometheus_output)

    print("\nJSON 格式输出:")
    print("-" * 40)
    json_output = exporter.export_json()
    print(json_output)

    print("\n直接使用 collector 导出:")
    print("-" * 40)
    direct_output = collector.to_prometheus_format()
    print(direct_output)

    print("\n" + "=" * 60)
    print("4. Timer 上下文管理器")
    print("=" * 60)

    print("\n使用 Timer 测量执行时间...")

    def simulated_operation():
        time.sleep(0.1)
        return "operation completed"

    with Timer(security_metrics, "operation_duration_seconds") as timer:
        result = simulated_operation()

    print(f"   操作结果: {result}")
    print(f"   已记录执行时间到直方图")

    with Timer(security_metrics, "operation_duration_seconds", {"operation": "data_processing"}):
        time.sleep(0.05)

    print("   已记录带标签的操作时间")

    print("\n" + "=" * 60)
    print("5. HealthServer 健康检查")
    print("=" * 60)

    print("\n创建 HealthServer...")

    health_server = HealthServer(
        host="0.0.0.0",
        liveness_port=8081,
        readiness_port=8082,
        metrics_port=8083
    )

    print(f"   健康服务器已配置")
    print(f"   - 主机: {health_server.host}")
    print(f"   - 存活端口: {health_server.liveness_port}")
    print(f"   - 就绪端口: {health_server.readiness_port}")
    print(f"   - 指标端口: {health_server.metrics_port}")

    print("\n健康检查探针:")
    print(f"   - 存活探针: {health_server.liveness_probe}")
    print(f"   - 就绪探针: {health_server.readiness_probe}")
    print(f"   - 健康检查注册表: {health_server.registry}")

    print("\n获取存活状态:")
    liveness = health_server.get_liveness_response()
    print(f"   存活: {liveness}")

    print("\nPrometheus 指标:")
    exporter = MetricsExporter(collector)
    metrics_output = exporter.export_prometheus()
    print(f"   指标输出 (前500字符):")
    print(metrics_output[:500])

    print("\n" + "=" * 60)
    print("6. 综合示例: 模拟完整的监控流程")
    print("=" * 60)

    print("\n创建新的 MetricsCollector 用于模拟...")
    sim_collector = MetricsCollector()
    sim_collector.reset()

    sim_security_metrics = SecurityMetrics(sim_collector)

    print("\n模拟用户请求流程...")

    def simulate_request(user_id, allowed, latency):
        with Timer(sim_security_metrics, "request_duration_seconds", {"user_id": user_id}):
            time.sleep(latency)

        sim_security_metrics.record_request(allowed=allowed, latency=latency)

    simulate_request("user1", True, 0.1)
    simulate_request("user2", True, 0.15)
    simulate_request("user3", False, 0.05)
    simulate_request("user1", True, 0.2)
    simulate_request("user2", False, 0.08)

    print("   模拟了5个请求")

    print("\n模拟安全事件...")

    def simulate_security_event(event_type):
        if event_type == "sensitive_data":
            sim_security_metrics.record_sensitive_data(["email", "phone"])
        elif event_type == "prompt_injection":
            sim_security_metrics.record_prompt_injection(True, "high")
        elif event_type == "policy_violation":
            sim_security_metrics.record_policy_violation("rate_limit")

    simulate_security_event("sensitive_data")
    simulate_security_event("prompt_injection")
    simulate_security_event("policy_violation")

    print("   模拟了3个安全事件")

    print("\n模拟工具执行...")

    def simulate_tool_execution(tool_name, allowed):
        time.sleep(0.01)
        sim_security_metrics.record_tool_execution(tool_name, allowed)

    simulate_tool_execution("read_file", True)
    simulate_tool_execution("write_file", True)
    simulate_tool_execution("execute_command", False)
    simulate_tool_execution("delete_file", False)

    print("   模拟了4次工具执行")

    print("\n模拟合规检查...")

    def simulate_compliance_check(framework, passed):
        time.sleep(0.01)
        sim_security_metrics.record_compliance_check(framework, passed)

    simulate_compliance_check("SOC2", True)
    simulate_compliance_check("GDPR", True)
    simulate_compliance_check("ISO27001", False)
    simulate_compliance_check("HIPAA", True)

    print("   模拟了4次合规检查")

    print("\n模拟动态指标更新...")

    import random
    for i in range(5):
        active_sessions = random.randint(10, 50)
        security_score = random.uniform(0.7, 1.0)
        sim_security_metrics.set_active_sessions(active_sessions)
        sim_security_metrics.set_security_score(security_score)
        time.sleep(0.01)

    print("   更新了5次会话和安全评分")

    print("\n导出最终指标...")
    sim_exporter = MetricsExporter(sim_collector)
    final_metrics = sim_exporter.export_prometheus()
    print(final_metrics)

    print("\n" + "=" * 60)
    print("7. 多线程安全测试")
    print("=" * 60)

    print("\n测试 MetricsCollector 的线程安全性...")

    thread_collector = MetricsCollector()
    thread_collector.reset()

    def worker(worker_id, num_operations):
        for i in range(num_operations):
            thread_collector.counter("concurrent_requests_total", 1, {"worker": f"worker_{worker_id}"})
            thread_collector.gauge("worker_load", i % 10, {"worker": f"worker_{worker_id}"})
            thread_collector.histogram("worker_latency", random.uniform(0.01, 0.5))

    threads = []
    num_threads = 5
    operations_per_thread = 20

    import random

    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(i, operations_per_thread))
        threads.append(t)

    start_time = time.time()

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    elapsed = time.time() - start_time

    print(f"   完成了 {num_threads} 个线程 x {operations_per_thread} 次操作")
    print(f"   耗时: {elapsed:.3f}秒")

    thread_metrics = thread_collector.get_metrics()
    print(f"   收集到的指标数量: {len(thread_metrics)}")

    concurrent_counter = sum(
        m.value for m in thread_metrics
        if "concurrent_requests_total" in m.name
    )
    print(f"   总请求计数: {concurrent_counter}")

    print("\n" + "=" * 60)
    print("Prometheus 监控示例完成!")
    print("=" * 60)

    print("\n总结:")
    print("  1. MetricsCollector - 单例模式的指标收集器,支持计数器、仪表和直方图")
    print("  2. SecurityMetrics - 专门的安全指标类,记录请求、阻止、敏感数据等")
    print("  3. MetricsExporter - 导出 Prometheus 和 JSON 格式的指标")
    print("  4. Timer - 上下文管理器,用于测量操作执行时间")
    print("  5. HealthServer - 提供健康检查和指标端点的 HTTP 服务器")
    print("  6. 线程安全 - MetricsCollector 是线程安全的,可用于多线程环境")


if __name__ == "__main__":
    main()
