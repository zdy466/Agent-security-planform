import argparse
import asyncio
import json
import sys
from typing import Optional

from agentshield import AgentShieldClient
from agentshield.firewall.llm_data_firewall import EnhancedLLMDataFirewall as LLMDataFirewall
from agentshield.firewall.injection.prompt_injection import PromptInjectionFirewall
from agentshield.audit.audit_logger import AuditLogger


class CLI:
    def __init__(self):
        self.client: Optional[AgentShieldClient] = None

    def run(self, args=None):
        parser = self._create_parser()
        parsed = parser.parse_args(args)

        if not hasattr(parsed, 'func'):
            parser.print_help()
            return

        try:
            asyncio.run(parsed.func(self, parsed))
        except KeyboardInterrupt:
            print("\n操作已取消")
            sys.exit(0)
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)
            sys.exit(1)

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="agentshield",
            description="AgentShield OS - AI Agent Security CLI"
        )
        subparsers = parser.add_subparsers(title="命令", dest="command")

        scan_parser = subparsers.add_parser("scan", help="扫描文本中的敏感数据")
        scan_parser.add_argument("text", help="要扫描的文本")
        scan_parser.add_argument("--json", action="store_true", help="JSON 格式输出")
        scan_parser.set_defaults(func=self.cmd_scan)

        inject_parser = subparsers.add_parser("check-inject", help="检查 Prompt 注入")
        inject_parser.add_argument("text", help="要检查的文本")
        inject_parser.add_argument("--json", action="store_true", help="JSON 格式输出")
        inject_parser.set_defaults(func=self.cmd_check_inject)

        subparsers.add_parser("init", help="初始化 AgentShield 配置").set_defaults(func=self.cmd_init)

        logs_parser = subparsers.add_parser("logs", help="查看审计日志")
        logs_parser.add_argument("--limit", type=int, default=10, help="显示条数")
        logs_parser.add_argument("--json", action="store_true", help="JSON 格式输出")
        logs_parser.set_defaults(func=self.cmd_logs)

        subparsers.add_parser("config", help="显示当前配置").set_defaults(func=self.cmd_config)

        version_parser = subparsers.add_parser("version", help="显示版本信息")
        version_parser.set_defaults(func=self.cmd_version)

        return parser

    async def cmd_scan(self, args):
        firewall = LLMDataFirewall()
        result = firewall.check_input(args.text)

        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            if result.get("allowed"):
                print("✅ 未检测到敏感数据")
            else:
                print("❌ 检测到敏感数据")
                print(f"类型: {result.get('detected_types', [])}")
                print(f"原因: {result.get('reason', 'N/A')}")

    async def cmd_check_inject(self, args):
        firewall = PromptInjectionFirewall()
        result = firewall.check(args.text)

        if args.json:
            print(json.dumps({
                "detected": result.detected,
                "confidence": result.confidence,
                "attack_type": result.attack_type,
                "risk_level": result.risk_level
            }, ensure_ascii=False, indent=2))
        else:
            if result.detected:
                print(f"❌ 检测到 Prompt 注入攻击")
                print(f"攻击类型: {result.attack_type}")
                print(f"风险级别: {result.risk_level}")
                print(f"置信度: {result.confidence:.2%}")
            else:
                print("✅ 未检测到 Prompt 注入")

    async def cmd_init(self, args):
        config = {
            "version": "0.5.0",
            "firewall": {
                "enabled": True,
                "blocker": {
                    "block_critical": True,
                    "block_high": True
                }
            },
            "tool_manager": {
                "enabled": True,
                "whitelist": []
            },
            "data_gateway": {
                "enabled": True
            },
            "audit_logger": {
                "enabled": True
            }
        }

        with open("agentshield.json", "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)

        print("✅ 已创建配置文件 agentshield.json")

    async def cmd_logs(self, args):
        logger = AuditLogger()
        events = logger.get_events(limit=args.limit)

        if args.json:
            print(json.dumps([e.__dict__ for e in events], ensure_ascii=False, indent=2))
        else:
            if not events:
                print("暂无日志")
                return

            for event in events:
                status = "✅" if event.result == "success" else "❌"
                print(f"{status} [{event.timestamp}] {event.event_type}: {event.result}")

    async def cmd_config(self, args):
        try:
            with open("agentshield.json", "r", encoding="utf-8") as f:
                config = json.load(f)
            print(json.dumps(config, ensure_ascii=False, indent=2))
        except FileNotFoundError:
            print("❌ 未找到配置文件，请先运行 'agentshield init'")
            sys.exit(1)

    async def cmd_version(self, args):
        from agentshield import __version__
        print(f"AgentShield OS v{__version__}")


def main():
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()
