"""Framework Adapters - Adapters for popular AI Agent frameworks"""

import logging
from typing import Any, Callable, Dict, List, Optional, Union
from abc import ABC, abstractmethod


class BaseAdapter(ABC):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.enabled = self.config.get("enabled", True)

    @abstractmethod
    def wrap_agent(self, agent: Any) -> Any:
        pass

    @abstractmethod
    def wrap_tool(self, tool: Any) -> Any:
        pass


class LangChainAdapter(BaseAdapter):
    """Adapter for LangChain framework"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.security_layer = None
        self.firewall = None
        self.tool_manager = None

    def set_security_components(self, security_layer=None, firewall=None, tool_manager=None):
        self.security_layer = security_layer
        self.firewall = firewall
        self.tool_manager = tool_manager

    def wrap_agent(self, agent: Any) -> Any:
        if not self.enabled:
            return agent

        original_run = getattr(agent, 'run', None)
        original_call = getattr(agent, '__call__', None)

        def secure_run(*args, **kwargs):
            if self.firewall:
                input_text = args[0] if args else kwargs.get('input', '')
                if isinstance(input_text, str):
                    result = self.firewall.check_input(input_text)
                    if not result.get('allowed'):
                        return {"error": result.get('reason'), "blocked": True}

            if original_run:
                result = original_run(*args, **kwargs)
            elif original_call:
                result = original_call(*args, **kwargs)
            else:
                result = agent

            if self.firewall and isinstance(result, str):
                result = self.firewall.sanitize(result)

            return result

        if original_run:
            agent.run = secure_run
        if original_call:
            agent.__call__ = secure_run

        return agent

    def wrap_tool(self, tool: Any) -> Any:
        if not self.enabled:
            return tool

        original_func = getattr(tool, 'func', None) or getattr(tool, 'function', None)

        def secure_func(*args, **kwargs):
            if self.tool_manager:
                tool_name = getattr(tool, 'name', 'unknown')
                can_execute = self.tool_manager.can_execute(tool_name)
                if not can_execute:
                    raise PermissionError(f"Tool '{tool_name}' is not allowed to execute")

            if original_func:
                return original_func(*args, **kwargs)
            return None

        if original_func:
            if hasattr(tool, 'func'):
                tool.func = secure_func
            elif hasattr(tool, 'function'):
                tool.function = secure_func

        return tool

    def create_secure_agent(self, llm: Any, tools: List[Any], **kwargs) -> Any:
        try:
            from langchain.agents import AgentExecutor
            from langchain.tools import Tool

            secure_tools = [self.wrap_tool(tool) for tool in tools]

            if 'agent' not in kwargs:
                from langchain.agents import AgentType
                kwargs['agent'] = AgentType.ZERO_SHOT_REACT_DESCRIPTION

            executor = AgentExecutor.from_agent_and_tools(
                agent=llm,
                tools=secure_tools,
                **kwargs
            )

            return self.wrap_agent(executor)
        except ImportError:
            self.logger.warning("LangChain not installed, returning mock adapter")
            return self._create_mock_agent(llm, tools)

    def create_secure_llm(self, llm: Any) -> Any:
        original_generate = getattr(llm, 'generate', None)

        def secure_generate(prompts: List[str], **kwargs):
            if self.firewall:
                for prompt in prompts:
                    result = self.firewall.check_input(prompt)
                    if not result.get('allowed'):
                        raise ValueError(f"Input blocked: {result.get('reason')}")

            if original_generate:
                results = original_generate(prompts, **kwargs)
            else:
                results = llm(prompts)

            if self.firewall and hasattr(results, 'generations'):
                for generation_list in results.generations:
                    for generation in generation_list:
                        if hasattr(generation, 'text'):
                            generation.text = self.firewall.sanitize(generation.text)

            return results

        if original_generate:
            llm.generate = secure_generate

        return llm

    def _create_mock_agent(self, llm: Any, tools: List[Any]) -> Any:
        class MockAgent:
            def __init__(self, llm, tools):
                self.llm = llm
                self.tools = tools

            def run(self, input_text: str):
                return f"Secure agent processed: {input_text}"

            def __call__(self, input_text: str):
                return self.run(input_text)

        return MockAgent(llm, tools)


class AutoGPTAdapter(BaseAdapter):
    """Adapter for AutoGPT framework"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

    def wrap_agent(self, agent: Any) -> Any:
        if not self.enabled:
            return agent

        original_think = getattr(agent, 'think', None)

        def secure_think(*args, **kwargs):
            if original_think:
                return original_think(*args, **kwargs)
            return agent

        if original_think:
            agent.think = secure_think

        return agent

    def wrap_tool(self, tool: Any) -> Any:
        return tool


class OpenAIFunctionsAdapter(BaseAdapter):
    """Adapter for OpenAI Functions agents"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

    def wrap_agent(self, agent: Any) -> Any:
        return agent

    def wrap_tool(self, tool: Any) -> Any:
        return tool

    def create_secure_function(self, func: Callable) -> Callable:
        def secure_function(*args, **kwargs):
            return func(*args, **kwargs)
        return secure_function


class FrameworkAdapterFactory:
    ADAPTERS = {
        "langchain": LangChainAdapter,
        "autogpt": AutoGPTAdapter,
        "openai_functions": OpenAIFunctionsAdapter,
    }

    @classmethod
    def create_adapter(cls, framework: str, config: Optional[Dict[str, Any]] = None) -> BaseAdapter:
        adapter_class = cls.ADAPTERS.get(framework.lower())
        if adapter_class:
            return adapter_class(config)
        raise ValueError(f"Unsupported framework: {framework}")

    @classmethod
    def register_adapter(cls, name: str, adapter_class: type):
        cls.ADAPTERS[name.lower()] = adapter_class


class LlamaIndexAdapter(BaseAdapter):
    """Adapter for LlamaIndex framework"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.security_layer = None
        self.firewall = None
        self.tool_manager = None

    def set_security_components(self, security_layer=None, firewall=None, tool_manager=None):
        self.security_layer = security_layer
        self.firewall = firewall
        self.tool_manager = tool_manager

    def wrap_agent(self, agent: Any) -> Any:
        if not self.enabled:
            return agent

        original_query = getattr(agent, 'query', None)
        original_chat = getattr(agent, 'chat', None)

        def secure_query(*args, **kwargs):
            if self.firewall:
                query_text = args[0] if args else kwargs.get('query', '')
                if isinstance(query_text, str):
                    result = self.firewall.check_input(query_text)
                    if not result.get('allowed'):
                        return {"error": result.get('reason'), "blocked": True}

            if original_query:
                response = original_query(*args, **kwargs)
            elif original_chat:
                response = original_chat(*args, **kwargs)
            else:
                response = agent

            if self.firewall and hasattr(response, 'response'):
                response.response = self.firewall.sanitize(str(response.response))

            return response

        if original_query:
            agent.query = secure_query
        if original_chat:
            agent.chat = secure_chat = secure_query

        return agent

    def wrap_tool(self, tool: Any) -> Any:
        if not self.enabled:
            return tool

        original_call = getattr(tool, '__call__', None) or getattr(tool, 'call', None)

        def secure_call(*args, **kwargs):
            if self.tool_manager:
                tool_name = getattr(tool, 'name', 'unknown')
                can_execute = self.tool_manager.can_execute(tool_name)
                if not can_execute:
                    raise PermissionError(f"Tool '{tool_name}' is not allowed to execute")

            if original_call:
                return original_call(*args, **kwargs)
            return None

        if original_call:
            if hasattr(tool, '__call__'):
                tool.__call__ = secure_call
            elif hasattr(tool, 'call'):
                tool.call = secure_call

        return tool

    def wrap_index(self, index: Any) -> Any:
        if not self.enabled:
            return index

        original_query = getattr(index, 'query', None)

        def secure_query(*args, **kwargs):
            if self.firewall:
                query_text = args[0] if args else kwargs.get('query', '')
                if isinstance(query_text, str):
                    result = self.firewall.check_input(query_text)
                    if not result.get('allowed'):
                        raise ValueError(f"Query blocked: {result.get('reason')}")

            if original_query:
                response = original_query(*args, **kwargs)

                if self.firewall and hasattr(response, 'response'):
                    response.response = self.firewall.sanitize(str(response.response))

                return response
            return None

        if original_query:
            index.query = secure_query

        return index

    def create_secure_query_engine(self, query_engine: Any) -> Any:
        return self.wrap_index(query_engine)


class AutoGenAdapter(BaseAdapter):
    """Adapter for AutoGen framework"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.security_layer = None
        self.firewall = None
        self.tool_manager = None

    def set_security_components(self, security_layer=None, firewall=None, tool_manager=None):
        self.security_layer = security_layer
        self.firewall = firewall
        self.tool_manager = tool_manager

    def wrap_agent(self, agent: Any) -> Any:
        if not self.enabled:
            return agent

        original_generate = getattr(agent, 'generate_reply', None)
        original_run = getattr(agent, 'run', None)

        def secure_generate_reply(*args, **kwargs):
            if self.firewall and args:
                for arg in args:
                    if isinstance(arg, str):
                        result = self.firewall.check_input(arg)
                        if not result.get('allowed'):
                            return {"error": result.get('reason'), "blocked": True}
                    elif isinstance(arg, dict):
                        for key, value in arg.items():
                            if isinstance(value, str):
                                result = self.firewall.check_input(value)
                                if not result.get('allowed'):
                                    return {"error": result.get('reason'), "blocked": True}

            if original_generate:
                response = original_generate(*args, **kwargs)
            else:
                response = None

            if self.firewall and isinstance(response, str):
                response = self.firewall.sanitize(response)

            return response

        def secure_run(*args, **kwargs):
            if self.firewall:
                for arg in args:
                    if isinstance(arg, str):
                        result = self.firewall.check_input(arg)
                        if not result.get('allowed'):
                            return {"error": result.get('reason'), "blocked": True}

                for key, value in kwargs.items():
                    if isinstance(value, str):
                        result = self.firewall.check_input(value)
                        if not result.get('allowed'):
                            return {"error": result.get('reason'), "blocked": True}

            if original_run:
                result = original_run(*args, **kwargs)
            else:
                result = agent

            if self.firewall and isinstance(result, str):
                result = self.firewall.sanitize(result)

            return result

        if original_generate:
            agent.generate_reply = secure_generate_reply
        if original_run:
            agent.run = secure_run

        return agent

    def wrap_tool(self, tool: Any) -> Any:
        if not self.enabled:
            return tool

        original_func = getattr(tool, 'func', None) or getattr(tool, 'function', None)

        def secure_func(*args, **kwargs):
            if self.tool_manager:
                tool_name = getattr(tool, 'name', 'unknown')
                can_execute = self.tool_manager.can_execute(tool_name)
                if not can_execute:
                    raise PermissionError(f"Tool '{tool_name}' is not allowed to execute")

            if original_func:
                result = original_func(*args, **kwargs)
                if self.firewall and isinstance(result, str):
                    result = self.firewall.sanitize(result)
                return result
            return None

        if original_func:
            if hasattr(tool, 'func'):
                tool.func = secure_func
            elif hasattr(tool, 'function'):
                tool.function = secure_func

        return tool

    def wrap_conversation(self, conversation: Any) -> Any:
        if not self.enabled:
            return conversation

        original_add = getattr(conversation, 'add', None)

        def secure_add(*args, **kwargs):
            if self.firewall:
                for arg in args:
                    if isinstance(arg, str):
                        result = self.firewall.check_input(arg)
                        if not result.get('allowed'):
                            return {"error": result.get('reason'), "blocked": True}

            if original_add:
                return original_add(*args, **kwargs)
            return None

        if original_add:
            conversation.add = secure_add

        return conversation


class CrewAIAdapter(BaseAdapter):
    """Adapter for CrewAI framework"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.security_layer = None
        self.firewall = None
        self.tool_manager = None

    def set_security_components(self, security_layer=None, firewall=None, tool_manager=None):
        self.security_layer = security_layer
        self.firewall = firewall
        self.tool_manager = tool_manager

    def wrap_agent(self, agent: Any) -> Any:
        if not self.enabled:
            return agent

        original_execute = getattr(agent, 'execute_task', None) or getattr(agent, 'execute', None)

        def secure_execute(*args, **kwargs):
            if self.firewall:
                task = args[0] if args else kwargs.get('task', '')
                if isinstance(task, str):
                    result = self.firewall.check_input(task)
                    if not result.get('allowed'):
                        return {"error": result.get('reason'), "blocked": True}

            if original_execute:
                result = original_execute(*args, **kwargs)
            else:
                result = agent

            if self.firewall and isinstance(result, str):
                result = self.firewall.sanitize(result)

            return result

        if original_execute:
            if hasattr(agent, 'execute_task'):
                agent.execute_task = secure_execute
            elif hasattr(agent, 'execute'):
                agent.execute = secure_execute

        return agent

    def wrap_task(self, task: Any) -> Any:
        if not self.enabled:
            return task

        return task

    def wrap_tool(self, tool: Any) -> Any:
        if not self.enabled:
            return tool

        original_func = getattr(tool, 'func', None) or getattr(tool, 'execute', None)

        def secure_func(*args, **kwargs):
            if self.tool_manager:
                tool_name = getattr(tool, 'name', 'unknown')
                can_execute = self.tool_manager.can_execute(tool_name)
                if not can_execute:
                    raise PermissionError(f"Tool '{tool_name}' is not allowed to execute")

            if original_func:
                return original_func(*args, **kwargs)
            return None

        if original_func:
            if hasattr(tool, 'func'):
                tool.func = secure_func
            elif hasattr(tool, 'execute'):
                tool.execute = secure_func

        return tool


class VertexAIAgentBuilderAdapter(BaseAdapter):
    """Adapter for Google Vertex AI Agent Builder"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.security_layer = None
        self.firewall = None

    def set_security_components(self, security_layer=None, firewall=None):
        self.security_layer = security_layer
        self.firewall = firewall

    def wrap_agent(self, agent: Any) -> Any:
        if not self.enabled:
            return agent

        original_predict = getattr(agent, 'predict', None) or getattr(agent, 'chat', None)

        def secure_predict(*args, **kwargs):
            if self.firewall:
                input_text = args[0] if args else kwargs.get('message', '')
                if isinstance(input_text, str):
                    result = self.firewall.check_input(input_text)
                    if not result.get('allowed'):
                        return {"error": result.get('reason'), "blocked": True}

            if original_predict:
                response = original_predict(*args, **kwargs)
            else:
                response = agent

            if self.firewall and isinstance(response, str):
                response = self.firewall.sanitize(response)

            return response

        if original_predict:
            if hasattr(agent, 'predict'):
                agent.predict = secure_predict
            elif hasattr(agent, 'chat'):
                agent.chat = secure_predict

        return agent


FrameworkAdapterFactory.ADAPTERS.update({
    "llamaindex": LlamaIndexAdapter,
    "autogen": AutoGenAdapter,
    "crewai": CrewAIAdapter,
    "vertexai": VertexAIAgentBuilderAdapter,
})
