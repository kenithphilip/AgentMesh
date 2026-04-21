"""AgentMesh SDK: framework adapters backed by the proxy HTTP API.

Each adapter implements its framework's callback/hook interface but
delegates security decisions to the AgentMesh proxy instead of running
Tessera locally. This lets framework users adopt the mesh without
importing tessera-mesh or running scanners in-process.

Available adapters:

| Adapter module                  | Class                  | Framework            |
|---------------------------------|------------------------|----------------------|
| agentmesh.sdk.langchain         | MeshCallbackHandler    | LangChain            |
| agentmesh.sdk.openai_agents     | MeshAgentHooks         | OpenAI Agents SDK    |
| agentmesh.sdk.crewai            | MeshCrewCallback       | CrewAI               |
| agentmesh.sdk.google_adk        | MeshADKCallbacks       | Google ADK           |
| agentmesh.sdk.llamaindex        | MeshLlamaIndexHandler  | LlamaIndex           |
| agentmesh.sdk.langgraph         | MeshLangGraphGuard     | LangGraph            |
| agentmesh.sdk.haystack          | MeshHaystackGuard      | Haystack             |
| agentmesh.sdk.pydantic_ai       | MeshPydanticAIGuard    | PydanticAI           |
| agentmesh.sdk.nemo              | MeshRailAction         | NeMo Guardrails      |
| agentmesh.sdk.agentdojo         | MeshToolLabeler /      | AgentDojo benchmark  |
|                                 | MeshToolGuard          |                      |
| agentmesh.sdk.generic           | MeshGuard              | Any framework        |

LlamaFirewall is a scanner library, not a framework. Use
``MeshClient.scan(text)`` directly if you want LlamaFirewall-style
scoring through the proxy.
"""
