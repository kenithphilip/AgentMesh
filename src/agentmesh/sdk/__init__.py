"""AgentMesh SDK: framework adapters backed by the proxy HTTP API.

Each adapter implements its framework's callback/hook interface but
delegates security decisions to the AgentMesh proxy instead of running
Tessera locally. This lets framework users adopt the mesh without
importing tessera-mesh or running scanners in-process.

Available adapters:
- agentmesh.sdk.langchain: TesseraCallbackHandler for LangChain
- agentmesh.sdk.openai_agents: TesseraAgentHooks for OpenAI Agents SDK
- agentmesh.sdk.crewai: TesseraCrewCallback for CrewAI
- agentmesh.sdk.google_adk: TesseraADKCallbacks for Google ADK
- agentmesh.sdk.generic: GenericMeshGuard for any framework
"""
