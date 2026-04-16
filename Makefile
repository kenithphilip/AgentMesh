# AgentMesh Team Tier operations

COMPOSE = docker compose -f deployment/docker/docker-compose.yml

.PHONY: up down logs demo clean

## Start the mesh
up:
	$(COMPOSE) up -d
	@echo ""
	@echo "AgentMesh is running."
	@echo "  Tessera proxy: http://localhost:9090"
	@echo "  agentgateway:  http://localhost:8080"
	@echo "  Demo tools:    http://localhost:3000"
	@echo ""
	@echo "Run the demo:    make demo"
	@echo "View events:     make logs"

## Stop the mesh
down:
	$(COMPOSE) down

## Tail security events from OTel collector
logs:
	$(COMPOSE) logs -f otel-collector

## Run the demo agent
demo:
	python examples/demo_agent.py

## Remove all containers, volumes, and images
clean:
	$(COMPOSE) down -v --rmi local

## Show mesh status
status:
	$(COMPOSE) ps
