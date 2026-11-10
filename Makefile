SHELL      := /bin/bash
PY         := python3
DK         := ./scripts/dk
TARGET     ?= juice-shop
TOOLS      ?= sast,sca,sca-npm,dast,custom
RUN_ID     ?=
FAIL_ON    ?=

.DEFAULT_GOAL := help

.PHONY: help install install-docker sources up up-crapi up-juice up-roundcube down down-crapi down-all scan scan-offline ci compare clean

help: ## Afficher cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Installer les dépendances Python du projet
	@if python3 -c "import yaml" 2>/dev/null; then \
	  echo "PyYAML déjà disponible"; \
	elif command -v uv >/dev/null 2>&1; then \
	  uv pip install --system -r requirements.txt; \
	else \
	  python3 -m pip install --user -r requirements.txt; \
	fi

install-docker: ## Installer Docker Engine + Compose (sudo requis)
	sudo bash scripts/install-docker.sh

sources: ## Cloner les codes source des cibles (SAST / SCA)
	bash scripts/fetch-sources.sh

up-crapi: ## Déployer crAPI (http://localhost:8888)
	bash scripts/deploy-crapi.sh

up-juice: ## Déployer Juice Shop (http://localhost:3000)
	$(DK) compose -f targets/compose/juice-shop.yml up -d

up-roundcube: ## Déployer Roundcube (http://localhost:8080)
	$(DK) compose -f targets/compose/roundcube.yml up -d

up-sonar: ## Déployer SonarQube (http://localhost:9000, admin/admin)
	sudo sysctl -w vm.max_map_count=262144
	$(DK) compose -f targets/compose/sonarqube.yml up -d

sonar: ## Lancer sonar-scanner sur TARGET (SONAR_HOST_URL / SONAR_TOKEN requis)
	bash scripts/run-sonar.sh $(TARGET)

up: up-juice up-crapi up-roundcube ## Déployer toutes les cibles

down-crapi: ## Arrêter crAPI
	bash scripts/deploy-crapi.sh stop

down: ## Arrêter Juice Shop et Roundcube
	$(DK) compose -f targets/compose/juice-shop.yml down
	$(DK) compose -f targets/compose/roundcube.yml down

down-sonar: ## Arrêter SonarQube
	$(DK) compose -f targets/compose/sonarqube.yml down

down-all: down down-crapi ## Arrêter toutes les cibles

scan: ## Lancer une campagne (TARGET=..., TOOLS=...)
	$(PY) -m secauto run --target $(TARGET) --tools $(TOOLS) \
	  $(if $(RUN_ID),--run-id $(RUN_ID),) $(if $(FAIL_ON),--fail-on $(FAIL_ON),)

scan-offline: ## Campagne sans packs Semgrep distants
	$(PY) -m secauto run --target $(TARGET) --tools $(TOOLS) --offline

ci: ## Campagne de CI (échec si high ou critical)
	$(PY) -m secauto run --target $(TARGET) --tools sast,sca,sca-npm \
	  --fail-on high

compare: ## Comparer deux exécutions : make compare BEFORE=... AFTER=...
	$(PY) -m secauto compare --target $(TARGET) --before $(BEFORE) --after $(AFTER)

clean: ## Supprimer les rapports générés
	rm -rf reports/*
	touch reports/.gitkeep
