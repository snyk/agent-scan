.PHONY: run test tests ci pre-commit clean binary build shiv publish-pypi publish reset-uv install-dev-server-cursor install-dev-server-windsurf generate-mcp-locations

# Pass extra arguments via ARGS, e.g.: make test ARGS="-v -k test_basic tests/e2e/"
ARGS ?=

# Capture trailing targets for the run command (e.g. make run scan --json foo.json)
ifeq (run,$(firstword $(MAKECMDGOALS)))
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  $(eval $(RUN_ARGS):;@:)
endif

# Capture positional pytest args (e.g. make test tests/e2e/test_scan.py)
# Use ARGS for flag-like pytest args (e.g. ARGS="-k basic -q").
ifneq (,$(filter test tests ci,$(firstword $(MAKECMDGOALS))))
  PYTEST_PATH_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  .PHONY: $(PYTEST_PATH_ARGS)
  $(eval $(PYTEST_PATH_ARGS):;@:)
endif

run:
	uv run -m src.agent_scan.run $(RUN_ARGS)

test tests:
	AGENT_SCAN_ENVIRONMENT=test uv run --extra test -m pytest --runner=uv $(PYTEST_PATH_ARGS) $(ARGS)

ci:
	$(MAKE) binary
	AGENT_SCAN_ENVIRONMENT=ci uv run --extra test -m pytest -vv --runner=binary $(PYTEST_PATH_ARGS) $(ARGS)

pre-commit:
	uv sync
	uv pip install pre-commit
	uv run pre-commit run --all-files

clean:
	rm -rf ./dist
	rm -rf ./agent_scan/agent_scan.egg-info
	rm -rf ./npm/dist
	rm -rf ./ame.spec
	rm -rf ./agent-scan.spec

binary:
	uv sync
	uv pip install -e .[dev]
	if [ -n "${APPLE_SIGNING_IDENTITY}" ]; then uv run pyinstaller --onefile --name agent-scan src/agent_scan/run.py --codesign-identity "${APPLE_SIGNING_IDENTITY}"; else uv run pyinstaller --onefile --name agent-scan src/agent_scan/run.py; fi

build: clean
	uv build --no-sources

shiv: build
	uv pip install -e .[dev]
	mkdir -p dist
	uv run shiv -c agent-scan -o dist/agent-scan.pyz --python "/usr/bin/env python3" dist/*.whl

publish-pypi: build
	uv publish --token ${AGENT_SCAN_PYPI_TOKEN}

publish: publish-pypi

reset-uv:
	rm -rf .venv || true
	rm uv.lock || true
	uv venv

install-dev-server-cursor:
	uv run --directory $PWD -m src.agent_scan.run install-mcp-server ~/.cursor/mcp.json --background --tool --client-name Cursor

install-dev-server-windsurf:
	uv run --directory $PWD -m src.agent_scan.run install-mcp-server ~/.codeium/windsurf/mcp_config.json --background --tool --client-name Windsurf

generate-mcp-locations:
	uv run python scripts/generate_mcp_config_locations.py
