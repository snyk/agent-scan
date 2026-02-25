# If the first argument is "run"...
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

run:
	uv run -m src.mcp_scan.run ${RUN_ARGS}

test-all:
	uv sync
	uv pip install -e ".[test,proxy]"
	MCP_SCAN_ENVIRONMENT=test uv run python -m pytest

test-static:
	uv sync
	uv pip install -e ".[test]"
	MCP_SCAN_ENVIRONMENT=test uv run python -m pytest

test: test-all

ci-static:
	uv sync
	uv pip install -e ".[test]"
	MCP_SCAN_ENVIRONMENT=ci uv run python -m pytest

ci-proxy:
	uv sync
	uv pip install -e ".[test,proxy]"
	MCP_SCAN_ENVIRONMENT=ci uv run python -m pytest

ci: ci-static ci-proxy

pre-commit:
	uv sync
	uv pip install pre-commit
	uv run pre-commit run --all-files

clean:
	rm -rf ./dist
	rm -rf ./mcp_scan/mcp_scan.egg-info
	rm -rf ./npm/dist
	rm -rf ./ame.spec
	rm -rf ./mcp-scan.spec

binary:
	uv sync
	uv pip install -e .[dev]
	if [ -n "${APPLE_SIGNING_IDENTITY}" ]; then uv run pyinstaller --onefile --name mcp-scan src/mcp_scan/run.py --codesign-identity "${APPLE_SIGNING_IDENTITY}"; else uv run pyinstaller --onefile --name mcp-scan src/mcp_scan/run.py; fi

build: clean
	uv build --no-sources

shiv: build
	uv pip install -e .[dev]
	mkdir -p dist
	uv run shiv -c mcp-scan -o dist/mcp-scan.pyz --python "/usr/bin/env python3" dist/*.whl

publish-pypi: build
	uv publish --token ${PYPI_TOKEN}

publish: publish-pypi

pre-commit:
	pre-commit run --all-files

reset-uv:
	rm -rf .venv || true
	rm uv.lock || true
	uv venv

install-dev-server-cursor:
	uv run --directory $PWD -m src.mcp_scan.run install-mcp-server ~/.cursor/mcp.json --background --tool --client-name Cursor

install-dev-server-windsurf:
	uv run --directory $PWD -m src.mcp_scan.run install-mcp-server ~/.codeium/windsurf/mcp_config.json --background --tool --client-name Windsurf
