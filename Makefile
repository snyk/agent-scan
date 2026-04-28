.PHONY: run test tests ci pre-commit clean binary build shiv publish-pypi publish reset-uv install-dev-server-cursor install-dev-server-windsurf

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

ARCH ?=

binary:
ifeq ($(ARCH),x86_64)
	@if [ "$$(uname)" != "Darwin" ]; then echo "ERROR: ARCH=x86_64 is only supported on macOS (darwin)"; exit 1; fi
	curl -LsSf https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-apple-darwin.tar.gz | tar -xz -C /tmp
	UV_PYTHON_PREFERENCE=managed arch -x86_64 /tmp/uv-x86_64-apple-darwin/uv python install 3.13
	UV_PROJECT_ENVIRONMENT=.venv-x86_64 UV_PYTHON_PREFERENCE=managed arch -x86_64 /tmp/uv-x86_64-apple-darwin/uv sync --extra dev
	if [ -n "${APPLE_SIGNING_IDENTITY}" ]; then UV_PROJECT_ENVIRONMENT=.venv-x86_64 UV_PYTHON_PREFERENCE=managed arch -x86_64 /tmp/uv-x86_64-apple-darwin/uv run pyinstaller --onefile --name agent-scan --add-data 'src/agent_scan/hooks:agent_scan/hooks' src/agent_scan/run.py --codesign-identity "${APPLE_SIGNING_IDENTITY}"; else UV_PROJECT_ENVIRONMENT=.venv-x86_64 UV_PYTHON_PREFERENCE=managed arch -x86_64 /tmp/uv-x86_64-apple-darwin/uv run pyinstaller --onefile --name agent-scan --add-data 'src/agent_scan/hooks:agent_scan/hooks' src/agent_scan/run.py; fi
else
	uv sync
	uv pip install -e .[dev]
	if [ -n "${APPLE_SIGNING_IDENTITY}" ]; then uv run pyinstaller --onefile --name agent-scan --add-data 'src/agent_scan/hooks:agent_scan/hooks' src/agent_scan/run.py --codesign-identity "${APPLE_SIGNING_IDENTITY}"; else uv run pyinstaller --onefile --name agent-scan --add-data 'src/agent_scan/hooks:agent_scan/hooks' src/agent_scan/run.py; fi
endif

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
