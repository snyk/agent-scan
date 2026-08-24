.PHONY: run test tests coverage ci pre-commit clean binary build shiv publish-pypi publish reset-uv install-dev-server-cursor install-dev-server-windsurf compare-startup

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

coverage:
	AGENT_SCAN_ENVIRONMENT=test uv run --extra test -m pytest --runner=uv --cov=src/agent_scan --cov-report=term-missing --cov-report=html $(PYTEST_PATH_ARGS) $(ARGS)
	@echo ""
	@echo "📊 Coverage report generated! Open htmlcov/index.html in your browser"

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
	if [ -n "${APPLE_SIGNING_IDENTITY}" ]; then UV_PROJECT_ENVIRONMENT=.venv-x86_64 UV_PYTHON_PREFERENCE=managed arch -x86_64 /tmp/uv-x86_64-apple-darwin/uv run pyinstaller --onefile --name agent-scan --add-data 'src/agent_scan/hooks:agent_scan/hooks' --collect-all detect_secrets src/agent_scan/run.py --codesign-identity "${APPLE_SIGNING_IDENTITY}"; else UV_PROJECT_ENVIRONMENT=.venv-x86_64 UV_PYTHON_PREFERENCE=managed arch -x86_64 /tmp/uv-x86_64-apple-darwin/uv run pyinstaller --onefile --name agent-scan --add-data 'src/agent_scan/hooks:agent_scan/hooks' --collect-all detect_secrets src/agent_scan/run.py; fi
else
	uv sync
	uv pip install -e .[dev]
	if [ -n "${APPLE_SIGNING_IDENTITY}" ]; then uv run pyinstaller --onefile --name agent-scan --add-data 'src/agent_scan/hooks:agent_scan/hooks' --collect-all detect_secrets src/agent_scan/run.py --codesign-identity "${APPLE_SIGNING_IDENTITY}"; else uv run pyinstaller --onefile --name agent-scan --add-data 'src/agent_scan/hooks:agent_scan/hooks' --collect-all detect_secrets src/agent_scan/run.py; fi
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

# ---------------------------------------------------------------------------
# Startup-time comparison across packagers.
#
# Builds the CLI three ways, runs `--help` 3x on each, and prints a table so we
# can compare cold/warm startup latency. All artifacts land under COMPARE_DIR
# (default /tmp) so the working tree stays clean. Each build is best-effort
# (prefixed with `-`): if one packager fails to build, the others still run and
# the timing script reports "BUILD FAILED" for the missing one.
#
# Data bundling mirrors the real `binary` target: the guard hooks and the full
# detect_secrets package (plugins/data) must be included, or `agent-scan` won't
# run. Hook source is absolutized via $(CURDIR) so it resolves regardless of
# each build's --specpath/output-dir.
COMPARE_DIR ?= /tmp/agent-scan-startup-compare
COMPARE_DATA_PYI := --add-data '$(CURDIR)/src/agent_scan/hooks:agent_scan/hooks' --collect-all detect_secrets
COMPARE_ENTRY := $(CURDIR)/src/agent_scan/run.py

compare-startup:
	rm -rf $(COMPARE_DIR)
	mkdir -p $(COMPARE_DIR)
	uv sync
	uv pip install -e .[dev]
	uv pip install nuitka || true

	@echo "===> [1/3] PyInstaller --onefile (single file)"
	-uv run pyinstaller --onefile --name agent-scan \
		--distpath $(COMPARE_DIR)/pyi-onefile --workpath $(COMPARE_DIR)/_work/pyi-onefile --specpath $(COMPARE_DIR)/_spec/pyi-onefile \
		$(COMPARE_DATA_PYI) "$(COMPARE_ENTRY)"

	@echo "===> [2/3] PyInstaller --onedir (folder)"
	-uv run pyinstaller --onedir --name agent-scan \
		--distpath $(COMPARE_DIR)/pyi-onedir --workpath $(COMPARE_DIR)/_work/pyi-onedir --specpath $(COMPARE_DIR)/_spec/pyi-onedir \
		$(COMPARE_DATA_PYI) "$(COMPARE_ENTRY)"

	@echo "===> [3/3] Nuitka --onefile (single file, cached extraction dir)"
	@# Compile a launcher that lives OUTSIDE the package. Pointing Nuitka (or
	@# plain Python) directly at src/agent_scan/run.py puts that script's dir on
	@# sys.path[0], which exposes agent_scan/inspect.py as a top-level `inspect`
	@# and shadows the stdlib module (breaks anyio: `from inspect import
	@# isasyncgen`). A top-level launcher keeps agent_scan.inspect namespaced.
	printf '%s\n' 'from agent_scan.run import run' 'run()' > $(COMPARE_DIR)/nuitka_entry.py
	-uv run python -m nuitka --onefile --onefile-tempdir-spec="{CACHE_DIR}/agent-scan/{VERSION}" \
		--product-version=0.6.0 --assume-yes-for-downloads \
		--include-package=agent_scan --include-package=detect_secrets --include-package-data=detect_secrets \
		--include-data-dir="$(CURDIR)/src/agent_scan/hooks=agent_scan/hooks" \
		--output-dir=$(COMPARE_DIR)/nuitka --output-filename=agent-scan $(COMPARE_DIR)/nuitka_entry.py

	@# Wipe app-level extraction caches so run 1 of each variant is a true cold
	@# start. The Nuitka onefile bootstrap caches its unpacked payload under
	@# ~/.cache/agent-scan/<version>; without this it would be pre-warmed by the
	@# build/verify steps. (PyInstaller onefile re-extracts to a fresh temp dir
	@# every run, and onedir doesn't extract, so only the Nuitka cache persists.)
	@# NOTE: this does not purge the OS filesystem page cache — a fully cold-disk
	@# measurement would additionally need `sudo purge`.
	@echo "===> Clearing extraction caches for clean cold-run numbers"
	rm -rf "$$HOME/.cache/agent-scan"

	@echo ""
	@echo "================= STARTUP COMPARISON (agent-scan --help x3) ================="
	uv run python scripts/compare_startup.py \
		"PyInstaller onefile|$(COMPARE_DIR)/pyi-onefile/agent-scan|$(COMPARE_DIR)/pyi-onefile/agent-scan" \
		"PyInstaller onedir|$(COMPARE_DIR)/pyi-onedir/agent-scan/agent-scan|$(COMPARE_DIR)/pyi-onedir/agent-scan" \
		"Nuitka onefile|$(COMPARE_DIR)/nuitka/agent-scan|$(COMPARE_DIR)/nuitka/agent-scan"
