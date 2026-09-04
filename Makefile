.PHONY: help
help:
	@grep -E '^[a-zA-Z_0-9-]+(-%)?:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# ===========================================================================
# Unit tests
# ===========================================================================

.PHONY: test_unit
test_unit: test_unit_core test_unit_sandbox test_unit_qjs ## Run unit tests

# vitest matches these by path substring, not glob, so keep them scoped:
# src/core is the shared library (also dual-tested under QuickJS below),
# src/lib + src/main*.ts is isolated-run's own action code.
.PHONY: test_unit_core
test_unit_core: ## Run core library unit tests
	@vp test run src/core

.PHONY: test_unit_sandbox
test_unit_sandbox: ## Run the action's own unit tests
	@vp test run src/lib src/main

# qjs can't execute .ts directly, so compile fresh (vp run build:qjs-test)
# and bind-mount the output in.
QJS_MOUNTS := \
	-v "$(CURDIR)/dist/qjs-test/src/core:/opt/buildcage/core:ro"
QJS_TEST_DIRS := \
	/opt/buildcage/core/lib/acl

.PHONY: test_unit_qjs
test_unit_qjs: ## Run unit tests in Docker
	@vp run build:qjs-test
	@docker build -f docker/universal/Dockerfile -t buildcage-qjs-test .
	@docker run --rm --entrypoint qjs $(QJS_MOUNTS) buildcage-qjs-test \
		--std -m /opt/buildcage/core/scripts/test/run-tests.qjs.js $(QJS_TEST_DIRS)

# ===========================================================================
# Sandbox dev loop — mac-friendly local iteration on run-isolated.sh (see
# dev/Dockerfile). CI's test_sandbox job runs run-isolated.sh directly on
# the host instead — see docs/development.md.
# ===========================================================================

.PHONY: setup_sandbox_dev
setup_sandbox_dev: ## Start sandbox proxy + dev runner (mac-friendly dev loop)
	@echo "Starting buildcage sandbox (dev loop)..."
	@ALLOWED_HTTPS_RULES="$${ALLOWED_HTTPS_RULES:-example.com:443}" \
	  ALLOWED_HTTP_RULES="$${ALLOWED_HTTP_RULES:-example.com:80}" \
	  docker compose -f compose.yaml -f docker/compose.sandbox-dev.yaml up -d --build --wait proxy sandbox-dev-runner
	@echo "Proxy container:  buildcage-proxy"
	@echo "Dev runner:       buildcage-sandbox-dev-runner"
	@echo "Try: make test_sandbox_dev"

.PHONY: test_sandbox_dev
test_sandbox_dev: ## Run a sample isolated command in the dev loop and verify isolation
	@$(MAKE) setup_sandbox_dev
	@PROXY_PID=$$(docker inspect --format '{{.State.Pid}}' buildcage-proxy); \
	  docker compose -f compose.yaml -f docker/compose.sandbox-dev.yaml exec sandbox-dev-runner sh -c " \
	    set -e; \
	    build-test-bundle.sh --netns-name buildcage-sandbox-dev --script /usr/local/bin/smoke-test.sh --bundle /var/tmp/buildcage/dev-bundle; \
	    run-isolated.sh --proxy-pid $$PROXY_PID --runc /usr/local/bin/runc --bundle /var/tmp/buildcage/dev-bundle \
	      --container-id buildcage-sandbox-dev --netns-name buildcage-sandbox-dev --rootfs-bind-dir /var/tmp/buildcage/dev-bundle/rootfs \
	      --gateway 172.20.0.1 --dns 172.20.0.1 --target-ip 172.20.0.101"
	@$(MAKE) clean_sandbox_dev

.PHONY: clean_sandbox_dev
clean_sandbox_dev: ## Stop and remove the sandbox dev-loop containers
	@docker compose -f compose.yaml -f docker/compose.sandbox-dev.yaml down -v --rmi local

# Drives dist/main.cjs directly (a host command, not a Docker build).
.PHONY: test_integration_sandbox_linux
test_integration_sandbox_linux: ## Run the action's integration tests (needs BUILDCAGE_LOCAL_IMAGE_REF and a test-hook build of dist/main.cjs)
	@./test/integration-test-writable-dir.sh
	@./test/integration-test-writable-disabled.sh
	@./test/integration-test-defaults.sh
	@./test/integration-test-seccomp.sh
	@./test/integration-test-die-with-parent.sh
	@./test/integration-test-fs-escape.sh
	@./test/integration-test-runner-temp.sh
	@./test/integration-test-nested-mount-readonly.sh
	@./test/integration-test-non-runc-default-pseudofs-readonly.sh
	@./test/integration-test-concurrent.sh
	@./test/integration-test-known-blocked-rules.sh
	@./test/integration-test-zero-traffic.sh
	@./test/integration-test-runtime-sockets.sh
	@./test/integration-test-ephemeral-fs.sh

# Separate from test_integration_sandbox_linux: these use the fixture origin
# network in compose.test-universal.yaml (fake DNS + an origin under our own
# control) instead of the real internet, which is what lets them cover cases
# real hosts can't -- an allowlisted name resolving to an internal address,
# NXDOMAIN, direct-IP blocking with no allowed_ip_rules, etc.
.PHONY: test_integration_sandbox_universal
test_integration_sandbox_universal: ## Run the universal-engine fixture-based integration tests (needs BUILDCAGE_LOCAL_IMAGE_REF built with test hooks)
	@./test/integration-test-universal-restrict.sh
	@./test/integration-test-universal-audit.sh

# Separate from the above: these need an inspect-engine image (a different
# Dockerfile/build) and the fixture origin network in compose.test-inspect.yaml.
.PHONY: test_integration_sandbox_inspect
test_integration_sandbox_inspect: ## Run the inspect-engine integration tests (needs BUILDCAGE_LOCAL_IMAGE_REF built from docker/inspect with test hooks)
	@./test/integration-test-inspect-restrict.sh
	@./test/integration-test-inspect-audit.sh
	@./test/integration-test-inspect-roundtrip.sh
