BIN := salve
CARGO ?= cargo

.PHONY: build release test lint fmt fmt-check clean install deps smoke verify dev

# Every target that produces a binary signs it (cli-common's dev-sign.sh), so
# the code identity stays stable between builds and the vault's one keychain
# item is not asked for again after each rebuild.
build: SIGN_TARGET = target/debug/$(BIN)
build:
	$(CARGO) build
	@$(SIGN)

release: SIGN_TARGET = target/release/$(BIN)
release:
	$(CARGO) build --release
	@$(SIGN)

test:
	$(CARGO) test

lint:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

clean:
	$(CARGO) clean

deps:
	$(CARGO) fetch

# `--locked` builds from Cargo.lock, the versions the tests and audit ran on.
install: SIGN_TARGET = $${CARGO_INSTALL_ROOT:-$$HOME/.cargo}/bin/$(BIN)
install:
	$(CARGO) install --path . --locked --force
	@$(SIGN)

dev: SIGN_TARGET = target/debug/$(BIN)
dev:
	$(CARGO) build
	@$(SIGN)

# Offline smoke test: no network and never the real keychain, vault or
# browser profile: SALVE_KEYCHAIN_SERVICE names a service that holds
# nothing, with the vault under a fresh folder in target/. Nothing is stored,
# so no key is read.
SMOKE_DIR := $(CURDIR)/target/smoke-$(shell date +%s)
HERMETIC = SALVE_KEYCHAIN_SERVICE=piekstra.salve.hermetic-tests XDG_DATA_HOME=$(SMOKE_DIR)/data \
	XDG_CONFIG_HOME=$(SMOKE_DIR)/config
smoke: build
	@./target/debug/$(BIN) --version >/dev/null
	@env -u SALVE_PROFILE ./target/debug/$(BIN) info >/dev/null
	@env -u SALVE_PROFILE ./target/debug/$(BIN) completions bash >/dev/null
	@$(HERMETIC) ./target/debug/$(BIN) -q profiles add smoke >/dev/null
	@$(HERMETIC) ./target/debug/$(BIN) -q auth status --profile smoke --json | grep -q '"authenticated": false' \
		|| { echo "smoke: a fresh profile reads as signed in"; exit 1; }
	@$(HERMETIC) ./target/debug/$(BIN) -q records export --profile smoke --ndjson >/dev/null 2>&1; \
		test $$? -eq 3 || { echo "smoke: an export with no session is not exit 3"; exit 1; }
	@for c in "auth login" "auth status" "auth logout" "auth reset" "profiles list" "profiles add" \
		"profiles remove" "orgs list" "patients list" "records export" "documents list" \
		"documents download" api info; do \
		./target/debug/$(BIN) $$c --help >/dev/null || exit 1; done
	@echo "smoke ok"

verify: fmt-check lint test smoke

define SIGN
if [ -x "$$HOME/Dev/cli-common/scripts/dev-sign.sh" ]; then \
	"$$HOME/Dev/cli-common/scripts/dev-sign.sh" "$(SIGN_TARGET)"; \
else echo "cli-common/scripts/dev-sign.sh not found — $(SIGN_TARGET) left ad-hoc signed"; fi
endef
