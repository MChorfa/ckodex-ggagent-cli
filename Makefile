export CARGO_TARGET_DIR := $(CURDIR)/target

.PHONY: all build release test clippy fmt doctor clean playground

all: fmt clippy test build

build:
	cargo build --workspace

release:
	cargo build --workspace --release
	mkdir -p bin
	@TARGET_DIR=$$(cargo metadata --format-version 1 2>/dev/null | grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4); \
	if [ -n "$$TARGET_DIR" ] && [ -f "$$TARGET_DIR/release/ggagent" ]; then \
		cp "$$TARGET_DIR/release/ggagent" ./bin/ggagent; \
	elif [ -f "target/release/ggagent" ]; then \
		cp "target/release/ggagent" ./bin/ggagent; \
	else \
		find target -name "ggagent" -type f -perm +111 -exec cp {} ./bin/ggagent \; 2>/dev/null || true; \
	fi
	@chmod +x ./bin/ggagent
	@echo "Built release binary at ./bin/ggagent"

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --check

fmt-fix:
	cargo fmt

doctor: release
	./bin/ggagent doctor

playground: release
	./bin/ggagent playground --port 8080

clean:
	cargo clean
	rm -rf bin
