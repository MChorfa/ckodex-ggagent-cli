.PHONY: all build release test clippy fmt doctor clean playground

all: fmt clippy test build

build:
	cargo build --workspace

release:
	cargo build --workspace --release
	mkdir -p bin
	cp /Users/mchorfa/.cache/cargo-target/release/ggagent ./bin/ggagent

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
