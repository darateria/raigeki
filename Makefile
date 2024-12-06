include .env
export

.PHONY: run
run:
	RUST_LOG=debug cargo run
