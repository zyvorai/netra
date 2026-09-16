.PHONY: test build web bpf fmt test-python
fmt:
	gofmt -w cmd internal

test:
	go test ./...

# Optional companion; no pip packages required for the linear runner.
test-python:
	PYTHONPATH=python python3 -m unittest discover -s python/tests -v

build: web
	go build ./cmd/netrad ./cmd/netractl ./cmd/netra-agent ./cmd/netra-doctor

web:
	npm --prefix web install
	npm --prefix web run build

bpf:
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_tc.c -o bpf/netra_tc.o
