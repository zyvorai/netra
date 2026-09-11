.PHONY: test build web bpf fmt
fmt:
	gofmt -w cmd internal

test:
	go test ./...

build: web
	go build ./cmd/netrad ./cmd/netractl ./cmd/netra-agent ./cmd/netra-doctor

web:
	npm --prefix web install
	npm --prefix web run build

bpf:
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_tc.c -o bpf/netra_tc.o
