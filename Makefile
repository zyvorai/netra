.PHONY: test build web bpf fmt test-python test-tlsfp test-p1-p5
fmt:
	gofmt -w cmd internal

test:
	go test ./...

test-tlsfp:
	./scripts/ci-tlsfp-unit.sh

test-p1-p5:
	./scripts/ci-p1-p5-unit.sh

# Optional companion; no pip packages required for the linear runner.
test-python:
	PYTHONPATH=python python3 -m unittest discover -s python/tests -v

build: web
	go build ./cmd/netrad ./cmd/netractl ./cmd/netra-agent ./cmd/netra-doctor

web:
	npm --prefix web install
	npm --prefix web run build

bpf:
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -mllvm -bpf-stack-size=1024 -c bpf/netra_tc.c -o bpf/netra_tc.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_edge_intel.c -o bpf/netra_edge_intel.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_capture.c -o bpf/netra_capture.o
	clang -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/$(shell uname -m)-linux-gnu -c bpf/netra_tlsfp.c -o bpf/netra_tlsfp.o
