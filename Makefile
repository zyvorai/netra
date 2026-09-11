.PHONY: help build test bpf web helm-lint deploy-remote

help:
	@echo "Targets:"
	@echo "  make build          Build netrad, netractl, netra-agent"
	@echo "  make test           Run Go tests"
	@echo "  make bpf            Compile bpf/netra_tc.o (Linux + clang BPF)"
	@echo "  make web            Build React UI into web/dist"
	@echo "  make helm-lint      Helm lint + template (agent on/off)"
	@echo "  make deploy-remote H=host U=user   PacketWolf-style remote deploy"

build:
	go build -o bin/netrad ./cmd/netrad
	go build -o bin/netractl ./cmd/netractl
	go build -o bin/netra-agent ./cmd/netra-agent

test:
	go test ./...

bpf:
	clang -O2 -g -Wall -Wextra -Werror -target bpf -c bpf/netra_tc.c -o bpf/netra_tc.o

web:
	npm --prefix web install
	npm --prefix web run build

helm-lint:
	helm lint ./helm/netra
	helm template netra ./helm/netra >/dev/null
	helm template netra ./helm/netra --set agent.enabled=true >/dev/null

deploy-remote:
	./scripts/deploy-remote.sh $(U)@$(H)
