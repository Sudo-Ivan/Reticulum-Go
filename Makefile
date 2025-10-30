GOCMD=go
GOBUILD=$(GOCMD) build
GOBUILD_EXPERIMENTAL=GOEXPERIMENT=greenteagc $(GOCMD) build
GOBUILD_RELEASE=CGO_ENABLED=0 $(GOCMD) build -ldflags="-s -w"
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=reticulum-go
BINARY_UNIX=$(BINARY_NAME)_unix

BUILD_DIR=bin

MAIN_PACKAGE=./cmd/reticulum-go

ALL_PACKAGES=$$(go list ./... | grep -v /vendor/)

.PHONY: all build build-experimental experimental release lint bench bench-experimental bench-compare clean test coverage deps help tinygo-build tinygo-wasm

all: clean deps build test

build:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

build-experimental:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD_EXPERIMENTAL) -o $(BUILD_DIR)/$(BINARY_NAME)-experimental $(MAIN_PACKAGE)

experimental: build-experimental

release:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD_RELEASE) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

lint:
	revive -config revive.toml -formatter friendly ./pkg/* ./cmd/* ./internal/*

bench:
	$(GOTEST) -bench=. -benchmem ./...

bench-experimental:
	GOEXPERIMENT=greenteagc $(GOTEST) -bench=. -benchmem ./...

bench-compare: bench bench-experimental

clean:
	@rm -rf $(BUILD_DIR)
	$(GOCLEAN)

test:
	$(GOTEST) -v $(ALL_PACKAGES)

coverage:
	$(GOTEST) -coverprofile=coverage.out $(ALL_PACKAGES)
	$(GOCMD) tool cover -html=coverage.out

deps:
	$(GOMOD) download
	$(GOMOD) verify

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm $(MAIN_PACKAGE)

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-arm64.exe $(MAIN_PACKAGE)

build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_PACKAGE)

build-freebsd:
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-freebsd-amd64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=386 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-freebsd-386 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-freebsd-arm64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-freebsd-arm $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=riscv64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-freebsd-riscv64 $(MAIN_PACKAGE)

build-openbsd:
	CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-openbsd-amd64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=386 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-openbsd-386 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-openbsd-arm64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=arm $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-openbsd-arm $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=ppc64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-openbsd-ppc64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=riscv64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-openbsd-riscv64 $(MAIN_PACKAGE)

build-netbsd:
	CGO_ENABLED=0 GOOS=netbsd GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-netbsd-amd64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=netbsd GOARCH=386 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-netbsd-386 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=netbsd GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-netbsd-arm64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=netbsd GOARCH=arm $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-netbsd-arm $(MAIN_PACKAGE)

build-arm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-arm $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-arm64 $(MAIN_PACKAGE)

build-riscv:
	CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-riscv64 $(MAIN_PACKAGE)

build-all: build-linux build-windows build-darwin build-freebsd build-openbsd build-netbsd build-arm build-riscv

run:
	@./$(BUILD_DIR)/$(BINARY_NAME)

tinygo-build:
	@mkdir -p $(BUILD_DIR)
	tinygo build -o $(BUILD_DIR)/$(BINARY_NAME)-tinygo -size short $(MAIN_PACKAGE)

tinygo-wasm:
	@mkdir -p $(BUILD_DIR)
	tinygo build -target wasm -o $(BUILD_DIR)/$(BINARY_NAME).wasm $(MAIN_PACKAGE)

install:
	$(GOMOD) download

help:
	@echo "Available targets:"
	@echo "  all                - Clean, download dependencies, build and test"
	@echo "  build              - Build binary"
	@echo "  build-experimental - Build binary with experimental features (GOEXPERIMENT=greenteagc)"
	@echo "  experimental       - Alias for build-experimental"
	@echo "  release            - Build stripped static binary for release"
	@echo "  lint               - Run revive linter"
	@echo "  bench              - Run benchmarks with standard GC"
	@echo "  bench-experimental - Run benchmarks with experimental GC"
	@echo "  bench-compare      - Run benchmarks with both GC settings"
	@echo "  clean              - Remove build artifacts"
	@echo "  test               - Run tests"
	@echo "  coverage           - Generate test coverage report"
	@echo "  deps               - Download dependencies"
	@echo "  build-linux  - Build for Linux (amd64, arm64, arm)"
	@echo "  build-windows- Build for Windows (amd64, arm64)"
	@echo "  build-darwin - Build for MacOS (amd64, arm64)"
	@echo "  build-freebsd- Build for FreeBSD (amd64, 386, arm64, arm, riscv64)"
	@echo "  build-openbsd- Build for OpenBSD (amd64, 386, arm64, arm, ppc64, riscv64)"
	@echo "  build-netbsd - Build for NetBSD (amd64, 386, arm64, arm)"
	@echo "  build-arm    - Build for ARM architectures (arm, arm64)"
	@echo "  build-riscv  - Build for RISC-V architecture (riscv64)"
	@echo "  build-all    - Build for all platforms and architectures"
	@echo "  run          - Run reticulum binary"
	@echo "  tinygo-build - Build binary with TinyGo compiler"
	@echo "  tinygo-wasm  - Build WebAssembly binary with TinyGo compiler"
	@echo "  install      - Install dependencies" 