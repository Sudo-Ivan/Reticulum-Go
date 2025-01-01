GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=reticulum-go
BINARY_UNIX=$(BINARY_NAME)_unix

BUILD_DIR=bin

MAIN_PACKAGE=./cmd/reticulum-go

ALL_PACKAGES=$$(go list ./... | grep -v /vendor/)

.PHONY: all build clean test coverage deps help

all: clean deps build test

build: 
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

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

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)

build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)

build-all: build-linux build-windows build-darwin

run:
	@./$(BUILD_DIR)/$(BINARY_NAME)

install:
	$(GOMOD) download

help:
	@echo "Available targets:"
	@echo "  all          - Clean, download dependencies, build and test"
	@echo "  build        - Build binary"
	@echo "  clean        - Remove build artifacts"
	@echo "  test         - Run tests"
	@echo "  coverage     - Generate test coverage report"
	@echo "  deps         - Download dependencies"
	@echo "  build-linux  - Build for Linux"
	@echo "  build-windows- Build for Windows"
	@echo "  build-darwin - Build for MacOS"
	@echo "  build-all    - Build for all platforms"
	@echo "  run          - Run reticulum binary"
	@echo "  install      - Install dependencies" 