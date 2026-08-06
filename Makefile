BINARY_NAME := oswbb-analyse
AI_BINARY_NAME := oswbb-analyse-ai
GOCACHE ?= /private/tmp/oswbb-ay-go-build
GOENV := GOCACHE=$(GOCACHE)
GO := go

.PHONY: build build-ai test clean

build:
	$(GOENV) $(GO) build -o $(BINARY_NAME) main.go

build-ai:
	$(GOENV) $(GO) build -o $(AI_BINARY_NAME) ./cmd/oswbb-analyse-ai

test:
	$(GOENV) $(GO) test ./...

clean:
	rm -f $(BINARY_NAME) $(AI_BINARY_NAME)
