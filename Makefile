.PHONY: all auto_remediation test

VERSION := $(shell git describe --exact-match --tags 2>/dev/null)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
COMMIT := $(shell git rev-parse --short HEAD)
LDFLAGS := $(LDFLAGS) -X main.commit=$(COMMIT) -X main.branch=$(BRANCH)
ifdef VERSION
    LDFLAGS += -X main.version=$(VERSION)
endif

all:
		$(MAKE) auto_remediation

auto_remediation:
		go build -mod=vendor -ldflags "$(LDFLAGS)" ./cmd/auto_remediation

debug:
		go build -mod=vendor -race ./cmd/auto_remediation

test:
		go test -v -mod=vendor -race -short -failfast ./...

linux:
		GOOS=linux GOARCH=amd64 go build -mod=vendor -o auto_remediation_linux ./cmd/auto_remediation
