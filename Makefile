.PHONY: all auto_remediation test

VERSION := $(shell git describe --exact-match --tags 2>/dev/null)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
COMMIT := $(shell git rev-parse --short HEAD)
LDFLAGS := $(LDFLAGS) -X main.commit=$(COMMIT) -X main.branch=$(BRANCH)
ifdef VERSION
    LDFLAGS += -X main.version=$(VERSION)
endif

all:
		$(MAKE) deps
		$(MAKE) auto_remediation

deps:
		go get -u golang.org/x/lint/golint
		go get -u github.com/golang/dep/cmd/dep
		dep ensure

auto_remediation:
		go build -ldflags "$(LDFLAGS)" ./cmd/auto_remediation

debug:
		dep ensure
		go build -race ./cmd/auto_remediation

test:
		go test -v -race -short -failfast ./...

linux:
		dep ensure
		GOOS=linux GOARCH=amd64 go build -o auto_remediation_linux ./cmd/auto_remediation
