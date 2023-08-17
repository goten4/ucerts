#!/usr/bin/make
SHELL=/bin/bash -o pipefail
RED := \033[31m
GREEN := \033[32m
NC := \033[m
VERSION = v0.1.0
BUILD_TIME ?= $(shell date +%FT%T%z)
GO_TEST_FLAGS ?= -race
GO_BUILD_FLAGS += -tags timetzdata
GO_BUILD_LDFLAGS += -s -w -X 'github.com/goten4/ucerts/internal/build.Version=$(VERSION)' -X 'github.com/goten4/ucerts/internal/build.BuiltAt=$(BUILD_TIME)'

clean:
	@go clean ./... || (echo -e "$(RED)clean failed$(NC)" && exit 1)
	@echo -e "$(GREEN)clean OK$(NC)"

test:
	@go test $(GO_TEST_FLAGS) ./... || (echo -e "$(RED)tests failed$(NC)" && exit 1)
	@echo -e "$(GREEN)tests OK$(NC)"

build:
	@CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -ldflags "all=$(GO_BUILD_LDFLAGS)"
	@echo -e "$(GREEN)build OK$(NC)"

cover: override GO_TEST_FLAGS += -coverprofile=coverage.out
cover: test
	@go tool cover -html=coverage.out &

release:
	@unset GITLAB_TOKEN && goreleaser release --clean
