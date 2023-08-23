#!/usr/bin/make
SHELL=/bin/bash -o pipefail
RED := \033[31m
GREEN := \033[32m
NC := \033[m
VERSION := $(shell git describe --abbrev=0)
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

protoc:
	@protoc --proto_path=protobuf --go_opt=paths=source_relative --go_out=pkg/agent --go_opt=Magent.proto=github.com/goten4/ucerts/agent agent.proto
	@protoc --proto_path=protobuf --go-grpc_opt=paths=source_relative --go-grpc_out=pkg/agent --go-grpc_opt=Magent.proto=github.com/goten4/ucerts/agent agent.proto

release:
	@read -p "Enter new release version (last release was $(VERSION)): " tag && \
	git tag -a $$tag -m "Release $$tag" && git push origin $$tag
	@unset GITLAB_TOKEN && goreleaser release --clean
