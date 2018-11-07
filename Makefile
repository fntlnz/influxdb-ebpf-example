.PHONY: image/build image/push build

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
GIT_COMMIT := $(if $(shell git status --porcelain --untracked-files=no),"${COMMIT_NO}-dirty","${COMMIT_NO}")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")
IMAGE := quay.io/fntlnz/influxdb-ebpf-example:$(GIT_BRANCH_CLEAN)
COMMIT_IMAGE := quay.io/fntlnz/influxdb-ebpf-example:$(GIT_COMMIT)
LDFLAGS ?= -ldflags '-w'
BUILDFLAGS ?= -a -tags netgo
OUTPUTFLAGS ?= -o influxdb-epbf-example
GO ?= go
DOCKER ?= docker

build:
	GO111MODULE=on $(GO) build $(BUILDFLAGS) $(LDFLAGS) $(OUTPUTFLAGS) .

image/build:
	$(DOCKER) build -t $(IMAGE) .
	$(DOCKER) tag $(IMAGE) $(COMMIT_IMAGE)

image/push:
	$(DOCKER) push $(IMAGE)
	$(DOCKER) push $(COMMIT_IMAGE)

