.PHONY: build buildimage

GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")
IMAGE := quay.io/fntlnz/influxdb-ebpf-example:$(GIT_BRANCH_CLEAN)

build:
	docker build -t $(IMAGE) .

