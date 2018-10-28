.PHONY: build buildimage

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
GIT_COMMIT := $(if $(shell git status --porcelain --untracked-files=no),"${COMMIT_NO}-dirty","${COMMIT_NO}")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")
IMAGE := quay.io/fntlnz/influxdb-ebpf-example:$(GIT_BRANCH_CLEAN)
COMMIT_IMAGE := quay.io/fntlnz/influxdb-ebpf-example:$(GIT_COMMIT)

build:
	docker build -t $(IMAGE) .
	docker tag $(IMAGE) $(COMMIT_IMAGE)

push:
	docker push $(IMAGE)
	docker push $(COMMIT_IMAGE)

