.PHONY: build buildimage

build:
	docker run -e GOPATH=/go --rm -v $$PWD:/go/src/github.com/fntlnz/influxdb-ebpf-example -w /go/src/github.com/fntlnz/influxdb-ebpf-example -it influxdb-ebpf-example go build .

buildimage:
	docker build -t influxdb-ebpf-example -f Dockerfile.build .

