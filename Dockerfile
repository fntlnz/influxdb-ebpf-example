# Example usage:
# docker run --net=host -v /sys:/sys:ro -v /lib/libreadline.so.7.0:/lib/libreadline.so.7.0:ro -v /lib/modules/$(uname -r)/build:/lib/modules/$(uname -r)/build:ro  --privileged --rm -it quay.io/fntlnz/influxdb-ebpf-example:master
FROM golang:1.11

RUN apt-get update -y
RUN apt install apt-transport-https ca-certificates -y
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
RUN echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | tee /etc/apt/sources.list.d/iovisor.list
RUN apt-get update
RUN apt-get install bcc-tools libbcc libbcc-examples linux-headers-4.9.0-8-common -y

ADD . /go/src/github.com/fntlnz/influxdb-ebpf-example
WORKDIR /go/src/github.com/fntlnz/influxdb-ebpf-example

RUN go build -a -tags netgo -ldflags '-w' -o /influxdb-ebpf-example .

ENTRYPOINT ["/influxdb-ebpf-example"]
