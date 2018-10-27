#!/usr/bin/env bash

docker run --name=influxdb -d -p 8086:8086 -p 8888:8888 quay.io/influxdb/influxdb:nightly
docker run --net=container:influxdb -d --name=chronograf quay.io/influxdb/chronograf:nightly

docker exec -ti influxdb sh -c "influx -execute 'create database uprobe'"
sudo ./influxdb-ebpf-example

