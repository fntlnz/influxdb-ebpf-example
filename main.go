package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	client "github.com/influxdata/influxdb/client/v2"
	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
#include <uapi/linux/ptrace.h>

struct readline_event_t {
				u32 pid;
				char str[80];
} __attribute__((packed));

BPF_PERF_OUTPUT(readline_events);

int get_return_value(struct pt_regs *ctx) {
	struct readline_event_t event = {};
	u32 pid;
	if (!PT_REGS_RC(ctx)) {
		return 0;
	}
	pid = bpf_get_current_pid_tgid();
	event.pid = pid;
	bpf_probe_read(&event.str, sizeof(event.str), (void *)PT_REGS_RC(ctx));
	readline_events.perf_submit(ctx, &event, sizeof(event));

	return 0;
}
`

type readlineEvent struct {
	Pid uint32
	Str [80]byte
}

func main() {
	mdb := os.Getenv("MONITOR_DATABASE")
	mrp := os.Getenv("MONITOR_RP")
	maddr := os.Getenv("MONITOR_HOST")
	binaryName := os.Getenv("URETPROBE_BINARY")

	if len(mdb) == 0 {
		log.Fatalf("MONITOR_DATABASE environment variable missing")
	}

	if len(mrp) == 0 {
		log.Fatalf("MONITOR_RP environment variable missing")
	}

	if len(maddr) == 0 {
		log.Fatalf("MONITOR_HOST environment variable missing")
	}

	if len(binaryName) == 0 {
		binaryName = "/bin/bash"
	}

	c, err := client.NewHTTPClient(client.HTTPConfig{
		Addr: maddr,
	})

	if err != nil {
		log.Fatal(err)
	}
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	readlineUretprobe, err := m.LoadUprobe("get_return_value")
	if err != nil {
		log.Fatalf("Failed to load get_return_value: %s", err)
	}

	err = m.AttachUretprobe("/lib/libreadline.so.7.0", "readline", readlineUretprobe, -1)
	if err != nil {
		log.Fatalf("Failed to attach return_value: %s", err)
	}

	table := bpf.NewTable(m.TableId("readline_events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		log.Fatalf("Failed to init perf map: %s", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event readlineEvent
		for {
			bp, err := client.NewBatchPoints(client.BatchPointsConfig{
				Database:        mdb,
				RetentionPolicy: mrp,
			})
			if err != nil {
				log.Printf("%v", err)
				continue
			}

			data := <-channel
			err = binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("failed to decode received data: %s", err)
				continue
			}

			comm := string(event.Str[:bytes.IndexByte(event.Str[:], 0)])
			tags := map[string]string{"uprobe": "readline", "pid": fmt.Sprintf("%d", event.Pid)}
			fields := map[string]interface{}{
				"pid":     event.Pid,
				"command": comm,
			}

			pt, err := client.NewPoint("uprobe", tags, fields, time.Now())
			if err != nil {
				log.Printf("%v", err)
				continue
			}

			bp.AddPoint(pt)
			if err := c.Write(bp); err != nil {
				log.Printf("%v", err)
				continue
			}
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
