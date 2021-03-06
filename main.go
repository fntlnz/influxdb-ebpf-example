package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"time"

	client "github.com/influxdata/influxdb/client/v2"
	bpf "github.com/iovisor/gobpf/bcc"
)

// This is the C source code of the eBPF program we are loading.
// The readline_event_t struct is 1:1 with the Go readlineEvent struct
// and we use it as data structure to populate the "readline_events"
// table created with BPF_PERF_OUTPUT.
// That table is pupulated using the events coming from the uretprobe loaded
// on the readline function symbol of the current program.
// That symbol returns a context that is passed to the get_return_value function
// and then after being validated the data is used to pupulate the readline_event_t struct
// and sent back using readline_events.perf_submit to userspace.
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

// This is our userspace struct 1:1 with the struct readline_event_t in the eBPF program.
type readlineEvent struct {
	Pid uint32
	Str [80]byte
}

func main() {
	// Here are some environment variables we need
	// in order to have this program working in the target system.
	// MONITOR_DATABASE is the name of the database to use for our data
	mdb := os.Getenv("MONITOR_DATABASE")
	// MONITOR_RP is the name of the retention policy to use for the data we are sending
	mrp := os.Getenv("MONITOR_RP")
	// MONITOR_HOST is the url of the target influxdb, e.g: https://influxdb.monitoring.svc.cluster.local:8086
	maddr := os.Getenv("MONITOR_HOST")
	// URETPROBE_BINARY is the path of the binary (or library) we want to analyze
	binaryName := os.Getenv("URETPROBE_BINARY")

	// Get the current node hostname
	hostname := os.Getenv("HOSTNAME")

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

	// This creates a new module to compile our eBPF code asynchronously
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	// This loads the uprobe program and sets the "get_return_value" as entrypoint
	readlineUretprobe, err := m.LoadUprobe("get_return_value")
	if err != nil {
		log.Fatalf("Failed to load get_return_value: %s", err)
	}

	// This attaches the uretprobe to the readline function of the passed binary.
	// This will consider every process (old and new) since we didn't specify the pid to look for.
	err = m.AttachUretprobe(binaryName, "readline", readlineUretprobe, -1)
	if err != nil {
		log.Fatalf("Failed to attach return_value: %s", err)
	}

	// This creates a new perf table "readline_events" to look to,
	// this must have the same name as the table defined in the eBPF progrma with BPF_PERF_OUTPUT.
	table := bpf.NewTable(m.TableId("readline_events"), m)

	// This channel will contain our results
	channel := make(chan []byte)

	// Link our channel with the perf table
	perfMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		log.Fatalf("Failed to init perf map: %s", err)
	}

	// Defined some handlers ot allow the user to kill the program
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	// Goroutine to handle the events
	go func() {
		var event readlineEvent
		for {
			// Create the influxdb client.
			bp, err := client.NewBatchPoints(client.BatchPointsConfig{
				Database:        mdb,
				RetentionPolicy: mrp,
			})
			if err != nil {
				log.Printf("%v", err)
				continue
			}

			// Get the current element from the channel
			data := <-channel

			// Read the data and populate the event struct
			err = binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("failed to decode received data: %s", err)
				continue
			}

			// Convert the C string to a Go string
			comm := string(event.Str[:bytes.IndexByte(event.Str[:], 0)])

			// Prepare the tags for InfluxDB
			tags := map[string]string{"uprobe": "readline", "hostname": hostname}

			// Prepare the fields for InfluxDB
			fields := map[string]interface{}{
				"pid":     event.Pid,
				"command": comm,
			}

			// Create the new point to write to InfluxDB
			pt, err := client.NewPoint("uprobe", tags, fields, time.Now())
			if err != nil {
				log.Printf("%v", err)
				continue
			}

			// Add the point to the batch
			bp.AddPoint(pt)

			// Write the batch
			if err := c.Write(bp); err != nil {
				log.Printf("%v", err)
				continue
			}
		}
	}()

	// Start reading
	perfMap.Start()
	// Wait to stop
	<-sig
	// Stop reading
	perfMap.Stop()
}
