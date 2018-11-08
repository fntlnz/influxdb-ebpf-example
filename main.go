package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	client "github.com/influxdata/influxdb/client/v2"
	bpf "github.com/iovisor/gobpf/bcc"
)

type EventType int32

const (
	eventArg EventType = iota
	eventRet
)

const source string = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#define ARGSIZE  128
enum event_type {
    EVENT_ARG,
    EVENT_RET,
};
struct data_t {
    u64 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};
BPF_PERF_OUTPUT(events);
static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}
static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the getPpid function as a fallback in those cases.
    // See https://github.com/iovisor/bcc/issues/1883.
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;
    __submit_arg(ctx, (void *)filename, &data);
    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAX_ARGS; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}
int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the getPpid function as a fallback in those cases.
    // See https://github.com/iovisor/bcc/issues/1883.
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
`

type execveEvent struct {
	Pid    uint64
	Ppid   uint64
	Comm   [16]byte
	Type   int32
	Argv   [128]byte
	RetVal int32
}

type eventPayload struct {
	Time   string `json:"time,omitempty"`
	Comm   string `json:"comm"`
	Pid    uint64 `json:"pid"`
	Ppid   string `json:"ppid"`
	Argv   string `json:"argv"`
	RetVal int32  `json:"retval"`
}

// getPpid is a fallback to read the parent PID from /proc.
// Some kernel versions, like 4.13.0 return 0 getting the parent PID
// from the current task, so we need to use this fallback to have
// the parent PID in any kernel.
func getPpid(pid uint64) uint64 {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/status", pid), os.O_RDONLY, os.ModePerm)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		text := sc.Text()
		if strings.Contains(text, "PPid:") {
			f := strings.Fields(text)
			i, _ := strconv.ParseUint(f[len(f)-1], 10, 64)
			return i
		}
	}
	return 0
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

	c, err := client.NewHTTPClient(client.HTTPConfig{
		Addr: maddr,
	})

	if err != nil {
		log.Fatal(err)
	}

	// This creates a new module to compile our eBPF code asynchronously
	m := bpf.NewModule(strings.Replace(source, "MAX_ARGS", strconv.FormatUint(20, 10), -1), []string{})
	defer m.Close()

	fnName := bpf.GetSyscallFnName("execve")

	kprobe, err := m.LoadKprobe("syscall__execve")
	if err != nil {
		log.Fatalf("Failed to load syscall__execve: %s", err)
	}

	if err := m.AttachKprobe(fnName, kprobe); err != nil {
		log.Fatalf("Failed to attach syscall__execve: %s", err)
	}

	kretprobe, err := m.LoadKprobe("do_ret_sys_execve")
	if err != nil {
		log.Fatalf("Failed to load do_ret_sys_execve: %s", err)
	}

	if err := m.AttachKretprobe(fnName, kretprobe); err != nil {
		log.Fatalf("Failed to attach do_ret_sys_execve: %s", err)
	}

	// This creates a new perf table "execve_events" to look to,
	// this must have the same name as the table defined in the eBPF progrma with BPF_PERF_OUTPUT.
	table := bpf.NewTable(m.TableId("events"), m)

	// This channel will contain our results
	channel := make(chan []byte, 1000)

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
		var event execveEvent
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
			err = binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
			if err != nil {
				log.Printf("failed to decode received data: %s", err)
				continue
			}

			// Convert the C string to a Go string
			argv := string(event.Argv[:bytes.IndexByte(event.Argv[:], 0)])
			comm := string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)])
			// Prepare the tags for InfluxDB
			tags := map[string]string{"krpobe": "execve", "hostname": hostname}

			// Prepare the fields for InfluxDB
			fields := map[string]interface{}{
				"argv":   argv,
				"comm":   comm,
				"retval": event.RetVal,
				"pid":    fmt.Sprintf("%d", event.Pid),
			}

			// Create the new point to write to InfluxDB
			pt, err := client.NewPoint("kprobe", tags, fields, time.Now())
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
