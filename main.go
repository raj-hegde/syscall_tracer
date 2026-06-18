package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Event_entry struct {
	PID     uint32
	Syscall uint32
	Comm    [16]byte
}

func main() {

	var objs struct {
		Prog   *ebpf.Program `ebpf:"syscall_entry"`
		Events *ebpf.Map     `ebpf:"events"`
	}

	var event Event_entry
	spec, err := ebpf.LoadCollectionSpec("syscall.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF bytecode: %v", err)
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load maps and programs into kernel: %v", err)
	}
	defer objs.Prog.Close()
	defer objs.Events.Close()

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.Prog,
	})
	if err != nil {
		log.Fatalf("failed to attach Raw Tracepoint")
	}
	defer l.Close()
	fmt.Println("Successfully attached Raw Tracepoint")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			log.Fatal(err)
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}
		fmt.Printf("PID=%d COMM=%s SYSCALL=%d\n", event.PID, bytes.TrimRight(event.Comm[:], "\x00"), event.Syscall)
	}
}
