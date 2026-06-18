package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	PID     uint32
	Syscall uint32
	Type    uint32
	_       uint32
	Retval  int64
	Comm    [16]byte
}

var syscalls = map[uint32]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	7:   "poll",
	59:  "execve",
	257: "openat",
	16:  "ioctl",
	39:  "getpid",
}

func main() {

	var objs struct {
		Sys_enter *ebpf.Program `ebpf:"syscall_entry"`
		Sys_exit  *ebpf.Program `ebpf:"syscall_exit"`
		Events    *ebpf.Map     `ebpf:"events"`
	}

	var event Event
	spec, err := ebpf.LoadCollectionSpec("syscall.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF bytecode: %v", err)
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load maps and programs into kernel: %v", err)
	}
	defer objs.Sys_enter.Close()
	defer objs.Sys_exit.Close()
	defer objs.Events.Close()

	// sys_enter
	EnterLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.Sys_enter,
	})
	if err != nil {
		log.Fatalf("failed to attach Raw Enter Tracepoint: %v", err)
	}
	defer EnterLink.Close()
	fmt.Println("Successfully attached Entry Tracepoint")

	// sys_exit
	ExitLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: objs.Sys_exit,
	})
	if err != nil {
		log.Fatalf("failed to attach Raw Exit Tracepoint: %v", err)
	}
	defer ExitLink.Close()
	fmt.Println("Successfully attached Exit Tracepoint")

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

		if event.PID == uint32(os.Getpid()) {
			continue
		}
		switch event.Type {
		case 0:
			fmt.Printf("ENTER: %s(%d): %s\n", bytes.TrimRight(event.Comm[:], "\x00"), event.PID, syscalls[event.Syscall])
		case 1:
			fmt.Printf("EXIT: %s(%d): %s RET=%d\n", bytes.TrimRight(event.Comm[:], "\x00"), event.PID, syscalls[event.Syscall], event.Retval)
		}
	}
}
