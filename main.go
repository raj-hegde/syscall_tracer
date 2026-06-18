package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Event struct {
	PID     uint32
	Syscall uint32
	Comm    [16]byte
}

func main() {

	var objs struct {
		Prog   *ebpf.Program `ebpf:"trace_syscall"`
		Events *ebpf.Map     `ebpf:"events"`
	}

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
}
