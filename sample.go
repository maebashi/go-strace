package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/maebashi/go-strace/strace"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -p pid / PROG [ARGS]\n", os.Args[0])
		flag.PrintDefaults()
	}
	optPid := flag.Int("p", 0, "trace process with process id PID")
	debug := flag.Bool("d", false, "")
	flag.Parse()
	strace.Debug = *debug

	/*strace.Options |= syscall.PTRACE_O_TRACECLONE |
		syscall.PTRACE_O_TRACEFORK |
		syscall.PTRACE_O_TRACEVFORK
	strace.DefaultTracer.FollowFork = true*/

	if *optPid != 0 {
		err := strace.Attach(*optPid)
		if err != nil {
			log.Fatalf("FindProcess: %v", err)
		}
	} else if flag.NArg() > 0 {
		_, err := strace.Exec(flag.Arg(0), flag.Args())
		if err != nil {
			log.Fatalf("Exec: %v", err)
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM)
	go func() { strace.Interrupt(<-sc) }()

	err := strace.Trace(nil)
	//err := strace.Trace(&strace.NullHandler{})
	if err != nil && err != syscall.ECHILD {
		log.Fatalf("ERROR: %v", err)
	}
}
