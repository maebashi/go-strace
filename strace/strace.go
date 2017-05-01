package strace

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
)

const (
	TCB_STARTUP                   = 0x01
	TCB_IGNORE_ONE_SIGSTOP        = 0x02
	TCB_INSYSCALL                 = 0x04
	TCB_ATTACHED                  = 0x08
	TCB_REPRINT                   = 0x10
	TCB_FILTERED                  = 0x20
	TCB_TAMPERED                  = 0x40
	TCB_HIDE_LOG                  = 0x80
	TCB_SKIP_DETACH_ON_FIRST_EXEC = 0x100
)

var Options int = syscall.PTRACE_O_TRACESYSGOOD |
	syscall.PTRACE_O_TRACEEXEC |
	syscall.PTRACE_O_TRACEEXIT

type State int

const (
	UNKNOWN State = iota
	SYSCALL_ENTER_STOP
	SYSCALL_EXIT_STOP
	EXIT
)

type Handler interface {
	Handle(t *tracee)
}

type SimplePrint struct{}

var DefaultHandler Handler = &SimplePrint{}

func (*SimplePrint) Handle(t *tracee) {
	switch t.State {
	case SYSCALL_ENTER_STOP:
		tprintf("%s(", t.s_ent.SysName)
		print_syscall_args(t)
		tprintf(") = ")
	case SYSCALL_EXIT_STOP:
		tprintf("%d\n", t.result)
	case EXIT:
		tprintf("Child(%d) exit with status %v\n", t.Pid, t.ExitStatus)
	}
}

type NullHandler struct{}

func (*NullHandler) Handle(t *tracee) {}

func tprintf(format string, a ...interface{}) (int, error) {
	return fmt.Fprintf(os.Stderr, format, a...)
}

type tracee struct {
	Pid   int
	State State

	ExitStatus int

	flags  int
	u_arg  [MAX_ARGS]uint64
	s_ent  *sysent
	result int
}

type tracer struct {
	FollowFork bool

	h           Handler
	fc          chan func()
	ec          chan error
	nprocs      int
	interrupted os.Signal
	table       map[int]*tracee
	child       int
}

var DefaultTracer = &tracer{}

func print_syscall_args(t *tracee) {
	nargs := t.s_ent.Nargs
	for i := 0; i < int(nargs); i++ {
		arg := t.u_arg[i]
		typ := t.s_ent.ArgTypes[i]
		switch typ {
		case ARG_INT:
			tprintf("%d", arg)
		case ARG_STR:
			strval := read_string(t.Pid, arg)
			tprintf("%q", strval)
		default:
			tprintf("0x%x", arg)
		}
		if i != int(nargs-1) {
			tprintf(", ")
		}
	}
}

func (tracer *tracer) traceSyscallEntering(t *tracee, regs *syscall.PtraceRegs) {
	t.State = SYSCALL_ENTER_STOP
	t.get_scno(regs)
	t.get_syscall_args(regs)
	tracer.h.Handle(t)

	t.flags |= TCB_INSYSCALL
}

func (tracer *tracer) traceSyscallExiting(t *tracee, regs *syscall.PtraceRegs) {
	t.State = SYSCALL_EXIT_STOP
	t.get_syscall_args(regs)
	if true {
		t.result = int(regs.Rax)
		tracer.h.Handle(t)
	}
	t.flags &= ^TCB_INSYSCALL
}

func (tracer *tracer) traceSyscall(t *tracee, regs *syscall.PtraceRegs) {
	if (t.flags & TCB_INSYSCALL) > 0 {
		tracer.traceSyscallExiting(t, regs)
	} else {
		tracer.traceSyscallEntering(t, regs)
	}
}

func (tracer *tracer) start() {
	if tracer.fc != nil {
		return
	}
	tracer.fc = make(chan func())
	tracer.ec = make(chan error)
	tracer.table = map[int]*tracee{}
	go func() {
		runtime.LockOSThread()
		tracer.loop()
	}()
}

func (tracer *tracer) loop() {
	for {
		select {
		case f := <-tracer.fc:
			f()
		}
	}
}

func fork() (int, syscall.Errno) {
	cloneflags := 0
	r1, _, err1 := syscall.RawSyscall6(syscall.SYS_CLONE,
		uintptr(syscall.SIGCHLD)|uintptr(cloneflags), 0, 0, 0, 0, 0)
	if err1 != 0 {
		return 0, err1
	}
	pid := int(r1)
	return pid, 0
}

func (tracer *tracer) Exec(name string, argv []string) (int, error) {
	tracer.start()
	tracer.nprocs++
	pc := make(chan int)
	tracer.fc <- func() {
		pid, errno := fork()
		if errno != 0 {
			tracer.ec <- errno
			return
		}

		if pid == 0 {
			_, _, errno = syscall.RawSyscall(syscall.SYS_PTRACE,
				uintptr(syscall.PTRACE_TRACEME), 0, 0)
			if errno != 0 {
				log.Fatalf("child error %v", errno)
			}
			err := syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)
			if err != nil {
				log.Fatalf("sigstop error %v", errno)
			}

			path, err := exec.LookPath(name)
			if err != nil {
				log.Fatalf("LookPath error: %v", err)
			}
			err = syscall.Exec(path, argv, os.Environ())
			if err != nil {
				log.Fatalf("Exec error: %v", err)
			}
		}

		flags := TCB_STARTUP | TCB_ATTACHED | TCB_HIDE_LOG
		tracer.table[pid] = &tracee{Pid: pid, flags: flags}
		tracer.child = pid

		pc <- pid
		tracer.ec <- nil
	}
	return <-pc, <-tracer.ec
}

func (tracer *tracer) Attach(pid int) error {
	tracer.start()
	tracer.nprocs++
	tracer.fc <- func() {
		_, err := os.FindProcess(pid)
		if err != nil {
			tracer.ec <- err
			return
		}
		tracer.ec <- tracer.attach(pid)
	}
	return <-tracer.ec
}

func (tracer *tracer) attach(pid int) error {
	err := syscall.PtraceAttach(pid)
	if err != nil {
		return err
	}
	flags := TCB_STARTUP | TCB_ATTACHED
	tracer.table[pid] = &tracee{Pid: pid, flags: flags}
	dprintf("attach(%d) (main)\n", pid)
	if tracer.FollowFork {
		procdir := fmt.Sprintf("/proc/%d/task", pid)
		fis, err := ioutil.ReadDir(procdir)
		if err != nil {
			return nil
		}
		for _, fi := range fis {
			tid, err := strconv.Atoi(fi.Name())
			if err != nil || tid == pid {
				continue
			}
			err = syscall.PtraceAttach(tid)
			if err != nil {
				log.Printf("PtraceAttach(%d): %v", tid, err)
				continue
			}
			tracer.table[tid] = &tracee{Pid: tid, flags: flags}
			dprintf("attach(%d)\n", tid)
		}
	}
	return nil
}

func (tracer *tracer) Detach(pid int) error {
	tracer.start()
	tracer.fc <- func() {
		tracer.ec <- tracer.detach(pid)
	}
	tracer.nprocs--
	return <-tracer.ec
}

func (tracer *tracer) detach(pid int) error {
	err := syscall.PtraceDetach(pid)
	dprintf("detach(%d)\n", pid)
	return err
}

func (tracer *tracer) Interrupt(sig os.Signal) {
	tracer.interrupted = sig
	for pid, t := range tracer.table {
		if t.State == EXIT {
			continue
		}
		syscall.Kill(pid, syscall.SIGSTOP)
	}
}

func (tracer *tracer) Trace(h Handler) error {
	tracer.start()
	if h == nil {
		h = DefaultHandler
	}
	tracer.h = h
	f := func() { tracer.ec <- tracer.trace(h) }
	defer tracer.cleanup()
	for tracer.nprocs > 0 {
		tracer.fc <- f
		err := <-tracer.ec
		if err != nil {
			return err
		}
		if tracer.interrupted != nil {
			return nil
		}
	}
	return nil
}

func ptrace_restart(op int, pid int, sig int) error {
	var err error
	switch op {
	case syscall.PTRACE_SYSCALL:
		err = syscall.PtraceSyscall(pid, sig)
	case syscall.PTRACE_CONT:
		err = syscall.PtraceCont(pid, sig)
	case syscall.PTRACE_DETACH:
		err = syscall.PtraceDetach(pid)
	default:
		err = errors.New("restart error")
	}
	return err
}

func (tracer *tracer) cleanup() {
	for pid, t := range tracer.table {
		if t.State == EXIT {
			continue
		}

		if (pid == tracer.child) || (tracer.child == 0) {
			err := syscall.Kill(pid, syscall.SIGCONT)
			if err != nil {
				log.Printf("SIGCONT %d: %v", pid, err)
			}
		}

		tracer.fc <- func() {
			tracer.ec <- tracer.detach(pid)
		}
		if err := <-tracer.ec; err != nil {
			if err != syscall.ESRCH {
				log.Printf("PtraceDetach(%d): %v", pid, err)
			}
		}
	}
}

func (tracer *tracer) trace(h Handler) error {
	var wstatus syscall.WaitStatus
	pid, err := syscall.Wait4(-1, &wstatus, syscall.WALL, nil)
	if err != nil {
		return err
	}
	if tracer.interrupted != nil {
		return nil
	}

	t, ok := tracer.table[pid]
	if !ok {
		if tracer.FollowFork {
			t = &tracee{
				Pid:   pid,
				flags: TCB_STARTUP | TCB_ATTACHED,
			}
			tracer.table[pid] = t
			tracer.nprocs++
		} else {
			log.Printf("pid %d not found", pid)
			return syscall.PtraceCont(pid, 0)
		}
	}

	event := wstatus >> 16
	if event == syscall.PTRACE_EVENT_EXEC {
	}

	if wstatus.Signaled() {
	}

	if wstatus.Exited() {
		t.State = EXIT
		t.ExitStatus = wstatus.ExitStatus()
		tracer.h.Handle(t)
		tracer.nprocs--
		return nil
	}

	var regs syscall.PtraceRegs
	if wstatus.Stopped() {
		err = syscall.PtraceGetRegs(pid, &regs)
		if err != nil {
			log.Printf("get regs err %v", err)
			return err
		}
	}

	if t.flags&TCB_STARTUP > 0 {
		err = syscall.PtraceSetOptions(t.Pid, Options)
		if err != nil {
			if err != syscall.ESRCH {
				log.Printf("setoptions(%d) err: %v", t.Pid, err)
				return err
			}
		}
		err = t.get_scno(&regs)
		if err != nil {
			log.Printf("get_scno error: %v", err)
			return err
		}
		t.flags &= ^TCB_STARTUP
	}

	sig := wstatus.StopSignal()
	if sig == syscall.SIGSTOP {
		err := ptrace_restart(syscall.PTRACE_SYSCALL, pid, 0)
		if err != nil {
			log.Printf("err %v", err)
			return err
		}
		return nil
	}

	if sig != (syscall.SIGTRAP | 0x80) {
		err := ptrace_restart(syscall.PTRACE_SYSCALL, pid, int(sig))
		if err != nil {
			if err == syscall.ESRCH {
				delete(tracer.table, pid)
				return nil
			}
			return err
		}
		return nil
	}

	tracer.traceSyscall(t, &regs)
	syscall.PtraceSyscall(pid, 0)
	return nil
}

func Exec(name string, argv []string) (int, error) {
	return DefaultTracer.Exec(name, argv)
}

func Attach(pid int) error {
	return DefaultTracer.Attach(pid)
}

func Detach(pid int) error {
	return DefaultTracer.Detach(pid)
}

func Trace(h Handler) error {
	return DefaultTracer.Trace(h)
}

func Interrupt(sig os.Signal) {
	DefaultTracer.Interrupt(sig)
}
