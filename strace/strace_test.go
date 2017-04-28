package strace

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestAttach(t *testing.T) {
	proc, err := os.StartProcess("/bin/true", []string{"true"}, &os.ProcAttr{})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1 * time.Nanosecond)

	pid := proc.Pid
	err = Attach(pid)
	if err != nil {
		t.Errorf("Attach(%v) threw %v", pid, err)
	}

	err = Detach(pid)
	if err != nil {
		t.Fatal(err)
	}
	proc.Wait()
}

func TestExec(t *testing.T) {
	pid, err := Exec("/bin/true", []string{"true"})
	if err != nil {
		t.Errorf("Exec(/bin/true) threw %v", err)
	}

	time.Sleep(1 * time.Nanosecond)

	err = Detach(pid)
	if err != nil {
		t.Fatal(err)
	}
	var wstatus syscall.WaitStatus
	pid, err = syscall.Wait4(pid, &wstatus, syscall.WALL, nil)
	if err != nil {
		t.Fatal(err)
	}
}

type testHandler struct {
	f func(t *tracee)
}

func (h *testHandler) Handle(t *tracee) {
	h.f(t)
}

func TestTrace(t *testing.T) {
	_, err := Exec("/bin/true", []string{"true"})
	if err != nil {
		t.Errorf("Exec(/bin/true) threw %v", err)
	}

	time.Sleep(1 * time.Nanosecond)

	var state State
	Trace(&testHandler{
		f: func(t *tracee) {
			state = t.State
		}})
	if state != EXIT {
		t.Errorf("state: want %v, got: %v", EXIT, state)
	}
}
