package strace

import (
	"bytes"
	"errors"
	"syscall"
)

func ReadString(pid int, addr uint64) string {
	val := []byte{}
	b := make([]byte, 4)
	var read uint64 = 0

	for {
		count, err := syscall.PtracePeekData(pid, uintptr(addr+read), b)
		if err != nil {
			return ""
		}
		read += uint64(count)
		if ind := bytes.IndexByte(b, 0); ind >= 0 {
			val = append(val, b[0:ind]...)
			break
		} else {
			val = append(val, b...)
		}
	}
	return string(val)
}

func (t *Tracee) get_scno(regs *syscall.PtraceRegs) error {
	scno := int(regs.Orig_rax)
	if scno > len(syscallent) {
		return errors.New("error")
	}
	t.s_ent = &syscallent[scno]
	t.qual_flg = qualFlags(scno)
	return nil
}

func (t *Tracee) get_syscall_args(regs *syscall.PtraceRegs) error {
	t.u_arg[0] = regs.Rdi
	t.u_arg[1] = regs.Rsi
	t.u_arg[2] = regs.Rdx
	t.u_arg[3] = regs.R10
	t.u_arg[4] = regs.R8
	t.u_arg[5] = regs.R9

	return nil
}

func (t *Tracee) set_error() {
}
