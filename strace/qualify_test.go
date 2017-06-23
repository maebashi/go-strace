package strace

import "testing"

func TestNumberSet(t *testing.T) {
	set := &numberSet{}
	if set.nslots() != 0 {
		t.Errorf("want: 0, got: %v", set.nslots())
	}
	addNumberToSet(100, set)
	if !numberIsset(100, set.vec) {
		t.Errorf("bit %d not set", 100)
	}
	if set.nslots() != 2 {
		t.Errorf("want: 2, got: %v", set.nslots())
	}
	addNumberToSet(500, set)
	if set.nslots() != 8 {
		t.Errorf("want: 8, got: %v", set.nslots())
	}
}

func TestQualifySyscall(t *testing.T) {
	set := &numberSet{}
	qualifySyscallTokens("stat,pause", set, "system call")
	if isNumberInSet(1, set) {
		t.Errorf("bit %d set", 1)
	}
	if !isNumberInSet(4, set) {
		t.Errorf("bit %d not set", 4)
	}
	if !isNumberInSet(34, set) {
		t.Errorf("bit %d not set", 34)
	}

	qualifySyscallTokens("!stat", set, "system call")
	if !isNumberInSet(1, set) {
		t.Errorf("bit %d not set", 1)
	}
	if isNumberInSet(4, set) {
		t.Errorf("bit %d set", 4)
	}
	if !isNumberInSet(34, set) {
		t.Errorf("bit %d not set", 34)
	}

	qualifySyscallTokens("all", set, "system call")
	for i := 0; i < len(syscallent); i++ {
		if !isNumberInSet(uint(i), set) {
			t.Errorf("bit %d not set", i)
		}
	}
	qualifySyscallTokens("none", set, "system call")
	for i := 0; i < len(syscallent); i++ {
		if isNumberInSet(uint(i), set) {
			t.Errorf("bit %d set", i)
		}
	}
}

func TestQualify(t *testing.T) {
	Qualify("trace=stat,pause")
	if isNumberInSet(1, traceSet) {
		t.Errorf("bit %d set", 1)
	}
	if !isNumberInSet(4, traceSet) {
		t.Errorf("bit %d not set", 4)
	}
}
