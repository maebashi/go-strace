package strace

import (
	"fmt"
	"log"
	"strings"
)

const bits_per_slot = 8 * 8

const (
	QUAL_TRACE   = 0x001
	QUAL_ABBREV  = 0x002
	QUAL_VERBOSE = 0x004
	QUAL_RAW     = 0x008
	QUAL_INJECT  = 0x010
	QUAL_SIGNAL  = 0x100
	QUAL_READ    = 0x200
	QUAL_WRITE   = 0x400
)

type numberSet struct {
	vec []uint
	not bool
}

func (s *numberSet) clear() {
	s.vec = []uint{}
	s.not = false
}

func (s *numberSet) nslots() uint {
	return uint(len(s.vec))
}

func (s *numberSet) String() string {
	a := make([]string, len(s.vec))
	for i := 0; i < len(s.vec); i++ {
		a[i] = fmt.Sprintf("0x%016x", s.vec[i])
	}
	return strings.Join(a, " ")
}

var traceSet = &numberSet{not: true}
var injectSet = &numberSet{}

func numberSetbit(i uint, vec []uint) {
	vec[i/bits_per_slot] |= uint(1 << (i % bits_per_slot))
}

func numberIsset(i uint, vec []uint) bool {
	return (vec[i/bits_per_slot] & uint(1<<(i%bits_per_slot))) != 0
}

func addNumberToSet(number uint, set *numberSet) {
	n := int(number/bits_per_slot + 1)
	if n > len(set.vec) {
		set.vec = append(set.vec, make([]uint, n-len(set.vec))...)
	}
	numberSetbit(number, set.vec)
}

func isNumberInSet(number uint, set *numberSet) bool {
	return ((number/bits_per_slot < set.nslots()) &&
		(numberIsset(number, set.vec))) != set.not
}

func qualifySyscallName(s string, set *numberSet) bool {
	var found bool
	for i := 0; i < len(syscallent); i++ {
		if syscallent[i].SysName != s {
			continue
		}
		addNumberToSet(uint(i), set)
		found = true
	}
	return found
}

func qualifySyscall(token string, set *numberSet) bool {
	return qualifySyscallName(token, set)
}

func qualifySyscallTokens(str string, set *numberSet, name string) {
	set.clear()
	for {
		for str[0] == '!' {
			set.not = !set.not
			str = str[1:]
		}
		if str == "none" {
			return
		} else if str == "all" {
			str = "!none"
			continue
		}
		break
	}
	for _, token := range strings.Split(str, ",") {
		if !qualifySyscall(token, set) {
			log.Fatalf("invalid %s '%s'", name, token)
		}
	}
}

func qualifyTrace(str string) {
	qualifySyscallTokens(str, traceSet, "system call")
}

func qualifyInjectCommon(str, description string) {
	qualifySyscallTokens(str, injectSet, description)
}

func qualifyFault(str string) {
	qualifyInjectCommon(str, "fault argument")
}
func qualifyInject(str string) {
	qualifyInjectCommon(str, "inject argument")
}

type qOptions struct {
	name    string
	qualify func(string)
}

var qualOptions = []qOptions{
	qOptions{"trace", qualifyTrace},
	qOptions{"t", qualifyTrace},
	qOptions{"fault", qualifyFault},
	qOptions{"inject", qualifyInject},
}

func Qualify(str string) {
	for i := 0; i < len(qualOptions); i++ {
		p := qualOptions[i].name
		ss := strings.SplitN(str, "=", 2)
		if p != ss[0] || len(ss) != 2 {
			continue
		}
		qualOptions[i].qualify(ss[1])
		break
	}
}

func qualFlags(scno int) int {
	res := 0
	if isNumberInSet(uint(scno), traceSet) {
		res |= QUAL_TRACE
	}
	if isNumberInSet(uint(scno), injectSet) {
		res |= QUAL_INJECT
	}
	return res
}
