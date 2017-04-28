package strace

import "fmt"

var Debug = false

func dprintf(format string, a ...interface{}) (int, error) {
	if Debug {
		return fmt.Printf(format, a...)
	}
	return 0, nil
}
