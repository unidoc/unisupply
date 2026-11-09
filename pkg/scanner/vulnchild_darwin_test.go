package scanner

import "golang.org/x/sys/unix"

// processZombie reports whether pid has exited and waits to be reaped.
func processZombie(pid int) bool {
	p, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	return err == nil && p.Proc.P_stat == darwinZombie
}
