package scanner

import "golang.org/x/sys/unix"

// darwinZombie is SZOMB in <sys/proc.h>: a process that has exited and waits to be reaped.
const darwinZombie = 5

// listChildProcesses asks the kernel (kern.proc.all) for the live (not zombie) processes whose parent is ppid.
func listChildProcesses(ppid int) ([]childProc, error) {
	all, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	var procs []childProc
	for i := range all {
		p := &all[i]
		if int(p.Eproc.Ppid) != ppid || p.Proc.P_stat == darwinZombie {
			continue
		}
		procs = append(procs, childProc{pid: int(p.Proc.P_pid), pgid: int(p.Eproc.Pgid)})
	}
	return procs, nil
}
