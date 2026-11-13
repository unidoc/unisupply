package scanner

import (
	"os"
	"strconv"
	"strings"
)

// listChildProcesses reads /proc for the live (not zombie) processes whose parent is ppid.
func listChildProcesses(ppid int) ([]childProc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var procs []childProc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue // gone since the listing
		}
		if c, ok := parseProcStat(pid, string(stat), ppid); ok {
			procs = append(procs, c)
		}
	}
	return procs, nil
}

// parseProcStat reads a /proc/<pid>/stat line: "pid (comm) state ppid pgrp ...". comm can hold spaces and parentheses,
// so the fields are read after the last ")".
func parseProcStat(pid int, stat string, ppid int) (childProc, bool) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return childProc{}, false
	}
	f := strings.Fields(stat[i+1:])
	if len(f) < 3 || f[0] == "Z" || f[0] == "X" {
		return childProc{}, false
	}
	parent, err1 := strconv.Atoi(f[1])
	pgid, err2 := strconv.Atoi(f[2])
	if err1 != nil || err2 != nil || parent != ppid {
		return childProc{}, false
	}
	return childProc{pid: pid, pgid: pgid}, true
}
