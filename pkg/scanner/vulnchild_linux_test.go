package scanner

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// processZombie reports whether pid has exited and waits to be reaped.
func processZombie(pid int) bool {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(stat)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	return len(f) > 0 && f[0] == "Z"
}

func TestParseProcStat(t *testing.T) {
	cases := []struct {
		name, stat string
		want       childProc
		ok         bool
	}{
		{"go list", "4242 (go) S 100 4242 100 0 -1", childProc{pid: 4242, pgid: 4242}, true},
		{"comm with spaces and parens", "4243 (a) b (c) R 100 77 100 0", childProc{pid: 4243, pgid: 77}, true},
		{"zombie", "4244 (go) Z 100 4244 100", childProc{}, false},
		{"another parent", "4245 (go) S 101 4245 101", childProc{}, false},
		{"cut short", "4246 (go) S", childProc{}, false},
		{"no comm", "4247 go S 100 4247", childProc{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var pid int
			for _, r := range c.stat {
				if r < '0' || r > '9' {
					break
				}
				pid = pid*10 + int(r-'0')
			}
			got, ok := parseProcStat(pid, c.stat, 100)
			if ok != c.ok || got != c.want {
				t.Errorf("parseProcStat = %+v, %v; want %+v, %v", got, ok, c.want, c.ok)
			}
		})
	}
}
