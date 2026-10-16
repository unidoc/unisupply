package report

import (
	"testing"

	"github.com/unidoc/unisupply/pkg/scanner"
)

// issue134Vuln returns the called finding from issue #134: one project frame
// with a position, reaching the x/crypto SSH agent sink.
func issue134Vuln() scanner.Vulnerability {
	return scanner.Vulnerability{
		ID:           "GO-2026-5005",
		Severity:     "CRITICAL",
		Reachability: "called",
		CallPath: []string{
			"example.com/u1repro.main",
			"golang.org/x/crypto/ssh/agent.keyring.Add",
		},
		CallTrace: []scanner.CallFrame{
			{Name: "example.com/u1repro.main", Module: "example.com/u1repro", File: "main.go", Line: 13, Column: 12, Project: true},
			{Name: "golang.org/x/crypto/ssh/agent.keyring.Add", Module: "golang.org/x/crypto", Version: "v0.48.0", File: "ssh/agent/keyring.go", Line: 149, Column: 19},
		},
		CalledSymbols: []string{"golang.org/x/crypto/ssh/agent.keyring.Add"},
	}
}

func TestReachedVia(t *testing.T) {
	cut := issue134Vuln()
	cut.CallPath = []string{"example.com/app.main", "...", "golang.org/x/crypto/ssh/agent.keyring.Add"}
	cut.CallTrace = []scanner.CallFrame{
		cut.CallTrace[0],
		{Elided: true},
		cut.CallTrace[1],
	}
	cut.CallTrace[0].Name = "example.com/app.main"

	noTrace := issue134Vuln()
	noTrace.CallTrace = nil

	misaligned := issue134Vuln()
	misaligned.CallTrace = misaligned.CallTrace[:1]

	noLine := issue134Vuln()
	noLine.CallTrace[0].Line = 0

	noFile := issue134Vuln()
	noFile.CallTrace[0].File = ""

	depPosition := issue134Vuln()
	depPosition.CallTrace[1].Project = true // a dependency flagged as project would show its position

	imported := issue134Vuln()
	imported.Reachability = "imported"

	empty := issue134Vuln()
	empty.CallPath, empty.CallTrace = nil, nil

	tests := []struct {
		name string
		v    scanner.Vulnerability
		sep  string
		want string
	}{
		{"text separator, project position only", issue134Vuln(), callPathSepText,
			"example.com/u1repro.main (main.go:13) → golang.org/x/crypto/ssh/agent.keyring.Add"},
		{"PDF separator is ASCII", issue134Vuln(), callPathSepPDF,
			"example.com/u1repro.main (main.go:13) > golang.org/x/crypto/ssh/agent.keyring.Add"},
		{"elided slot", cut, callPathSepPDF,
			"example.com/app.main (main.go:13) > ... > golang.org/x/crypto/ssh/agent.keyring.Add"},
		{"no trace falls back to names", noTrace, callPathSepText,
			"example.com/u1repro.main → golang.org/x/crypto/ssh/agent.keyring.Add"},
		{"misaligned trace falls back to names", misaligned, callPathSepText,
			"example.com/u1repro.main → golang.org/x/crypto/ssh/agent.keyring.Add"},
		{"zero line shows no position", noLine, callPathSepText,
			"example.com/u1repro.main → golang.org/x/crypto/ssh/agent.keyring.Add"},
		{"empty file shows no position", noFile, callPathSepText,
			"example.com/u1repro.main → golang.org/x/crypto/ssh/agent.keyring.Add"},
		{"only project frames carry a position", depPosition, callPathSepText,
			"example.com/u1repro.main (main.go:13) → golang.org/x/crypto/ssh/agent.keyring.Add (ssh/agent/keyring.go:149)"},
		{"imported has no path", imported, callPathSepText, ""},
		{"empty path", empty, callPathSepText, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reachedVia(&tt.v, tt.sep); got != tt.want {
				t.Errorf("reachedVia() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCalledSymbolsLine(t *testing.T) {
	two := issue134Vuln()
	two.CalledSymbols = []string{"golang.org/x/crypto/ssh/agent.keyring.Add", "golang.org/x/crypto/ssh/agent.keyring.Lock"}
	imported := two
	imported.Reachability = "imported"

	tests := []struct {
		name string
		v    scanner.Vulnerability
		want string
	}{
		{"none", scanner.Vulnerability{Reachability: "called"}, ""},
		{"one symbol duplicates the path tail", issue134Vuln(), ""},
		{"two symbols", two, "golang.org/x/crypto/ssh/agent.keyring.Add, golang.org/x/crypto/ssh/agent.keyring.Lock"},
		{"not called", imported, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calledSymbolsLine(&tt.v); got != tt.want {
				t.Errorf("calledSymbolsLine() = %q, want %q", got, tt.want)
			}
		})
	}
}
