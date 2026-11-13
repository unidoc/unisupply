//go:build !linux && !darwin

package scanner

import "errors"

// fakeGoList is unix-only: the go command runs `go list` in a process group of its own only there.
func fakeGoList() error { return errors.New("the golist fake runs on linux and darwin only") }
