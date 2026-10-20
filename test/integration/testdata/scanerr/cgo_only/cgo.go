//go:build cgo

package cgoonly

// #include <stdlib.h>
import "C"

func F() { C.free(nil) }
