package cdep

// #include <stdlib.h>
import "C"

func F() { C.free(nil) }
