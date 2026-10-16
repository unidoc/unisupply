package main

import (
	_ "embed"

	_ "example.com/webkit"
)

// web/dist is a build output named in .gitignore, so it is absent from a
// fresh clone and the pattern matches nothing.
//
//go:embed web/dist
var assets string

func main() { _ = assets }
