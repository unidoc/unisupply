module example.com/replacetest

go 1.21

require (
	github.com/foo/pinned v1.0.0
	github.com/foo/local v1.0.0
	github.com/foo/redirected v1.0.0
)

replace (
	// Version-pin override — LOW severity.
	github.com/foo/pinned => github.com/foo/pinned v1.0.1
	// Local-path override — MEDIUM severity.
	github.com/foo/local => ../local/path
	// Redirect to a different module — HIGH severity.
	github.com/foo/redirected => github.com/attacker/redirected v1.0.0
)

exclude github.com/foo/excluded v0.9.0
