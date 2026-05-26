// Command calibration-record builds a calibration fixture from a raw
// `unisupply --format json` output by prepending a `_meta` block and computing
// the content_sha256 over the canonicalized body (Go's json.MarshalIndent with
// alphabetically sorted map keys). The same canonicalization is performed by
// pkg/scorer/calibration_test.go when validating the hash.
//
// Usage:
//
//	go run ./tools/calibration-record \
//	    --in  /tmp/unisupply-v0.4-raw.json \
//	    --out pkg/scorer/testdata/calibration/unisupply-v0.4.json \
//	    --upstream-pin v0.4.0 \
//	    --scanner-sha $(git rev-parse HEAD) \
//	    --version 0.5.0-dev \
//	    --reason "Initial recording for calibration corpus"
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	in := flag.String("in", "", "raw `unisupply --format json` output")
	out := flag.String("out", "", "fixture output path under pkg/scorer/testdata/calibration/")
	pin := flag.String("upstream-pin", "", "upstream git tag or sha (e.g. v1.20.0)")
	sha := flag.String("scanner-sha", "", "unisupply scanner git sha at recording time")
	ver := flag.String("version", "", "unisupply version constant (e.g. 0.5.0-dev)")
	reason := flag.String("reason", "", "rerecord_reason — mandatory per fixture commit")
	flag.Parse()

	if *in == "" || *out == "" || *pin == "" || *sha == "" || *ver == "" || *reason == "" {
		fmt.Fprintln(os.Stderr, "all flags are required")
		flag.Usage()
		os.Exit(2)
	}

	raw, err := os.ReadFile(*in)
	must(err)

	var body map[string]any
	must(json.Unmarshal(raw, &body))

	if _, exists := body["_meta"]; exists {
		fmt.Fprintln(os.Stderr, "input already has _meta — refusing to overwrite")
		os.Exit(2)
	}

	canon, err := json.MarshalIndent(body, "", "  ")
	must(err)
	sum := sha256.Sum256(canon)
	contentHash := hex.EncodeToString(sum[:])

	meta := map[string]any{
		"recorded_at":       time.Now().UTC().Format(time.RFC3339),
		"unisupply_version": *ver,
		"scanner_git_sha":   *sha,
		"upstream_pin":      *pin,
		"rerecord_reason":   *reason,
		"content_sha256":    contentHash,
	}

	// Add _meta to the body. json.MarshalIndent sorts map keys lexicographically,
	// and "_" (0x5F) sorts before any ASCII letter, so _meta is rendered as the
	// first field of the object without any byte-level splicing. This avoids
	// the prior assumption that MarshalIndent always emits a "{\n" prefix.
	if _, exists := body["_meta"]; exists {
		fmt.Fprintln(os.Stderr, "internal: body already contains _meta after canonicalization")
		os.Exit(2)
	}
	body["_meta"] = meta

	fixture, err := json.MarshalIndent(body, "", "  ")
	must(err)

	// Sanity check: _meta must end up as the first field. Decode the first two
	// tokens (a '{' delimiter, then the first key) rather than matching exact
	// byte prefixes — that way cosmetic stdlib indentation tweaks don't trip
	// the check.
	if err := requireFirstKey(fixture, "_meta"); err != nil {
		fmt.Fprintln(os.Stderr, "internal: ", err)
		os.Exit(2)
	}

	must(os.WriteFile(*out, fixture, 0o600))
	fmt.Printf("wrote %s (%d bytes, sha256=%s)\n", *out, len(fixture), contentHash)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// requireFirstKey verifies that the JSON object encoded in data has want as
// its very first key. Token-based so future MarshalIndent format tweaks
// (different whitespace, newline conventions) do not break the check.
func requireFirstKey(data []byte, want string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	openTok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decoding fixture: %w", err)
	}
	if d, ok := openTok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("fixture root is not a JSON object (got %v)", openTok)
	}
	keyTok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("reading first key: %w", err)
	}
	got, ok := keyTok.(string)
	if !ok {
		return fmt.Errorf("first token after '{' is not a string key (got %v)", keyTok)
	}
	if got != want {
		return fmt.Errorf("first key = %q, want %q", got, want)
	}
	return nil
}
