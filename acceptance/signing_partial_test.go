package acceptance

import (
	"maps"
	"testing"
)

// The native scheduling oracle accepts only entire independent code objects.
// Corruptions must never become accepted merely because another member matches.
func TestSigningPartialResultBoundaries(t *testing.T) {
	before := map[string]string{"parent/main": "old-parent", "parent/envelope": "old-envelope", "worker/main": "old-main", "worker/envelope": "old-seal", "other": "control"}
	full := map[string]string{"parent/main": "new-parent", "parent/envelope": "new-envelope", "worker/main": "new-main", "worker/envelope": "new-seal", "other": "control"}
	completed := maps.Clone(before)
	completed["worker/main"], completed["worker/envelope"] = full["worker/main"], full["worker/envelope"]
	for _, tc := range []struct {
		name   string
		input  map[string]string
		native bool
		valid  bool
		change func(map[string]string)
	}{
		{name: "native-unstarted", input: before, native: true, valid: true},
		{name: "native-completed", input: completed, native: true, valid: true},
		{name: "go-completed", input: completed, valid: true},
		{name: "go-required-completion", input: before},
		{name: "partial-main", input: before, native: true, change: func(m map[string]string) { m["worker/main"] = "new-main" }},
		{name: "partial-envelope", input: before, native: true, change: func(m map[string]string) { m["worker/envelope"] = "new-seal" }},
		{name: "corrupt-child", input: completed, native: true, change: func(m map[string]string) { m["worker/main"] = "corrupt" }},
		{name: "changed-parent", input: completed, native: true, change: func(m map[string]string) { m["parent/main"] = "new-parent" }},
		{name: "changed-ancestor-envelope", input: completed, native: true, change: func(m map[string]string) { m["parent/envelope"] = "new-envelope" }},
		{name: "changed-control", input: completed, native: true, change: func(m map[string]string) { m["other"] = "changed" }},
		{name: "missing-child", input: completed, native: true, change: func(m map[string]string) { delete(m, "worker/envelope") }},
		{name: "missing-control", input: before, native: true, change: func(m map[string]string) { delete(m, "other") }},
		{name: "new-child", input: before, native: true, change: func(m map[string]string) { m["worker/extra"] = "unexpected" }},
		{name: "new-sibling", input: completed, native: true, change: func(m map[string]string) { m["extra"] = "unexpected" }},
		{name: "prefix-neighbour", input: completed, native: true, change: func(m map[string]string) { m["worker-extra/main"] = "unexpected" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := maps.Clone(tc.input)
			if tc.change != nil {
				tc.change(actual)
			}
			if err := signingSidebandPartialResult(before, full, actual, "worker", tc.native); (err == nil) != tc.valid {
				t.Fatalf("valid=%t, error=%v", tc.valid, err)
			}
		})
	}
}
