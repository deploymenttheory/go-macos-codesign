package cli

import (
	"strings"
	"testing"
)

func TestIgnoreResourcesOption(t *testing.T) {
	for _, operation := range []string{"--verify", "--display", "--remove-signature", "--sign=-"} {
		o, err := parse([]string{operation, "--ignore-resources", "--ignore-resources", "input"})
		if err != nil || !o.ignoreResources {
			t.Fatal(o, err)
		}
	}
	for _, value := range []string{"", "true", "false", "0"} {
		if _, err := parse([]string{"--verify", "--ignore-resources=" + value, "input"}); err == nil {
			t.Fatal("accepted attached value", value)
		}
	}
	path := file(t, "adhoc-arm64")
	out, stderr, status := invoke(t, "--verify", "--ignore-resources", "--verbose=1", path)
	if status != 0 || out != "" || !strings.Contains(stderr, ": valid on disk (not all contents verified)\n") {
		t.Fatal(status, out, stderr)
	}
	out, stderr, status = invoke(t, "--help")
	if status != 0 || stderr != "" || !strings.Contains(out, "--ignore-resources") {
		t.Fatal(status, out, stderr)
	}
}
