package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestMetadataRoutingFlagsRejected(t *testing.T) {
	for _, operation := range [][]string{{"-s", "-"}, {"-v", "--strict=all"}, {"-d"}, {"--remove-signature"}} {
		for _, flag := range []string{"--appledouble", "--appledouble-map"} {
			for _, value := range []string{"", "=metadata"} {
				args := append(append([]string{}, operation...), flag+value, "metadata", "object")
				if _, err := parse(args); !errors.Is(err, codesign.ErrUnsupported) {
					t.Fatal(args, err)
				}
				if _, _, status := invoke(t, args...); status == 0 {
					t.Fatal("accepted obsolete metadata routing flag", args)
				}
			}
		}
	}
	out, stderr, status := invoke(t, "--help")
	if status != 0 || stderr != "" || strings.Contains(out, "--appledouble") {
		t.Fatal(status, out, stderr)
	}
}

func TestStripDisallowedArguments(t *testing.T) {
	if _, err := parse([]string{"--strip-disallowed-xattrs=yes"}); err == nil {
		t.Fatal("accepted argument to boolean native option")
	}
	for _, args := range [][]string{{"-s-", "--strip-disallowed-xattrs", "--no-strict", "object"}, {"-v", "--strip-disallowed-xattrs", "object"}, {"-d", "--strip-disallowed-xattrs", "object"}, {"--remove-signature", "--strip-disallowed-xattrs", "object"}} {
		if o, err := parse(args); err != nil || !o.stripDisallowed {
			t.Fatal(o, err)
		}
	}
	if _, _, status := invoke(t, "-v", "--strip-disallowed-xattrs", "absent"); status != 1 {
		t.Fatal(status)
	}
}
