package cli

import (
	"strings"
	"testing"
)

func TestStrictSelectors(t *testing.T) {
	for _, tc := range []struct {
		text    string
		mask    uint32
		disable bool
	}{
		{"", 0x280, false}, {"s", 128, false}, {"symlink", 128, false}, {"symlinks", 128, false}, {"side", 512, false}, {"all", 640, false}, {"n", 0, true}, {"none", 0, true},
		{"128", 128, false}, {"0x80", 128, false}, {"0X80", 128, false}, {"0200", 128, false}, {"128x", 128, false}, {"128 ", 128, false}, {"0", 0, false}, {"08", 0, false}, {"0x", 0, false}, {"4294967424", 128, false}, {"18446744073709551616", 0xffffffff, false},
	} {
		t.Run(tc.text, func(t *testing.T) {
			m, d, e := parseStrictSelector(tc.text)
			if e != nil || m != tc.mask || d != tc.disable {
				t.Fatal(m, d, e)
			}
		})
	}
	for _, text := range []string{"symlinks,sideband", "none,symlinks", "symlinks,", "SYMLINKS", "+128", "-1", "unknown"} {
		out, err, status := invoke(t, "--verify", "--strict="+text, "absent")
		if status != 1 || out != "" || err != "invalid strict option - "+text+"\n" {
			t.Fatal(text, status, out, err)
		}
	}
	for _, flags := range [][]string{{"--strict=none", "--strict=symlinks"}, {"--strict=symlinks", "--strict=none"}} {
		o, e := parse(append([]string{"--verify"}, flags...))
		if e != nil || !o.noStrict {
			t.Fatal(o, e)
		}
	}
	for _, flags := range [][]string{{"--strict=0", "--strict=128"}, {"--strict=symlinks", "--strict=0"}} {
		o, e := parse(append([]string{"--verify"}, flags...))
		if e != nil || o.noStrict || o.strictMask != 128 {
			t.Fatal(o, e)
		}
	}
	for _, args := range [][]string{{"--verify", "--strict=1"}, {"--verify", "--no-strict", "--strict=1"}, {"-d", "--no-strict"}, {"-s-", "--strict=symlinks"}, {"--verify", "--no-strict=yes"}} {
		_, e := parse(args)
		if e == nil {
			t.Fatal("accepted unsupported policy", args)
		}
	}
	p := file(t, "adhoc-arm64")
	for _, flags := range [][]string{{"--strict=0"}, {"--strict=128"}, {"--strict=none"}, {"--no-strict"}, {"--strict"}, {"--strict=all"}, {"--strict=512"}, {"--strict=sideband"}, {"--strict=sideband", "--no-strict"}} {
		out, err, status := invoke(t, append(append([]string{"--verify"}, flags...), p)...)
		if status != 0 || out != "" || err != "" {
			t.Fatal(flags, status, out, err)
		}
	}
	_, err, status := invoke(t, "--verify", "--no-strict", "--strict=bad", p)
	if status != 1 || !strings.Contains(err, "invalid strict option") {
		t.Fatal(status, err)
	}
}
