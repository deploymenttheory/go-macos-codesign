package codesign

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"
)

func TestMachOIdentifiers(t *testing.T) {
	for input, want := range map[string]string{"libfrotz7.3.5.dylib": "libfrotz7", "mumble.77.plugin": "mumble.77", "rumble.rb": "rumble", "foo.2.3.4": "foo.2", "foo2.3": "foo2", ".hidden": "", "27.1.dylib": "27.1"} {
		if got := canonicalIdentifier(input); got != want {
			t.Fatalf("%s: %s != %s", input, got, want)
		}
	}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		data := fixture(t, "unsigned-"+arch)
		got, err := machoIdentifier("hello", data, true)
		if err != nil || !strings.HasPrefix(got, "hello-55554944") || len(got) != 46 {
			t.Fatal(got, err)
		}
		for _, tc := range []struct {
			name  string
			adhoc bool
			want  string
		}{{"hello", false, "hello"}, {"hello.7.2.dylib", true, "hello.7"}} {
			got, err := machoIdentifier(tc.name, data, tc.adhoc)
			if err != nil || got != tc.want {
				t.Fatal(got, err)
			}
		}
	}
	if _, err := machoIdentifier("hello", nil, true); err == nil {
		t.Fatal("invalid Mach-O")
	}
	data := fixture(t, "unsigned-arm64")
	im, err := parseImage(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range im.commands {
		if cmd.kind != 0x1b {
			continue
		}
		// Preserve framing but make the UUID command an unknown command.
		im.order.PutUint32(data[cmd.offset:], 0x1234)
		h := sha1.New()
		_, _ = h.Write(data[:28])
		_, _ = h.Write(data[im.header : im.header+int(im.order.Uint32(data[20:]))])
		got, err := machoIdentifier("hello", data, true)
		if err != nil || got != "hello-"+hex.EncodeToString(h.Sum(nil)) {
			t.Fatal(got, err)
		}
		im.order.PutUint32(data[cmd.offset:], 0x1b)
		// A larger command reclassed as UUID provides valid framing with an invalid UUID size.
	}
	for _, cmd := range im.commands {
		if cmd.size != 24 {
			im.order.PutUint32(data[cmd.offset:], 0x1b)
			break
		}
	}
	if _, err := machoIdentifier("hello", data, true); err == nil {
		t.Fatal("malformed UUID accepted")
	}
}
