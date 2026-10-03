package plist_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// This is retained research for the next encoding increment, not a claim that
// Decode already supports the declared codecs. CI recaptures all native bytes.
func TestLegacyResearchProvenance(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var corpus struct {
		Schema int
		MacOS  string
		Native string `json:"native_sha256"`
		Source string `json:"source_sha256"`
		Codecs []struct {
			Name           string
			Prefix, Suffix []byte
			Scalars        []int32
		}
	}
	if err := json.Unmarshal(read("../../testdata/bundle-removal/plist-legacy-values.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	source := sha256.Sum256(read("../../scripts/probe-removal-legacy-values.go"))
	native, err := hex.DecodeString(corpus.Native)
	if err != nil || len(native) != sha256.Size || corpus.Schema != 1 || corpus.MacOS == "" || corpus.Source != hex.EncodeToString(source[:]) {
		t.Fatal("invalid native provenance")
	}
	wanted := map[string]bool{}
	for _, name := range []string{"us-ascii", "ascii", "ansi_x3.4-1968", "iso-8859-1", "iso_8859-1", "latin1", "latin-1", "iso_8859-1:1987", "l1", "koi8-r", "koi8-u", "x-mac-cyrillic"} {
		wanted[name] = true
	}
	for _, n := range []int{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16} {
		wanted[fmt.Sprintf("iso-8859-%d", n)] = true
	}
	for _, n := range []int{874, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258} {
		wanted[fmt.Sprintf("windows-%d", n)] = true
		wanted[fmt.Sprintf("cp%d", n)] = true
	}
	for _, n := range []int{437, 850, 852, 855, 860, 862, 863, 865, 866} {
		wanted[fmt.Sprintf("ibm%d", n)] = true
	}
	if len(corpus.Codecs) != 55 || len(wanted) != 55 {
		t.Fatal("incomplete codec inventory")
	}
	for _, c := range corpus.Codecs {
		if !wanted[c.Name] || len(c.Scalars) != 256 {
			t.Fatal("missing/duplicate codec or bytes", c.Name)
		}
		delete(wanted, c.Name)
		prefix := `<?xml version="1.0" encoding="` + c.Name + `"?><dict><key>value</key><string><![CDATA[`
		if !strings.EqualFold(string(c.Prefix), prefix) || string(c.Suffix) != `]]></string></dict>` {
			t.Fatal("unexpected native input", c.Name)
		}
		for n, r := range c.Scalars {
			if n < 128 && r != int32(n) || r != -1 && !utf8.ValidRune(r) {
				t.Fatal("invalid native scalar", c.Name, n, r)
			}
		}
	}
	if len(wanted) != 0 {
		t.Fatal("missing codecs", wanted)
	}
}
