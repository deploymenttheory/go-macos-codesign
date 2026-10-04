//go:build ignore

// Research only: preserve native signatures for reproducible large UDIF files.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

type observation struct {
	ContentLength int64  `json:"content_length"`
	Prefix        []byte `json:"prefix"`
	Signature     []byte `json:"signature"`
	Trailer       []byte `json:"trailer"`
	Display       string `json:"display"`
	Verify        string `json:"verify"`
}
type capture struct {
	Schema  int               `json:"schema"`
	Recipe  string            `json:"recipe"`
	Sources map[string]string `json:"source_sha256"`
	Host    string            `json:"host"`
	Cases   []observation     `json:"cases"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func hash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func run(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
	b, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%s %v: %v: %s", name, args, err, b))
	}
	return string(b)
}
func main() {
	check := flag.Bool("check", false, "compare native signature recipes with committed capture")
	output := flag.String("out", "artifacts/large-source.json", "capture destination")
	flag.Parse()
	const fixture = "testdata/dmg/native-adhoc-raw.dmg"
	seed := read(fixture)
	var footer disk.DMGFooter
	must(binary.Read(bytes.NewReader(seed[len(seed)-512:]), binary.BigEndian, &footer))
	prefix := seed[:footer.CodeSignatureOffset]
	footer.CodeSignatureOffset = 0
	footer.CodeSignatureLength = 0
	var unsignedTrailer bytes.Buffer
	must(binary.Write(&unsignedTrailer, binary.BigEndian, &footer))
	c := capture{Schema: 1, Recipe: "prefix, zero-filled sparse extent to content_length, native signature, native trailer; native signing uses -s - -i org.example.large-source --timestamp=none", Sources: map[string]string{}, Host: run("sw_vers")}
	for _, path := range []string{fixture, "scripts/probe-large-source.go", "go.mod", "go.sum", "/usr/bin/codesign"} {
		c.Sources[path] = hash(read(path))
	}
	tmp, err := os.MkdirTemp("", "codesign-large-source-")
	must(err)
	defer os.RemoveAll(tmp)
	path := filepath.Join(tmp, "large.dmg")
	for _, boundary := range []int64{1 << 30, 2 << 30, 4 << 30} {
		for _, delta := range []int64{-1, 0, 1} {
			size := boundary + delta
			f, err := os.Create(path)
			must(err)
			_, err = f.Write(prefix)
			must(err)
			must(f.Truncate(size + 512))
			_, err = f.WriteAt(unsignedTrailer.Bytes(), size)
			must(err)
			must(f.Close())
			run("/usr/bin/codesign", "-s", "-", "-i", "org.example.large-source", "--timestamp=none", path)
			display := run("/usr/bin/codesign", "-dvvvv", path)
			verify := run("/usr/bin/codesign", "--verify", "--strict", "--verbose=4", path)
			f, err = os.Open(path)
			must(err)
			st, err := f.Stat()
			must(err)
			trailer := make([]byte, 512)
			_, err = f.ReadAt(trailer, st.Size()-512)
			must(err)
			var signed disk.DMGFooter
			must(binary.Read(bytes.NewReader(trailer), binary.BigEndian, &signed))
			if signed.CodeSignatureOffset != uint64(size) || signed.CodeSignatureLength > 1<<20 {
				panic("unexpected native signature range")
			}
			signature := make([]byte, int(signed.CodeSignatureLength))
			_, err = f.ReadAt(signature, size)
			must(err)
			must(f.Close())
			c.Cases = append(c.Cases, observation{size, prefix, signature, trailer, string(bytes.ReplaceAll([]byte(display), []byte(path), []byte("<image>"))), string(bytes.ReplaceAll([]byte(verify), []byte(path), []byte("<image>")))})
			must(os.Remove(path))
			fmt.Println("Captured native content length", size)
		}
	}
	data, err := json.MarshalIndent(c, "", "  ")
	must(err)
	must(os.MkdirAll(filepath.Dir(*output), 0755))
	must(os.WriteFile(*output, append(data, '\n'), 0644))
	if *check {
		var baseline capture
		must(json.Unmarshal(read("testdata/research/large-source.json"), &baseline))
		if !reflect.DeepEqual(c.Cases, baseline.Cases) {
			panic("native large-source corpus changed")
		}
		for path, sum := range c.Sources {
			if path != "/usr/bin/codesign" && baseline.Sources[path] != sum {
				panic("stale source: " + path)
			}
		}
	}
	fmt.Println("Wrote", *output)
}
