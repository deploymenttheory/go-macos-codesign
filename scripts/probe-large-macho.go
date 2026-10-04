//go:build ignore

// Research only: capture native Mach-O allocation and removal at size boundaries.
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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type outcome struct {
	Exit       int    `json:"exit"`
	Diagnostic string `json:"diagnostic"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
}
type observation struct {
	Populated                    bool   `json:"populated"`
	Name                         string `json:"name"`
	Verify                       outcome
	Length                       int64  `json:"length"`
	Prefix                       []byte `json:"prefix"`
	Sign, Resign, DryRun, Remove outcome
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
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(path string, args ...string) outcome {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "/usr/bin/codesign", append(args, path)...)
	c.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
	b, e := c.CombinedOutput()
	exit := 0
	if e != nil {
		if x, ok := e.(*exec.ExitError); ok {
			exit = x.ExitCode()
		} else {
			panic(e)
		}
	}
	f, e := os.Open(path)
	must(e)
	defer f.Close()
	s, e := f.Stat()
	must(e)
	h := sha256.New()
	_, e = io.Copy(h, f)
	must(e)
	return outcome{exit, strings.ReplaceAll(string(b), path, "<image>"), s.Size(), hex.EncodeToString(h.Sum(nil))}
}
func main() {
	check := flag.Bool("check", false, "compare with committed native observations")
	out := flag.String("out", "artifacts/large-macho.json", "capture destination")
	flag.Parse()
	const seedPath = "testdata/removal/unsigned-arm64.macho"

	host, e := exec.Command("sw_vers").Output()
	must(e)
	c := capture{Schema: 1, Recipe: "prefix followed by zero bytes to length; populated case writes byte(i%251) for 4 MiB+37 bytes at 512 MiB-17; __LINKEDIT filesize extends to length; sign/resign/dryrun/remove in order with identifier org.example.large-macho and timestamp disabled", Host: string(host), Sources: map[string]string{}}
	for _, p := range []string{seedPath, "testdata/removal/unsigned-universal.macho", "spec/apple-macho-allocation.json", "scripts/probe-large-macho.go", "spec/apple-writer.json", "spec/apple-removal.json", "/usr/bin/codesign"} {
		c.Sources[p] = hash(read(p))
	}
	tmp, e := os.MkdirTemp("", "codesign-large-macho-")
	must(e)
	defer os.RemoveAll(tmp)
	tmp, e = filepath.EvalSymlinks(tmp)
	must(e)
	path := filepath.Join(tmp, "large.macho")
	type recipe struct {
		name      string
		size      int64
		universal bool
	}
	var recipes []recipe
	for _, boundary := range []int64{1 << 30, 2 << 30, 4 << 30} {
		for _, delta := range []int64{-1, 0, 1} {
			size := boundary + delta
			recipes = append(recipes, recipe{fmt.Sprint(size), size, false})
		}
	}
	for _, size := range []int64{1<<30 + 1, 2<<30 + 1} {
		recipes = append(recipes, recipe{fmt.Sprintf("universal-%d", size), size, true})
	}
	recipes = append(recipes, recipe{"populated-1073741825", 1<<30 + 1, false})
	for _, recipe := range recipes {
		size := recipe.size
		prefix := read(seedPath)
		if recipe.universal {
			prefix = read("testdata/removal/unsigned-universal.macho")
		}
		base := 0
		if recipe.universal {
			base = int(binary.BigEndian.Uint32(prefix[36:]))
			binary.BigEndian.PutUint32(prefix[40:], uint32(size-int64(base)))
		}
		image := prefix[base:]
		for p, i := 32, uint32(0); i < binary.LittleEndian.Uint32(image[16:]); i++ {
			if binary.LittleEndian.Uint32(image[p:]) == 0x19 && string(bytes.TrimRight(image[p+8:p+24], "\x00")) == "__LINKEDIT" {
				start := binary.LittleEndian.Uint64(image[p+40:])
				binary.LittleEndian.PutUint64(image[p+48:], uint64(size-int64(base))-start)
			}
			p += int(binary.LittleEndian.Uint32(image[p+4:]))
		}
		f, e := os.Create(path)
		must(e)
		_, e = f.Write(prefix)
		must(e)
		must(f.Truncate(size))
		populated := strings.HasPrefix(recipe.name, "populated-")
		if populated {
			data := make([]byte, 4<<20+37)
			for i := range data {
				data[i] = byte(i % 251)
			}
			_, e = f.WriteAt(data, 1<<29-17)
			must(e)
		}
		must(f.Close())
		row := observation{Populated: populated, Name: recipe.name, Length: size, Prefix: prefix}
		row.Sign = run(path, "-s", "-", "-i", "org.example.large-macho", "--timestamp=none")
		if row.Sign.Exit == 0 {
			row.Verify = run(path, "--verify", "--strict", "--verbose=4")
			if row.Verify.Exit != 0 {
				panic(fmt.Sprintf("native signature rejected: %+v", row.Verify))
			}
			row.Resign = run(path, "-f", "-s", "-", "-i", "org.example.large-macho", "--timestamp=none")
			row.DryRun = run(path, "-f", "--dryrun", "-s", "-", "-i", "org.example.large-macho", "--timestamp=none")
			row.Remove = run(path, "--remove-signature")
		} else {
			row.Remove = run(path, "--remove-signature")
		}
		c.Cases = append(c.Cases, row)
		must(os.Remove(path))
		fmt.Printf("size=%d sign=%+v remove=%+v\n", size, row.Sign, row.Remove)
	}
	b, e := json.MarshalIndent(c, "", "  ")
	must(e)
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	must(os.WriteFile(*out, append(b, '\n'), 0644))
	if *check {
		var baseline capture
		must(json.Unmarshal(read("testdata/research/large-macho.json"), &baseline))
		if !reflect.DeepEqual(c.Cases, baseline.Cases) {
			panic("native Mach-O observations changed")
		}
	}
}
