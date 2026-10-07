//go:build ignore

// Capture native CLI and SDK observations for deterministic large metadata.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

const seedPath = "testdata/dmg/native-adhoc-raw.dmg"
const oraclePath = "testdata/research/signature-metadata.c"
const driverPath = "scripts/probe-signature-metadata.go"

type part struct {
	Offset int64
	Data   []byte
}
type result struct {
	Exit int
	Text string
}
type observation struct {
	DirectorySize, FileSize int64
	Parts                   []part
	SHA256                  string
	Display, Verify         result
	Framework               json.RawMessage
}
type capture struct {
	Schema          int
	Scope           string
	Host, SDK       string
	Compiler        string
	OracleSHA256    string
	SDKHeaders      map[string]string
	SeedPrefixBytes int64
	Sources         map[string]string
	AST             map[string]map[string]int
	Cases           []observation
}
type astNode struct {
	Kind, Name string
	Inner      []astNode
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func hash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func command(name string, args ...string) result {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fmt.Fprintf(os.Stderr, "START %s %v\n", name, args)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
	output, err := cmd.CombinedOutput()
	fmt.Fprintf(os.Stderr, "END %s error=%v context=%v\n", name, err, ctx.Err())
	must(ctx.Err())
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			panic(err)
		}
		code = exit.ExitCode()
	}
	return result{code, string(output)}
}
func successful(name string, args ...string) string {
	r := command(name, args...)
	if r.Exit != 0 {
		panic(fmt.Sprintf("%s: exit %d: %s", name, r.Exit, r.Text))
	}
	return r.Text
}
func walk(n astNode, counts map[string]int) {
	counts[n.Kind]++
	for _, child := range n.Inner {
		walk(child, counts)
	}
}
func recipe(seed []byte, footer disk.DMGFooter, size int64, identity *codesign.Identity) observation {
	be := binary.BigEndian
	original := seed[footer.CodeSignatureOffset : footer.CodeSignatureOffset+footer.CodeSignatureLength]
	count := be.Uint32(original[8:])
	header := bytes.Clone(original[:12+8*count])
	p := uint32(len(header))
	c := observation{DirectorySize: size}
	var cms []byte
	for i := uint32(0); i < count; i++ {
		slot, offset := be.Uint32(original[12+i*8:]), be.Uint32(original[16+i*8:])
		length := be.Uint32(original[offset+4:])
		data := bytes.Clone(original[offset : offset+length])
		if slot == 0 {
			length = uint32(size)
			be.PutUint32(data[4:], length)
			if identity != nil {
				be.PutUint32(data[12:], 0) // Certificate-backed, not ad-hoc.
				directory := make([]byte, size)
				copy(directory, data)
				var err error
				cms, err = codesign.SignCMS(context.Background(), identity, [][]byte{directory}, time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
				must(err)
			}
		}
		if identity != nil && slot == codesign.SlotCMS {
			if len(cms) == 0 {
				panic("seed CMS precedes its directory")
			}
			length = uint32(8 + len(cms))
			data = make([]byte, length)
			be.PutUint32(data, codesign.MagicCMS)
			be.PutUint32(data[4:], length)
			copy(data[8:], cms)
		}
		be.PutUint32(header[16+i*8:], p)
		c.Parts = append(c.Parts, part{int64(footer.CodeSignatureOffset) + int64(p), data})
		p += length
	}
	be.PutUint32(header[4:], p)
	c.Parts = append(c.Parts, part{int64(footer.CodeSignatureOffset), header})
	footer.CodeSignatureLength = uint64(p)
	var trailer bytes.Buffer
	must(binary.Write(&trailer, be, footer))
	c.Parts = append(c.Parts, part{int64(footer.CodeSignatureOffset) + int64(p), trailer.Bytes()})
	c.FileSize = int64(footer.CodeSignatureOffset) + int64(p) + 512
	return c
}
func writeFixture(path string, prefix []byte, c observation) {
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	// Populate every byte on every host. These controls are intentionally dense.
	zero := make([]byte, 64<<10)
	for left := c.FileSize; left > 0; {
		n := min(left, int64(len(zero)))
		written, err := f.Write(zero[:n])
		must(err)
		if int64(written) != n {
			panic(io.ErrShortWrite)
		}
		left -= n
	}
	_, err = f.WriteAt(prefix, 0)
	must(err)
	for _, p := range c.Parts {
		_, err = f.WriteAt(p.Data, p.Offset)
		must(err)
	}
	must(f.Close())
}
func main() {
	output := flag.String("out", "artifacts/signature-metadata.json", "native capture destination")
	check := flag.Bool("check", false, "require equality with the retained native case corpus")
	certificate := flag.Bool("certificate", false, "capture certificate-backed directory boundaries")
	flag.Parse()
	dir, err := os.MkdirTemp("", "codesign-metadata-")
	must(err)
	defer os.RemoveAll(dir)
	dir, err = filepath.EvalSymlinks(dir)
	must(err)
	oracle := filepath.Join(dir, "oracle")
	sdk := strings.TrimSpace(successful("xcrun", "--show-sdk-path"))
	c := capture{Schema: 1, Scope: "Dense native-ad-hoc UDIF seed with a zero-extended CodeDirectory; the SuperBlob lengths and UDIF signature length change. Code pages, special slots and the blinded trailer binding are unchanged. Native CLI observations and independent SDK validation establish acceptance; AST records only the real SDK calls and declarations, not Apple's private implementation.", Host: successful("sw_vers"), SDK: sdk, Sources: map[string]string{}, AST: map[string]map[string]int{}}
	baselinePath := "testdata/research/signature-metadata.json"
	boundaries := []int64{64 << 10, 16 << 20, 128 << 20, 1 << 30}
	var identity *codesign.Identity
	if *certificate {
		identity, err = codesign.LoadIdentityPEM(read("testdata/identities/rsa-identity.pem"), nil)
		must(err)
		baselinePath = "testdata/research/signature-metadata-cms.json"
		boundaries = []int64{16 << 20}
		c.Scope = "Dense zero-extended CodeDirectory around the former 16 MiB CMS binding ceiling. A public RSA test key signs the directory with both Apple hash-agility attributes. Native CLI strict verification and independent C/SDK inspection/validation are the oracle; the Go producer is not the oracle. No keychain access. Display/date formatting is outside this profile."
		for _, path := range []string{"testdata/identities/rsa-identity.pem", "pkg/codesign/cms.go", "pkg/codesign/cms_binding.go"} {
			c.Sources[path] = hash(read(path))
		}
	}
	c.Compiler = successful("xcrun", "clang", "--version")
	c.SDKHeaders = map[string]string{}
	for _, name := range []string{"SecCode.h", "SecStaticCode.h"} {
		c.SDKHeaders[name] = hash(read(filepath.Join(sdk, "System/Library/Frameworks/Security.framework/Headers", name)))
	}
	for _, p := range []string{driverPath, oraclePath, seedPath, "go.mod", "go.sum", "/usr/bin/codesign"} {
		c.Sources[p] = hash(read(p))
	}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		raw := successful("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-target", target, "-isysroot", sdk, "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=metadata_probe", "-fsyntax-only", oraclePath)
		var ast astNode
		must(json.Unmarshal([]byte(raw), &ast))
		if ast.Kind != "FunctionDecl" || ast.Name != "metadata_probe" {
			panic("missing native probe body")
		}
		counts := map[string]int{}
		walk(ast, counts)
		c.AST[target] = counts
	}
	successful("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", oraclePath, "-framework", "Security", "-framework", "CoreFoundation", "-o", oracle)
	c.OracleSHA256 = hash(read(oracle))
	seed := read(seedPath)
	var footer disk.DMGFooter
	must(binary.Read(bytes.NewReader(seed[len(seed)-512:]), binary.BigEndian, &footer))
	c.SeedPrefixBytes = int64(footer.CodeSignatureOffset)
	path := filepath.Join(dir, "metadata.dmg")
	for _, boundary := range boundaries {
		for _, delta := range []int64{-1, 0, 1} {
			item := recipe(seed, footer, boundary+delta, identity)
			fmt.Fprintf(os.Stderr, "START dense fixture directory=%d bytes\n", item.DirectorySize)
			writeFixture(path, seed[:c.SeedPrefixBytes], item)
			f, err := os.Open(path)
			must(err)
			h := sha256.New()
			_, err = io.CopyBuffer(h, f, make([]byte, 64<<10))
			must(err)
			must(f.Close())
			item.SHA256 = hex.EncodeToString(h.Sum(nil))
			if !*certificate {
				item.Display = command("/usr/bin/codesign", "-d", "--verbose=4", path)
			}
			item.Verify = command("/usr/bin/codesign", "--verify", "--strict", "--verbose=4", path)
			item.Display.Text = strings.ReplaceAll(item.Display.Text, path, "<image>")
			item.Verify.Text = strings.ReplaceAll(item.Verify.Text, path, "<image>")
			framework := successful(oracle, path)
			var facts map[string]any
			must(json.Unmarshal([]byte(framework), &facts))
			item.Framework, err = json.Marshal(facts)
			must(err)
			c.Cases = append(c.Cases, item)
			must(os.Remove(path))
		}
	}
	// Retain evidence even when comparison fails, so CI can expose the actual
	// native observation rather than only the assertion message.
	encoded, err := json.MarshalIndent(c, "", "  ")
	must(err)
	must(os.MkdirAll(filepath.Dir(*output), 0755))
	must(os.WriteFile(*output, append(encoded, '\n'), 0600))
	if *check {
		var baseline capture
		must(json.Unmarshal(read(baselinePath), &baseline))
		// RawMessage retains input indentation. Compact both serializations;
		// every observation value and array element remains part of equality.
		actual, err := json.Marshal(c.Cases)
		must(err)
		expected, err := json.Marshal(baseline.Cases)
		must(err)
		if !bytes.Equal(actual, expected) {
			panic("native signature metadata cases changed; compare " + *output + " with " + baselinePath)
		}
		if !reflect.DeepEqual(c.AST, baseline.AST) {
			panic("native signature metadata AST changed; compare " + *output + " with " + baselinePath)
		}
		for p, sum := range c.Sources {
			if !strings.HasPrefix(p, "/") && baseline.Sources[p] != sum {
				panic("stale capture source: " + p)
			}
		}
	}
}
