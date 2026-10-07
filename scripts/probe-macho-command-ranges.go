//go:build ignore

// Research and acceptance: genuine C/SDK fixtures, native observations, and
// portable Go replay. No native executable is used by the portable replay.
package main

import (
	"compress/gzip"
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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

const corpusPath = "testdata/research/macho-command-ranges.json"
const cPath = "testdata/research/macho-command-ranges.c"
const scriptPath = "scripts/probe-macho-command-ranges.go"
const identifier = "org.example.command-ranges"

type recipe struct {
	Name                   string
	DylibSize, Rpaths, CPU uint32
	Text                   bool
	Platform               uint32
}
type outcome struct {
	Operation  string
	Exit       int
	Diagnostic string
	Size       int64
	SHA256     string
}
type observation struct {
	Recipe     recipe
	Initial    outcome
	Operations []outcome
}
type capture struct {
	Schema              int
	Scope               string
	Host, Compiler, SDK string
	Sources             map[string]string
	Layouts             map[string]map[string]string
	Cases               []observation
}
type astNode struct {
	Kind, Name, Value string
	Inner             []astNode
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func command(ctx context.Context, name string, args ...string) []byte {
	c := exec.CommandContext(ctx, name, args...)
	b, e := c.CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s %v: %v\n%s", name, args, e, b))
	}
	return b
}
func snapshot(path, operation string) outcome {
	f, e := os.Open(path)
	must(e)
	defer f.Close()
	info, e := f.Stat()
	must(e)
	h := sha256.New()
	_, e = io.CopyBuffer(h, f, make([]byte, 64<<10))
	must(e)
	return outcome{Operation: operation, Size: info.Size(), SHA256: hex.EncodeToString(h.Sum(nil))}
}
func sourcePaths() []string {
	return []string{scriptPath, cPath, "spec/apple-macho-allocation.json", "spec/apple-removal.json", "spec/apple-writer.json", "spec/apple-macho-command-policy.json", "scripts/extract-macho-command-policy.go"}
}
func recipes() []recipe {
	r := []recipe{{"small-arm64", 40, 0, 0x100000c, true, 1}, {"small-x86_64", 40, 0, 0x1000007, true, 1}, {"many-commands-arm64", 40, 8192, 0x100000c, true, 1}, {"padded-command-arm64", 65536, 0, 0x100000c, true, 1}, {"sectionless-control-arm64", 40, 0, 0x100000c, false, 0}, {"no-platform-control-arm64", 40, 0, 0x100000c, true, 0}}
	for _, delta := range []int64{-8, 0, 8, -40, -32} {
		n := uint32((1 << 30) + delta)
		r = append(r, recipe{fmt.Sprintf("sizeofcmds-%d", n), n - 272, 0, 0x100000c, true, 1})
	}
	return r
}
func arguments(operation string) []string {
	switch operation {
	case "inspect-unsigned", "inspect-signed", "inspect-removed":
		return []string{"--display", "--verbose=4"}
	case "sign":
		return []string{"--sign", "-", "--identifier", identifier, "--timestamp=none"}
	case "resign":
		return []string{"--force", "--sign", "-", "--identifier", identifier, "--timestamp=none"}
	case "dryrun":
		return []string{"--force", "--dryrun", "--sign", "-", "--identifier", identifier, "--timestamp=none"}
	case "verify":
		return []string{"--verify", "--strict", "--verbose=4"}
	case "remove":
		return []string{"--remove-signature"}
	default:
		panic(operation)
	}
}

var operations = []string{"inspect-unsigned", "sign", "inspect-signed", "verify", "resign", "dryrun", "remove", "inspect-removed"}

func native(path, operation string) outcome {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "/usr/bin/codesign", append(arguments(operation), path)...)
	c.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
	b, e := c.CombinedOutput()
	must(ctx.Err())
	out := snapshot(path, operation)
	out.Diagnostic = strings.ReplaceAll(string(b), path, "<image>")
	if e != nil {
		var x *exec.ExitError
		if !errors.As(e, &x) {
			panic(e)
		}
		out.Exit = x.ExitCode()
	}
	return out
}
func walk(n astNode, visit func(astNode)) {
	visit(n)
	for _, child := range n.Inner {
		walk(child, visit)
	}
}
func layout(ctx context.Context, sdk, target string) map[string]string {
	b := command(ctx, "clang", "-target", target, "-isysroot", sdk, "-std=c11", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CommandRangeLayout", cPath)
	var ast astNode
	must(json.Unmarshal(b, &ast))
	facts := map[string]string{}
	walk(ast, func(n astNode) {
		if n.Kind == "EnumConstantDecl" {
			walk(n, func(v astNode) {
				if v.Kind == "ConstantExpr" {
					facts[n.Name] = v.Value
				}
			})
		}
	})
	if len(facts) != 31 {
		panic(fmt.Sprintf("incomplete SDK layout facts %d", len(facts)))
	}
	return facts
}
func writeCapture(path string, c capture) {
	b, e := json.MarshalIndent(c, "", "  ")
	must(e)
	must(os.MkdirAll(filepath.Dir(path), 0755))
	must(os.WriteFile(path, append(b, '\n'), 0644))
}
func collect(ctx context.Context, dir, out string, small bool) capture {
	if runtime.GOOS != "darwin" {
		panic("native capture requires macOS")
	}
	sdk := strings.TrimSpace(string(command(ctx, "xcrun", "--show-sdk-path")))
	c := capture{Schema: 1, Scope: "SDK-structured signing-layout dylibs, not executable/loadable-code claims. C-generated files grow a zero-padded LC_ID_DYLIB, or repeat LC_RPATH commands; command ranges and segment offsets remain aligned. Full-file hashes cover every native operation. Two-target Clang AST enum values prove SDK structure layout/constants, not execution of Apple private implementation. Pinned complete Apple allocation/removal AST evidence is recorded separately by source hash. All accepted signed outputs must pass native strict verification. Portable replay constructs identical sparse recipes and uses only the public Go APIs, comparing native success/failure and all complete output hashes; display success additionally checks architecture, identifier, and signature presence.", Host: strings.TrimSpace(string(command(ctx, "sw_vers"))), Compiler: strings.Split(string(command(ctx, "clang", "--version")), "\n")[0], SDK: filepath.Base(sdk), Sources: map[string]string{}, Layouts: map[string]map[string]string{}}
	for _, p := range append(sourcePaths(), "/usr/bin/codesign") {
		c.Sources[p] = hash(read(p))
	}
	c.Sources["sdk:mach-o/loader.h"] = hash(read(filepath.Join(sdk, "usr/include/mach-o/loader.h")))
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		c.Layouts[target] = layout(ctx, sdk, target)
	}
	if !reflect.DeepEqual(c.Layouts["arm64-apple-macos27"], c.Layouts["x86_64-apple-macos27"]) {
		panic("cross-target SDK layout changed")
	}
	generator := filepath.Join(dir, "generate-command-ranges")
	command(ctx, "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", cPath, "-o", generator)
	for _, r := range recipes() {
		if small && r.DylibSize > 1<<20 {
			continue
		}
		path := filepath.Join(dir, "commands.dylib")
		command(ctx, generator, path, strconv.FormatUint(uint64(r.DylibSize), 10), strconv.FormatUint(uint64(r.Rpaths), 10), strconv.FormatUint(uint64(r.CPU), 10), strconv.Itoa(boolInt(r.Text)), strconv.FormatUint(uint64(r.Platform), 10))
		row := observation{Recipe: r, Initial: snapshot(path, "initial")}
		for _, op := range operations {
			value := native(path, op)
			row.Operations = append(row.Operations, value)
			fmt.Printf("native %-28s %-16s exit=%d size=%d sha256=%s\n", r.Name, op, value.Exit, value.Size, value.SHA256)
		}
		if row.Operations[1].Exit == 0 && row.Operations[3].Exit != 0 {
			panic("native accepted signing but failed strict verification: " + r.Name)
		}
		if row.Operations[5].Exit == 0 && (row.Operations[5].SHA256 != row.Operations[4].SHA256 || row.Operations[5].Size != row.Operations[4].Size) {
			panic("native Mach-O dry run unexpectedly mutated bytes")
		}
		c.Cases = append(c.Cases, row)
		must(os.Remove(path))
		writeCapture(out, c)
	}
	return c
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func materialize(path string, r recipe) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	must(e)
	defer f.Close()
	extra := uint64(80 * boolInt(r.Text))
	commands := uint64(168) + extra + uint64(r.DylibSize) + uint64(r.Rpaths)*24 + uint64(boolInt(r.Platform != 0))*24
	textEnd := (32 + commands + 32 + 16383) &^ uint64(16383)
	must(f.Truncate(int64(textEnd + 64)))
	write := func(at uint64, b []byte) {
		n, e := f.WriteAt(b, int64(at))
		must(e)
		if n != len(b) {
			panic(io.ErrShortWrite)
		}
	}
	w := binary.LittleEndian
	header := make([]byte, 32)
	w.PutUint32(header, 0xfeedfacf)
	w.PutUint32(header[4:], r.CPU)
	w.PutUint32(header[12:], 6)
	w.PutUint32(header[16:], 4+r.Rpaths+uint32(boolInt(r.Platform != 0)))
	w.PutUint32(header[20:], uint32(commands))
	write(0, header)
	segment := func(name string, vm, off, size uint64, prot uint32) []byte {
		b := make([]byte, 72)
		w.PutUint32(b, 0x19)
		w.PutUint32(b[4:], 72)
		copy(b[8:], name)
		w.PutUint64(b[24:], vm)
		w.PutUint64(b[32:], (size+16383)&^uint64(16383))
		w.PutUint64(b[40:], off)
		w.PutUint64(b[48:], size)
		w.PutUint32(b[56:], prot)
		w.PutUint32(b[60:], prot)
		return b
	}
	text := segment("__TEXT", 0x100000000, 0, textEnd, 5)
	w.PutUint32(text[4:], 72+uint32(extra))
	w.PutUint32(text[64:], uint32(boolInt(r.Text)))
	write(32, text)
	if r.Text {
		section := make([]byte, 80)
		copy(section, "__text")
		copy(section[16:], "__TEXT")
		w.PutUint64(section[32:], 0x100000000+textEnd-16)
		w.PutUint64(section[40:], 4)
		w.PutUint32(section[48:], uint32(textEnd-16))
		w.PutUint32(section[52:], 2)
		w.PutUint32(section[64:], 0x80000400)
		write(104, section)
		instruction := []byte{0xc0, 0x03, 0x5f, 0xd6}
		if r.CPU == 0x1000007 {
			instruction = []byte{0xc3, 0x90, 0x90, 0x90}
		}
		write(textEnd-16, instruction)
	}
	d := make([]byte, 40)
	w.PutUint32(d, 13)
	w.PutUint32(d[4:], r.DylibSize)
	w.PutUint32(d[8:], 24)
	copy(d[24:], "libsample.dylib")
	write(104+extra, d)
	write(104+extra+uint64(r.DylibSize), segment("__LINKEDIT", 0x100000000+textEnd, textEnd, 64, 1))
	uuid := make([]byte, 24)
	w.PutUint32(uuid, 27)
	w.PutUint32(uuid[4:], 24)
	copy(uuid[8:], "0123456789abcdef")
	write(176+extra+uint64(r.DylibSize), uuid)
	rpath := make([]byte, 24)
	w.PutUint32(rpath, 0x8000001c)
	w.PutUint32(rpath[4:], 24)
	w.PutUint32(rpath[8:], 12)
	copy(rpath[12:], "/usr/lib")
	for i := uint32(0); i < r.Rpaths; i++ {
		write(200+extra+uint64(r.DylibSize)+uint64(i)*24, rpath)
	}
	if r.Platform != 0 {
		build := make([]byte, 24)
		w.PutUint32(build, 0x32)
		w.PutUint32(build[4:], 24)
		w.PutUint32(build[8:], r.Platform)
		w.PutUint32(build[12:], 11<<16)
		w.PutUint32(build[16:], 27<<16)
		write(200+extra+uint64(r.DylibSize)+uint64(r.Rpaths)*24, build)
	}
	must(f.Sync())
}
func portable(ctx context.Context, path string, expected outcome, cpu uint32) outcome {
	var err error
	switch expected.Operation {
	case "sign", "resign", "dryrun":
		err = codesign.Sign(ctx, path, codesign.SignOptions{Identifier: identifier, Force: expected.Operation != "sign", DryRun: expected.Operation == "dryrun"})
	case "verify":
		_, err = codesign.Verify(ctx, path, codesign.VerifyOptions{})
	case "remove":
		err = codesign.RemoveSignature(ctx, path)
	default:
		var report *codesign.Report
		report, err = codesign.Inspect(ctx, path)
		if err == nil {
			if len(report.Architectures) != 1 || report.Architectures[0].CPU != cpu {
				panic("inspection architecture differs")
			}
			sig := report.Architectures[0].Signature
			if sig == nil {
				err = codesign.ErrUnsigned
			} else if len(sig.Directories) != 1 || sig.Directories[0].Identifier != identifier || expected.Exit == 0 && !strings.Contains(expected.Diagnostic, "Identifier="+identifier+"\n") {
				panic("native/Go display identifier changed")
			}
			if sig != nil && expected.Exit == 0 {
				d := sig.Directories[0]
				if !strings.Contains(expected.Diagnostic, "CodeDirectory v="+fmt.Sprintf("%x", d.Version)+" ") || !strings.Contains(expected.Diagnostic, "\nCDHash="+d.CDHash+"\n") || !strings.Contains(expected.Diagnostic, fmt.Sprintf("Page size=%d\n", uint64(1)<<d.PageExponent)) {
					panic("native/Go CodeDirectory display fields differ")
				}
			}
		}
	}
	result := snapshot(path, expected.Operation)

	if err != nil {
		result.Exit = 1
		result.Diagnostic = err.Error()
	}
	if (result.Exit == 0) != (expected.Exit == 0) || result.Size != expected.Size || result.SHA256 != expected.SHA256 {
		panic(fmt.Sprintf("portable %s differs: actual=%+v native=%+v", expected.Operation, result, expected))
	}
	return result
}
func validateCapture(c capture, small bool) {
	if c.Schema != 1 {
		panic("unknown schema")
	}
	var inventory []recipe
	for _, row := range c.Cases {
		inventory = append(inventory, row.Recipe)
	}
	expectedRecipes := recipes()
	if small {
		expectedRecipes = expectedRecipes[:6]
	}
	if !reflect.DeepEqual(inventory, expectedRecipes) {
		panic("native case inventory incomplete or changed")
	}
	for _, p := range sourcePaths() {
		if hash(read(p)) != c.Sources[p] {
			panic("stale native source provenance: " + p)
		}
	}
	if len(c.Layouts) != 2 || len(c.Layouts["arm64-apple-macos27"]) != 31 || !reflect.DeepEqual(c.Layouts["arm64-apple-macos27"], c.Layouts["x86_64-apple-macos27"]) {
		panic("incomplete SDK target layout inventory")
	}
	for _, row := range c.Cases {
		if len(row.Operations) != len(operations) {
			panic("native operation inventory incomplete")
		}
		for i, operation := range row.Operations {
			if operation.Operation != operations[i] {
				panic("native operation ordering changed")
			}
		}
	}
}
func replay(ctx context.Context, dir string, c capture, nativeVerify, small bool, exportDir, corpusDigest string) {
	validateCapture(c, small)
	manifest := exportManifest{Schema: 1, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CorpusSHA256: corpusDigest, Sources: productionHashes()}
	if exportDir != "" {
		must(os.MkdirAll(exportDir, 0755))
		entries, e := os.ReadDir(exportDir)
		must(e)
		if len(entries) != 0 {
			panic("export directory must be empty")
		}
	}
	for _, row := range c.Cases {
		path := filepath.Join(dir, "commands.dylib")

		materialize(path, row.Recipe)
		if initial := snapshot(path, "initial"); initial != row.Initial {
			panic(fmt.Sprintf("C/Go recipe differs: %+v %+v", initial, row.Initial))
		}
		if len(row.Operations) != len(operations) {
			panic("native operation inventory incomplete")
		}
		for i, expected := range row.Operations {
			if expected.Operation != operations[i] {
				panic("native operation ordering changed")
			}
			actual := portable(ctx, path, expected, row.Recipe.CPU)
			if nativeVerify && actual.Exit == 0 && (expected.Operation == "sign" || expected.Operation == "resign" || expected.Operation == "dryrun") {
				if verified := native(path, "verify"); verified.Exit != 0 {
					panic(fmt.Sprintf("native rejected Go signature: %+v", verified))
				}
			}
			if exportDir != "" && actual.Exit == 0 && (expected.Operation == "sign" || expected.Operation == "resign") {
				entry := exportEntry{Recipe: row.Recipe.Name, Operation: expected.Operation, File: row.Recipe.Name + "-" + expected.Operation + ".dylib.gz", Size: actual.Size, SHA256: actual.SHA256}
				exportFile(path, filepath.Join(exportDir, entry.File), entry)
				manifest.Entries = append(manifest.Entries, entry)
			}
			fmt.Printf("portable %-26s %-16s status/hash match\n", row.Recipe.Name, expected.Operation)
		}
		must(os.Remove(path))
	}
	if exportDir != "" {
		writeJSON(filepath.Join(exportDir, "manifest.json"), manifest)
	}
}
func main() {
	mode := flag.String("mode", "replay", "capture, replay, or verify-import")
	out := flag.String("out", corpusPath, "native capture destination")
	corpus := flag.String("corpus", corpusPath, "native corpus to replay or compare")
	check := flag.Bool("check", false, "compare native case observations against the retained corpus")
	verify := flag.Bool("native-verify", false, "native strict verification of every accepted Go signing output")
	small := flag.Bool("small", false, "development only: six small controls, never a complete acceptance run")
	exportDir := flag.String("export-dir", "", "archive every accepted Go sign/resign result with full-hash manifest")
	importDir := flag.String("import-dir", "", "directory containing producer artifact directories with manifest.json")
	requiredHosts := flag.String("required-hosts", "linux,windows", "comma-separated producer platforms required by verify-import")
	flag.Parse()
	ctx := context.Background()
	dir, e := os.MkdirTemp("", "codesign-command-ranges-")
	must(e)
	defer os.RemoveAll(dir)
	if runtime.GOOS == "darwin" {
		dir, e = filepath.EvalSymlinks(dir)
		must(e)
	}
	if *mode == "capture" {
		var baseline capture
		if *check {
			must(json.Unmarshal(read(*corpus), &baseline))
		}
		c := collect(ctx, dir, *out, *small)
		if *check {
			if !reflect.DeepEqual(c.Cases, baseline.Cases) || !reflect.DeepEqual(c.Layouts, baseline.Layouts) {
				panic("native command-range observations changed")
			}
		}
		return
	}
	if *mode != "replay" && *mode != "verify-import" {
		panic("unknown mode")
	}
	if *verify && runtime.GOOS != "darwin" {
		panic("native verification requires macOS")
	}
	var c capture
	corpusBytes := read(*corpus)
	must(json.Unmarshal(corpusBytes, &c))
	if *mode == "verify-import" {
		if runtime.GOOS != "darwin" {
			panic("native import verification requires macOS")
		}
		validateCapture(c, *small)
		verifyImports(dir, *importDir, strings.Split(*requiredHosts, ","), c, hash(corpusBytes))
		return
	}
	scratch := filepath.Join(dir, "working")
	must(os.Mkdir(scratch, 0700))
	ctx = codesign.WithWorkingStorage(ctx, codesign.WorkingStorageOptions{MemoryBytes: 64 << 10, TemporaryDirectory: scratch})
	replay(ctx, dir, c, *verify, *small, *exportDir, hash(corpusBytes))
	entries, e := os.ReadDir(scratch)
	must(e)
	if len(entries) != 0 {
		panic("working-storage artifacts leaked")
	}
}

type exportEntry struct {
	Recipe, Operation, File string
	Size                    int64
	SHA256                  string
}
type exportManifest struct {
	Schema                     int
	GOOS, GOARCH, CorpusSHA256 string
	Sources                    map[string]string
	Entries                    []exportEntry
}

func productionHashes() map[string]string {
	result := map[string]string{"go.mod": hash(read("go.mod")), "go.sum": hash(read("go.sum"))}
	for _, root := range []string{"pkg", "internal"} {
		must(filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				result[filepath.ToSlash(path)] = hash(read(path))
			}
			return nil
		}))
	}
	return result
}
func writeJSON(path string, value any) {
	b, e := json.MarshalIndent(value, "", "  ")
	must(e)
	must(os.WriteFile(path, append(b, '\n'), 0644))
}
func exportFile(source, path string, entry exportEntry) {
	input, e := os.Open(source)
	must(e)
	defer input.Close()
	output, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	z, e := gzip.NewWriterLevel(output, gzip.BestSpeed)
	must(e)
	h := sha256.New()
	n, e := io.CopyBuffer(io.MultiWriter(z, h), io.LimitReader(input, entry.Size+1), make([]byte, 64<<10))
	must(e)
	must(z.Close())
	must(output.Sync())
	must(output.Close())
	if n != entry.Size || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
		panic("payload changed while exporting")
	}
}
func verifyImports(dir, importDir string, required []string, c capture, corpusDigest string) {
	if importDir == "" {
		panic("-import-dir is required")
	}
	manifests, e := filepath.Glob(filepath.Join(importDir, "*", "manifest.json"))
	must(e)
	if _, e := os.Stat(filepath.Join(importDir, "manifest.json")); e == nil {
		manifests = append(manifests, filepath.Join(importDir, "manifest.json"))
	}
	sort.Strings(manifests)
	seen := map[string]bool{}
	var expected []exportEntry
	for _, row := range c.Cases {
		for _, op := range row.Operations {
			if op.Exit == 0 && (op.Operation == "sign" || op.Operation == "resign") {
				expected = append(expected, exportEntry{Recipe: row.Recipe.Name, Operation: op.Operation, File: row.Recipe.Name + "-" + op.Operation + ".dylib.gz", Size: op.Size, SHA256: op.SHA256})
			}
		}
	}
	currentSources := productionHashes()
	for _, path := range manifests {
		var manifest exportManifest
		must(json.Unmarshal(read(path), &manifest))
		if manifest.Schema != 1 || manifest.CorpusSHA256 != corpusDigest || !reflect.DeepEqual(manifest.Sources, currentSources) || !reflect.DeepEqual(manifest.Entries, expected) {
			panic("foreign producer provenance/inventory differs: " + path)
		}
		if manifest.GOOS != "linux" && manifest.GOOS != "windows" && manifest.GOOS != "darwin" {
			panic("unsupported producer host")
		}
		if seen[manifest.GOOS] {
			panic("duplicate producer host")
		}
		seen[manifest.GOOS] = true
		if manifest.GOARCH != "amd64" && manifest.GOARCH != "arm64" {
			panic("unsupported producer architecture")
		}
		files, e := os.ReadDir(filepath.Dir(path))
		must(e)
		if len(files) != len(expected)+1 {
			panic("foreign artifact file inventory differs")
		}
		for _, entry := range manifest.Entries {
			input, e := os.Open(filepath.Join(filepath.Dir(path), entry.File))
			must(e)
			z, e := gzip.NewReader(input)
			must(e)
			materialized := filepath.Join(dir, "imported.dylib")
			output, e := os.OpenFile(materialized, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			must(e)
			h := sha256.New()
			n, e := io.CopyBuffer(io.MultiWriter(output, h), io.LimitReader(z, entry.Size+1), make([]byte, 64<<10))
			must(e)
			must(z.Close())
			must(input.Close())
			must(output.Close())
			if n != entry.Size || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
				panic("foreign output size/hash differs: " + entry.File)
			}
			if verified := native(materialized, "verify"); verified.Exit != 0 {
				panic(fmt.Sprintf("native rejected %s %s: %+v", manifest.GOOS, entry.File, verified))
			}
			fmt.Printf("native verified %-7s %s\n", manifest.GOOS, entry.File)
			must(os.Remove(materialized))
		}
	}
	for _, host := range required {
		if host == "" || !seen[host] {
			panic("missing required producer host: " + host)
		}
	}
}
