package codesign

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testBundleCode(data []byte) codeSource {
	return codeSource{context.Background(), byteOutput(data)}
}

func TestBundleHeldSources(t *testing.T) {
	for _, mode := range []string{"reuse", "cancel", "missing", "closed-root", "replaced", "truncated", "closed-file", "close-failure"} {
		t.Run(mode, func(t *testing.T) {
			b, err := openAppBundle(testBundle(t))
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			ctx := context.Background()
			name := b.executable
			if mode == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if mode == "missing" {
				name = "missing"
			}
			if mode == "closed-root" {
				if err := b.root.Close(); err != nil {
					t.Fatal(err)
				}
			}
			src, err := b.holdCode(ctx, name)
			if mode == "cancel" || mode == "missing" || mode == "closed-root" {
				if err == nil {
					t.Fatal("invalid source accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			held := b.sources[name]
			p := filepath.Join(b.path, name)
			switch mode {
			case "replaced":
				if err := b.root.Rename(name, name+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, fixture(t, "unsigned-arm64"), 0755); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.Truncate(p, 17); err != nil {
					t.Fatal(err)
				}
			case "closed-file":
				if err := held.file.Close(); err != nil {
					t.Fatal(err)
				}
			case "close-failure":
				fault := errors.New("close fault")
				held.closer.close = func() error { return errors.Join(fault, held.file.Close()) }
				if err := b.close(); !errors.Is(err, fault) {
					t.Fatal(err)
				}
				return
			}
			second, err := b.holdCode(ctx, name)
			if mode != "reuse" {
				if err == nil {
					t.Fatal("changed source accepted")
				}
				return
			}
			if err != nil || src.source.reader != second.source.reader || len(b.sources) != 1 {
				t.Fatal("descriptor not retained", err)
			}
			got, err := second.read(0, uint64(second.source.size))
			if err != nil || !bytes.Equal(got, fixture(t, "unsigned-arm64")) {
				t.Fatal("held source bytes", err)
			}
			if err := b.close(); err != nil {
				t.Fatal(err)
			}
			if _, err := held.file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("held source leaked", err)
			}
		})
	}
}

func TestBundleSourceWriteLifecycle(t *testing.T) {
	for _, phase := range []string{"commit", "dryrun", "cancel", "replace-before", "grow-before", "read-fault", "grow-during", "close-fault", "grow-after", "cancel-commit"} {
		t.Run(phase, func(t *testing.T) {
			b, err := openAppBundle(testBundle(t))
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			src, err := b.holdCode(ctx, b.executable)
			if err != nil {
				t.Fatal(err)
			}
			held := b.sources[b.executable]
			defer held.file.Close()
			out, err := signCodeSource(src, SignOptions{Identifier: b.identifier})
			if err != nil {
				t.Fatal(err)
			}
			fault := errors.New("injected source failure")
			p := filepath.Join(b.path, b.executable)
			original := readTestFile(t, p)
			grow := func() {
				t.Helper()
				f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.Write([]byte{99})
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			switch phase {
			case "cancel":
				cancel()
			case "replace-before":
				if err := b.root.Rename(b.executable, b.executable+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, original, 0755); err != nil {
					t.Fatal(err)
				}
			case "grow-before":
				grow()
			case "read-fault":
				out.reader = transferReaderFunc(func([]byte, int64) (int, error) { return 0, fault })
			case "grow-during":
				reader := out.reader
				once := false
				out.reader = transferReaderFunc(func(p []byte, off int64) (int, error) {
					if !once {
						once = true
						grow()
					}
					return reader.ReadAt(p, off)
				})
			case "close-fault":
				held.closer.close = func() error { return errors.Join(fault, held.file.Close()) }
			}
			prepared, err := prepareBundleExecutable(ctx, bundleWrite{name: b.executable, output: out, bundle: b}, phase == "dryrun")
			switch phase {
			case "commit", "grow-after", "cancel-commit":
				if err != nil || prepared == nil {
					t.Fatal("preparation", err)
				}
				defer prepared.replacement.Close()
				if !held.released {
					t.Fatal("borrowed reader retained through rename")
				}
				if _, err := held.file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("borrowed handle open", err)
				}
				if phase == "grow-after" {
					grow()
				}
				if phase == "cancel-commit" {
					cancel()
				}
				err = prepared.commit(ctx)
				if phase == "commit" {
					if err != nil {
						t.Fatal(err)
					}
					want, err := SignBytes(context.Background(), original, SignOptions{Identifier: b.identifier})
					if err != nil || !bytes.Equal(want, readTestFile(t, p)) {
						t.Fatal("staged output bytes", err)
					}
					return
				}
			case "dryrun":
				if err != nil || prepared != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(original, readTestFile(t, p)) {
					t.Fatal("dryrun changed bytes")
				}
				return
			}
			if err == nil {
				t.Fatal("failed lifecycle committed")
			}
			if phase == "read-fault" || phase == "close-fault" {
				if !errors.Is(err, fault) {
					t.Fatal("lost cause", err)
				}
			}
			if prepared != nil {
				if err := prepared.replacement.Close(); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := os.ReadDir(filepath.Dir(p))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "hello" && entry.Name() != "hello.old" {
					t.Fatal("staging leak", entry.Name())
				}
			}
			actual := readTestFile(t, p)
			if strings.HasPrefix(phase, "grow-") {
				if !bytes.Equal(actual, append(bytes.Clone(original), 99)) {
					t.Fatal("failure replaced changed input")
				}
			} else if !bytes.Equal(actual, original) {
				t.Fatal("failure modified input")
			}
		})
	}
}

func TestBundleSourcePlanningFailures(t *testing.T) {
	for _, mode := range []string{"cancel", "options", "container", "read", "unsigned", "empty-count", "overflow", "negative-count"} {
		t.Run(mode, func(t *testing.T) {
			src := testBundleCode(fixture(t, "unsigned-arm64"))
			opts := SignOptions{Identifier: "test"}
			fault := errors.New("reader failure")
			switch mode {
			case "cancel":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				src.ctx = ctx
			case "options":
				opts.Identifier = ""
			case "container":
				src = testBundleCode([]byte("bad"))
			case "read":
				src.source.reader = transferReaderFunc(func([]byte, int64) (int, error) { return 0, fault })
			case "unsigned":
				if _, err := verifyCodeSource(src, VerifyOptions{}); !errors.Is(err, ErrUnsigned) {
					t.Fatal(err)
				}
				return
			case "empty-count":
				scope := newBundleScan()
				scope.bytes = math.MaxInt64
				if err := scope.addBytes(0); err != nil || scope.bytes != math.MaxInt64 {
					t.Fatal(err)
				}
				return
			case "overflow", "negative-count":
				scope := newBundleScan()
				scope.bytes = math.MaxInt64
				n := int64(1)
				if mode == "negative-count" {
					n = -1
				}
				if err := scope.addBytes(n); !errors.Is(err, ErrUnsupported) || scope.bytes != math.MaxInt64 {
					t.Fatal(err)
				}
				return
			}
			if _, err := signCodeSource(src, opts); err == nil {
				t.Fatal("bad source signed")
			}
		})
	}
	// A failing source during inspection/verification must never produce success.
	src := codeSource{context.Background(), outputSource{transferReaderFunc(func([]byte, int64) (int, error) { return 0, io.ErrUnexpectedEOF }), 0, 1024}}
	if r, err := verifyCodeSource(src, VerifyOptions{}); err == nil || r != nil && r.Valid {
		t.Fatal(r, err)
	}
}
