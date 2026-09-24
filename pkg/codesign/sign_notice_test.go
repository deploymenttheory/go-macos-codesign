package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReplacementNotificationBoundary(t *testing.T) {
	for _, format := range []string{"macho", "dmg", "bundle"} {
		for _, failure := range []string{"none", "cancel-before", "cancel-in-notice", "bad-options", "missing-main", "scan"} {
			t.Run(format+"/"+failure, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				path := filepath.Join(t.TempDir(), "hello")
				data := fixture(t, "unsigned-arm64")
				if format == "bundle" {
					path = testBundle(t)
				} else {
					if format == "dmg" {
						data = testDMG(t)
					}
					if err := os.WriteFile(path, data, 0755); err != nil {
						t.Fatal(err)
					}
				}
				if err := Sign(ctx, path, SignOptions{Identifier: "old"}); err != nil {
					t.Fatal(err)
				}
				main := path
				if format == "bundle" {
					main = filepath.Join(path, "Contents/MacOS/hello")
				}
				before := readTestFile(t, main)
				notices := 0
				opts := SignOptions{Force: true, Identifier: "new", OnReplace: func() {
					notices++
					if !bytes.Equal(before, readTestFile(t, main)) {
						t.Fatal("notification happened after mutation")
					}
					if failure == "cancel-in-notice" {
						cancel()
					}
				}}
				wantNotices, wantFailure := 1, failure != "none"
				switch failure {
				case "cancel-before":
					cancel()
					wantNotices = 0
				case "bad-options":
					opts.PageSize = 3
				case "missing-main":
					if err := os.Remove(main); err != nil {
						t.Fatal(err)
					}
					wantNotices = 0
				case "scan":
					if format == "bundle" {
						bundleFile(t, path, "unsupported-root-file", []byte("rejected before signing"))
					} else {
						wantFailure = false
					}
				}
				err := Sign(ctx, path, opts)
				if notices != wantNotices || (err != nil) != wantFailure {
					t.Fatalf("notices=%d want=%d, err=%v, want failure=%t", notices, wantNotices, err, wantFailure)
				}
				if wantFailure && failure != "missing-main" && !bytes.Equal(before, readTestFile(t, main)) {
					t.Fatal("failed operation changed input")
				}
			})
		}
	}
}

func TestReplacementNotificationIsPathOnly(t *testing.T) {
	ctx := context.Background()
	for _, format := range []string{"macho", "dmg"} {
		t.Run(format, func(t *testing.T) {
			input := fixture(t, "unsigned-universal")
			if format == "dmg" {
				input = testDMG(t)
			}
			notices := 0
			opts := SignOptions{Identifier: "id", Force: true, OnReplace: func() { notices++ }}
			signed, err := SignBytes(ctx, input, opts)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := SignBytes(ctx, signed, opts); err != nil || notices != 0 {
				t.Fatal("byte signing notified", notices, err)
			}
			path := filepath.Join(t.TempDir(), "code")
			for _, data := range [][]byte{input, []byte("malformed"), signed} {
				if err := os.WriteFile(path, data, 0755); err != nil {
					t.Fatal(err)
				}
				notices = 0
				_ = Sign(ctx, path, opts)
				want := 0
				if bytes.Equal(data, signed) {
					want = 1
				}
				if notices != want {
					t.Fatalf("notices=%d want=%d", notices, want)
				}
			}
			opts.Force = false
			notices = 0
			if err := Sign(ctx, path, opts); !errors.Is(err, ErrSigned) || notices != 0 {
				t.Fatal("no-force notification", notices, err)
			}
		})
	}
}
