package codesign

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestCompressionObservationPolicy(t *testing.T) {
	for _, name := range []string{"disabled", "stored", "empty", "query-error", "cancel-before", "cancel-query"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx = context.WithValue(ctx, preserveCompressionKey{}, name != "disabled")
			if name == "cancel-before" {
				cancel()
			}
			calls := 0
			kind, err := captureCompressionUsing(ctx, nil, func(context.Context, *os.File, int) (decmpfs.Info, error) {
				calls++
				if name == "cancel-query" {
					cancel()
				}
				if name == "query-error" {
					return decmpfs.Info{}, os.ErrPermission
				}
				info := decmpfs.Info{Type: 4, StoredSize: 100}
				if name == "empty" {
					info.StoredSize = 0
				}
				return info, nil
			})
			wantCalls := 1
			if name == "disabled" || name == "cancel-before" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatal("query ordering", calls)
			}
			wantKind := uint32(0)
			if name == "stored" {
				wantKind = 4
			}
			if kind != wantKind || !errors.Is(err, ctx.Err()) {
				t.Fatal(kind, err)
			}
		})
	}
}

type compressionAdmission struct {
	statErr, probeErr error
	closed            bool
	size              int64
	cancel            context.CancelFunc
}

func (i *compressionAdmission) Snapshot() (hostdata.CompressionFileState, error) {
	return hostdata.CompressionFileState{Size: i.size, Stat: hostdata.StatCopySource{Mode: 0100755}}, i.statErr
}
func (i *compressionAdmission) ProbeWrite() error {
	if i.cancel != nil {
		i.cancel()
	}
	return i.probeErr
}
func (i *compressionAdmission) Duplicate() (hostdata.CompressionStream, error) {
	return nil, os.ErrPermission
}
func (i *compressionAdmission) Close() error { i.closed = true; return nil }

func TestCompressionAdmissionPolicy(t *testing.T) {
	for _, name := range []string{"uncompressed", "open-denied", "stat-denied", "eligible-decline", "write-denied", "duplicate-denied", "cancel-before", "cancel-after-admission"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			input := &compressionAdmission{size: 65536}
			switch name {
			case "stat-denied":
				input.statErr = os.ErrPermission
			case "eligible-decline":
				input.size = 100
			case "write-denied":
				input.probeErr = os.ErrPermission
			case "cancel-before":
				cancel()
			case "cancel-after-admission":
				input.cancel = cancel
			}
			kind := uint32(3)
			if name == "uncompressed" {
				kind = 0
			}
			calls := 0
			err := recompressCommitted(ctx, "hello", kind, func(context.Context) (hostdata.CompressionInput, error) {
				calls++
				if name == "open-denied" {
					return nil, os.ErrPermission
				}
				return input, nil
			})
			if name == "cancel-before" || name == "cancel-after-admission" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if name == "open-denied" || name == "stat-denied" {
				var detail *VerificationError
				if !errors.Is(err, os.ErrPermission) || !errors.As(err, &detail) || detail.Diagnostic != "internal error in Code Signing subsystem" {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal("post-admission failure changed native signing result", err)
			}
			if name == "uncompressed" || name == "cancel-before" {
				if calls != 0 || input.closed {
					t.Fatal("unexpected acquisition")
				}
			} else if calls != 1 || input.closed != (name != "open-denied") {
				t.Fatal("admission ownership", calls, input.closed)
			}
		})
	}
}

func TestCompressionPrivateStage(t *testing.T) {
	for _, name := range []string{"default", "scoped", "cancel", "create-failure", "close-failure", "remove-failure"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			dir := t.TempDir()
			if name != "default" {
				if name == "create-failure" {
					dir = filepath.Join(dir, "missing")
				}
				var storage *workingStorage
				var err error
				ctx, storage, err = beginWorkingStorage(WithWorkingStorage(ctx, WorkingStorageOptions{TemporaryDirectory: dir}))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := storage.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			if name == "cancel" {
				cancel()
			}
			var cleanup error
			stage, err := newCompressionStage(ctx, &cleanup)
			if name == "cancel" || name == "create-failure" {
				want := context.Canceled
				if name == "create-failure" {
					want = os.ErrNotExist
				}
				if stage != nil || !errors.Is(err, want) || cleanup != nil {
					t.Fatal(stage, err, cleanup)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			path := stage.Name()
			if name == "scoped" && filepath.Dir(path) != dir {
				t.Fatal("stage escaped configured directory", path)
			}
			if _, err := stage.WriteAt([]byte("private bytes"), 0); err != nil {
				t.Fatal(err)
			}
			if name == "close-failure" || name == "remove-failure" {
				if err := stage.scratchFile.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if name == "remove-failure" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			err = stage.Close()
			if name == "close-failure" || name == "remove-failure" {
				if !errors.Is(err, os.ErrClosed) || !errors.Is(cleanup, os.ErrClosed) {
					t.Fatal(err, cleanup)
				}
			} else if err != nil || cleanup != nil {
				t.Fatal(err, cleanup)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("scratch retained", err)
			}
		})
	}
}
