package codesign

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestCMSDirectorySizeBoundary(t *testing.T) {
	identity := testIdentity(t, "rsa")
	prefix := testDirectories(t)[0]
	for _, size := range []int{16<<20 - 1, 16 << 20, 16<<20 + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			raw := make([]byte, size)
			copy(raw, prefix)
			be.PutUint32(raw[4:], uint32(size))
			cms, err := SignCMS(t.Context(), identity, [][]byte{raw}, time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyCMS(cms, [][]byte{raw}); err != nil {
				t.Fatal("owned binding", err)
			}
			encoded := superblob(MagicSignature, []Blob{{Slot: SlotDirectory, Data: raw}})
			ctx, storage, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: t.TempDir()}))
			if err != nil {
				t.Fatal(err)
			}
			defer storage.Close()
			view, err := parseSignatureView(codeSource{ctx, byteOutput(encoded)}, false)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := view.cmsBinding()
			if err != nil {
				t.Fatal("borrowed binding", err)
			}
			if _, err := verifyCMSBound(cms, bound); err != nil {
				t.Fatal(err)
			}
			if storage.stats.PeakMemoryBytes > transferBufferSize {
				t.Fatal("borrowed hash exceeded budget", storage.stats)
			}
			// Extended padding participates in the cryptographic binding even
			// though it contains neither header fields nor page hashes.
			raw[len(raw)-1] ^= 1
			if _, err := VerifyCMS(cms, [][]byte{raw}); !errors.Is(err, ErrInvalid) {
				t.Fatal("changed large directory accepted", err)
			}
		})
	}
}
