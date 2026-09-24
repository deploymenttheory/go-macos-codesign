package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDMGDryRunLifecycle(t *testing.T) {
	ctx := context.Background()
	input := testDMG(t)
	path := filepath.Join(t.TempDir(), "image.dmg")
	if err := os.WriteFile(path, input, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, path, SignOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	dry := readTestFile(t, path)
	// Captured from the independent native ad-hoc dry run: requirements and
	// empty CMS only. Footer/payload equality is covered by native whole images.
	want, err := hex.DecodeString("fade0cc00000003000000002000000020000001c0001000000000028fade0c010000000c00000000fade0b0100000008")
	if err != nil {
		t.Fatal(err)
	}
	offset := len(input) - 512
	if !bytes.Equal(dry[:offset], input[:offset]) || !bytes.Equal(dry[offset:len(dry)-512], want) {
		t.Fatal("native dry-run components or payload differ")
	}
	if _, err := ParseSignature(want); !errors.Is(err, ErrFormat) {
		t.Fatal("strict parser accepted missing directory", err)
	}
	if _, err := VerifyBytes(ctx, dry, VerifyOptions{}); !errors.Is(err, ErrUnsigned) {
		t.Fatal("dry-run image is not unsigned", err)
	}
	for _, signed := range []bool{false, true} {
		if signed {
			if err := Sign(ctx, path, SignOptions{Identifier: "real"}); err != nil {
				t.Fatal(err)
			}
		}
		if err := Sign(ctx, path, SignOptions{DryRun: true, Force: true}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(readTestFile(t, path), dry) {
			t.Fatal("repeat/force dry-run drift")
		}
	}
	// The byte API retains its construction-only contract even with DryRun set.
	out, err := SignBytes(ctx, dry, SignOptions{Identifier: "byte-api", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBytes(ctx, out, VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readTestFile(t, path), dry) {
		t.Fatal("byte API wrote path")
	}
}

func TestDMGDryRunFailurePreservation(t *testing.T) {
	for _, kind := range []string{"signed-without-force", "bad-pagesize", "bad-entitlements", "bad-requirements", "cancelled", "certificate"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			data := testDMG(t)
			opts := SignOptions{Identifier: "test", DryRun: true}
			want := ErrFormat
			switch kind {
			case "signed-without-force":
				var err error
				data, err = SignBytes(ctx, data, SignOptions{Identifier: "old"})
				if err != nil {
					t.Fatal(err)
				}
				want = ErrSigned
			case "bad-pagesize":
				opts.PageSize = 3
				want = nil
			case "bad-entitlements":
				opts.Entitlements = []byte("bad XML")
				opts.ForceLibraryEntitlements = true
				want = nil
			case "bad-requirements":
				opts.Requirements = []byte("bad requirements")
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "certificate":
				opts.Identity = testIdentity(t, "rsa")
				want = ErrUnsupported
				opts.Timestamp = &TimestampOptions{TrustedRoots: AppleTimestampRoots(), Provider: func(context.Context, []byte) ([]byte, error) {
					t.Fatal("unsupported dry run called TSA")
					return nil, nil
				}}
			}
			path := filepath.Join(t.TempDir(), "image.dmg")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			err = Sign(ctx, path, opts)
			if err == nil || want != nil && !errors.Is(err, want) {
				t.Fatal("wrong failure", err)
			}
			after, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || !bytes.Equal(data, readTestFile(t, path)) {
				t.Fatal("failed dry run changed input")
			}
		})
	}
}

func TestDMGUnsignedContainerBounds(t *testing.T) {
	data := testDMG(t)
	ctx := context.Background()
	dry, err := signBytes(ctx, data, SignOptions{Identifier: "test"}, true)
	if err != nil {
		t.Fatal(err)
	}
	offset := len(data) - 512
	for _, kind := range []string{"duplicate", "overlap", "bad-magic", "bad-length", "padding", "alternate-only"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(dry)
			sig := bad[offset : len(bad)-512]
			switch kind {
			case "duplicate":
				be.PutUint32(sig[20:], SlotRequirements)
			case "overlap":
				be.PutUint32(sig[16:], 40)
				be.PutUint32(sig[28:], MagicRequirements)
				be.PutUint32(sig[32:], 20)
				be.PutUint32(sig[40:], MagicRequirements)
				be.PutUint32(sig[44:], 8)
				be.PutUint32(sig[20:], 99)
				be.PutUint32(sig[24:], 28)
			case "bad-magic":
				be.PutUint32(sig[28:], MagicCMS)
			case "bad-length":
				be.PutUint32(sig[32:], uint32(len(sig)))
			case "padding":
				be.PutUint32(sig[4:], uint32(len(sig)-1))
			case "alternate-only":
				be.PutUint32(sig[12:], 0x1000)
			}
			if _, err := InspectBytes(bad); !errors.Is(err, ErrFormat) {
				t.Fatal("malformed unsigned container accepted", err)
			}
		})
	}
	signed, err := SignBytes(ctx, data, SignOptions{Identifier: "test"})
	if err != nil {
		t.Fatal(err)
	}
	// A valid alternate directory without the primary remains malformed rather
	// than being downgraded to an unsigned dry-run container.
	be.PutUint32(signed[offset+12:], 0x1000)
	if _, err := InspectBytes(signed); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
}

func TestDMGDryRunCertificateEvidence(t *testing.T) {
	var record struct {
		Codesign   string `json:"codesign_sha256"`
		Driver     string `json:"driver"`
		DriverHash string `json:"driver_sha256"`
		Cases      []struct {
			Algorithm, State string
			Signal           int `json:"signal_number"`
			Exit             int
			Preserved        bool `json:"bytes_inode_mtime_preserved"`
		}
	}
	if err := json.Unmarshal(readTestFile(t, "../../spec/apple-dmg-dryrun-certificate.json"), &record); err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Baseline struct {
			Codesign string `json:"codesign_sha256"`
		}
	}
	if err := json.Unmarshal(readTestFile(t, "../../spec/compatibility.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(readTestFile(t, filepath.Join("../..", record.Driver)))
	if record.Codesign != inventory.Baseline.Codesign || hex.EncodeToString(sum[:]) != record.DriverHash || len(record.Cases) != 4 {
		t.Fatal("native failure provenance differs")
	}
	seen := map[string]bool{}
	for _, c := range record.Cases {
		key := c.Algorithm + "/" + c.State
		if c.Exit != -1 || c.Signal != 10 && c.Signal != 11 || !c.Preserved || seen[key] {
			t.Fatal("invalid native failure case", c)
		}
		seen[key] = true
	}
	for _, key := range []string{"rsa/unsigned", "rsa/signed", "p256/unsigned", "p256/signed"} {
		if !seen[key] {
			t.Fatal("missing case", key)
		}
	}
}
