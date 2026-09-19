package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

// Recording explicitly contacts Apple's public TSA using a public test key.
// Normal acceptance replays the recorded signature without network access.
func TestRecordAppleTimestamp(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_RECORD_TIMESTAMP") != "1" {
		t.Skip("opt-in timestamp fixture recording")
	}
	keychain := nativeTestKeychain(t, "rsa")
	path := filepath.Join(t.TempDir(), "timestamped")
	copyFixture(t, "unsigned-arm64", path)
	mustRun(t, apple(t), "--keychain", keychain, "-s", "Public codesign test identity rsa", "-i", "org.example.timestamp", "--timestamp", path)
	mustRun(t, apple(t), "--verify", "--strict", path)
	dir := filepath.Join(root, "testdata/timestamps")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	data := nativeRead(t, path)
	if err := os.WriteFile(filepath.Join(dir, "apple-rsa-arm64"), data, 0644); err != nil {
		t.Fatal(err)
	}
	_, display, code := run(t, apple(t), "-dvv", path)
	if code != 0 || !strings.Contains(display, "Timestamp=") {
		t.Fatalf("timestamp display: %d %s", code, display)
	}
	host, _, _ := run(t, "/usr/bin/sw_vers")
	canonicalPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"schema": 1, "files": map[string]string{"apple-rsa-arm64": hash(data)}, "host": host, "codesign_sha256": hash(nativeRead(t, "/usr/bin/codesign")), "command": []string{"codesign", "--keychain", "<temporary public-test keychain>", "-s", "Public codesign test identity rsa", "-i", "org.example.timestamp", "--timestamp", "<unsigned-arm64 copy>"}, "native_strict_verified": true, "display": strings.ReplaceAll(display, canonicalPath, "<fixture>")}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestPortableTimestampReplay(t *testing.T) {
	ctx := context.Background()
	native := nativeRead(t, filepath.Join(root, "testdata/timestamps/apple-rsa-arm64"))
	r, err := codesign.InspectBytes(native)
	if err != nil {
		t.Fatal(err)
	}
	sig := r.Architectures[0].Signature
	metadata := sig.CertificateMetadata
	if metadata == nil || metadata.Timestamp == nil || r.Valid {
		t.Fatal("missing descriptive timestamp metadata")
	}
	id, err := codesign.LoadIdentityPEM(nativeRead(t, filepath.Join(root, "testdata/identities/rsa-identity.pem")), nil)
	if err != nil {
		t.Fatal(err)
	}
	anchor := nativeRead(t, filepath.Join(root, "testdata/chains/developer-id-2"))
	got, err := codesign.SignBytes(ctx, nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-arm64")), codesign.SignOptions{Identifier: "org.example.timestamp", Identity: id, SigningTime: metadata.SigningTime, Timestamp: &codesign.TimestampOptions{TrustedRoots: [][]byte{anchor}, Provider: func(_ context.Context, s []byte) ([]byte, error) {
		return metadata.Timestamp.Token, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	nativeEqual(t, "complete timestamped Mach-O", got, native)
	// Repeatable validation remains valid after the TSA's short-lived leaf
	// expires, because its certificate path is evaluated at authenticated genTime.
	vr, err := codesign.VerifyBytes(ctx, got, codesign.VerifyOptions{TrustedCertificates: id.Certificates, TimestampRoots: [][]byte{anchor}, CurrentTime: metadata.Timestamp.Time.AddDate(1, 0, 0)})
	if err != nil || !vr.Valid {
		t.Fatal("historical timestamp verification", err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "signed-timestamp-arm64")
	ca := filepath.Join(dir, "tsa-root.pem")
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	write(target, got)
	write(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor}))
	cert := filepath.Join(root, "testdata/identities/rsa-cert.pem")
	mustRun(t, binaryPath, "--verify", "--trust", cert, "--timestamp-root", ca, target)
	_, stderr, code := run(t, binaryPath, "--verify", "--trust", cert, target)
	if code != 1 || !strings.Contains(stderr, "timestamp authority") {
		t.Fatalf("untrusted timestamp accepted: %d %s", code, stderr)
	}
	_, display, code := run(t, binaryPath, "-dvv", target)
	wantDate := metadata.Timestamp.Time.UTC().Format("2 Jan 2006 at 15:04:05")
	if code != 0 || !strings.Contains(display, "Timestamp="+wantDate) || strings.Contains(display, "Signed Time=") {
		t.Fatalf("timestamp display: %d %s", code, display)
	}
	if runtime.GOOS == "darwin" {
		mustRun(t, apple(t), "--verify", "--strict", target)
		_, nativeDisplay, nativeCode := run(t, apple(t), "-dvv", target)
		if nativeCode != 0 || !strings.Contains(nativeDisplay, "Timestamp=") {
			t.Fatalf("native timestamp display: %d %s", nativeCode, nativeDisplay)
		}
		token := filepath.Join(dir, "token.der")
		write(token, metadata.Timestamp.Token)
		mustRun(t, "/usr/bin/openssl", "cms", "-verify", "-inform", "DER", "-in", token, "-noverify", "-out", filepath.Join(dir, "tstinfo.der"))
		mustRun(t, "/usr/bin/openssl", "ts", "-reply", "-token_in", "-in", token, "-text")
		leafPath, chainPath := filepath.Join(dir, "tsa-leaf.pem"), filepath.Join(dir, "tsa-chain.pem")
		write(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: metadata.Timestamp.SignerCertificate}))
		var chainPEM []byte
		for _, der := range metadata.Timestamp.Certificates {
			chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		write(chainPath, chainPEM)
		mustRun(t, "/usr/bin/openssl", "verify", "-attime", strconv.FormatInt(metadata.Timestamp.Time.Unix(), 10), "-purpose", "timestampsign", "-CAfile", ca, "-untrusted", chainPath, leafPath)
		verifyCMSWithOpenSSL(t, target, dir)
		bad := bytes.Clone(got)
		start := bytes.Index(bad, metadata.Timestamp.Token)
		if start < 0 {
			t.Fatal("timestamp bytes missing from signed file")
		}
		bad[start+len(metadata.Timestamp.Token)-1] ^= 1
		write(target, bad)
		_, _, nativeCode = run(t, apple(t), "--verify", "--strict", target)
		if nativeCode == 0 {
			t.Fatal("Apple accepted a modified timestamp")
		}
		_, _, portableCode := run(t, binaryPath, "--verify", "--trust", cert, "--timestamp-root", ca, target)
		if portableCode == 0 {
			t.Fatal("Go accepted a modified timestamp")
		}
	}
	if export := os.Getenv("MACOSCODESIGN_EXPORT_DIR"); export != "" {
		if err := os.MkdirAll(export, 0755); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(export, "signed-timestamp-arm64"), got)
	}
	attest(t, map[string]any{"native_fixture_byte_equal": true, "architecture": "arm64", "timestamp": metadata.Timestamp.Time.Format(time.RFC3339), "sha256": hash(got), "native_strict_verified": runtime.GOOS == "darwin", "native_tamper_rejected": runtime.GOOS == "darwin", "tsa_trust_separate": true, "historical_validation": true})
}

// Live exchange is deliberately separate from deterministic CI. net/http is a
// test-only transport; the shipped library/CLI do not import its platform bridge.
func TestAcquireAppleTimestamp(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_LIVE_TIMESTAMP") != "1" {
		t.Skip("opt-in public Apple TSA exchange")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id, err := codesign.LoadIdentityPEM(nativeRead(t, filepath.Join(root, "testdata/identities/rsa-identity.pem")), nil)
	if err != nil {
		t.Fatal(err)
	}
	anchor := nativeRead(t, filepath.Join(root, "testdata/chains/developer-id-2"))
	roots := [][]byte{anchor}
	client := &http.Client{Timeout: 15 * time.Second}
	exchange := func(ctx context.Context, request []byte) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://timestamp.apple.com/ts01", bytes.NewReader(request))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/timestamp-query")
		req.Header.Set("Accept", "application/timestamp-reply")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("TSA HTTP status %d", resp.StatusCode)
		}
		response, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err == nil {
			if err := os.MkdirAll(filepath.Join(root, "artifacts"), 0755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(root, "artifacts/timestamp-live-response.tsr"), response, 0644); err != nil {
				return nil, err
			}
		}
		return response, err
	}
	data, err := codesign.SignBytes(ctx, nativeRead(t, filepath.Join(root, "testdata/macho/unsigned-arm64")), codesign.SignOptions{Identifier: "org.example.timestamp.live", Identity: id, Timestamp: &codesign.TimestampOptions{TrustedRoots: roots, Provider: func(ctx context.Context, s []byte) ([]byte, error) {
		return codesign.AcquireTimestamp(ctx, s, exchange, roots, time.Time{})
	}}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := codesign.VerifyBytes(ctx, data, codesign.VerifyOptions{TrustedCertificates: id.Certificates, TimestampRoots: roots})
	if err != nil || !r.Valid {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "live-timestamp")
	if err := os.WriteFile(path, data, 0755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		mustRun(t, apple(t), "--verify", "--strict", path)
	}
	attest(t, map[string]any{"live_apple_tsa": true, "request_imprint": "SHA256", "random_nonce_bits": 128, "native_strict_verified": runtime.GOOS == "darwin", "timestamp": r.Architectures[0].Signature.CertificateMetadata.Timestamp.Time, "sha256": hash(data)})
}
