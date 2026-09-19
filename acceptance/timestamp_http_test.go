package acceptance

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

type tsaImprint struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}
type tsaAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}
type tsaContent struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}
type tsaSigner struct {
	Version int
	ID      struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	Digest     pkix.AlgorithmIdentifier
	Attributes asn1.RawValue
	Algorithm  pkix.AlgorithmIdentifier
	Signature  []byte
}

// This independent local authority uses standard-library X.509 and ASN.1, not
// the production timestamp parser or CMS encoder, to issue each fresh response.
func localTimestampAuthority(t *testing.T) (*httptest.Server, string, *atomic.Int32, *atomic.Value) {
	t.Helper()
	encode := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Error(err)
		}
		return b
	}
	raw := func(b []byte) asn1.RawValue { return asn1.RawValue{FullBytes: b} }
	explicit := func(b []byte) asn1.RawValue { return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: b} }
	identity, err := codesign.LoadIdentityPEM(nativeRead(t, filepath.Join(root, "testdata/identities/rsa-identity.pem")), nil)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local test TSA root"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, parent, parent, identity.Signer.Public(), identity.Signer)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Local test TSA signer"}, NotBefore: parent.NotBefore, NotAfter: parent.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: encode([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})}}}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, parent, identity.Signer.Public(), identity.Signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "tsa-root.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0600); err != nil {
		t.Fatal(err)
	}
	requests, mode := new(atomic.Int32), new(atomic.Value)
	mode.Store("ok")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		current := mode.Load().(string)
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return
		}
		if current == "second" {
			mode.Store("status")
		}
		if current == "timeout" {
			time.Sleep(250 * time.Millisecond)
		}
		if current == "status" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Version int
			Imprint tsaImprint
			Nonce   *big.Int
			CertReq bool
		}
		rest, err := asn1.Unmarshal(body, &req)
		if err != nil || len(rest) != 0 || req.Version != 1 || req.Nonce == nil || !req.CertReq || r.Method != "POST" || r.Header.Get("Content-Type") != "application/timestamp-query" {
			t.Error("invalid TSA request", err)
			http.Error(w, "invalid", 400)
			return
		}
		if current == "nonce" {
			req.Nonce.Add(req.Nonce, big.NewInt(1))
		}
		if current == "imprint" {
			req.Imprint.Digest[0] ^= 1
		}
		info := encode(struct {
			Version int
			Policy  asn1.ObjectIdentifier
			Imprint tsaImprint
			Serial  *big.Int
			Time    time.Time `asn1:"generalized"`
			Nonce   *big.Int
		}{1, asn1.ObjectIdentifier{1, 2, 3, 4}, req.Imprint, big.NewInt(int64(requests.Load())), time.Now().UTC().Truncate(time.Second), req.Nonce})
		digest, binding := sha256.Sum256(info), sha256.Sum256(leafDER)
		tstType := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
		ess := encode(struct{ Certs []struct{ Hash []byte } }{[]struct{ Hash []byte }{{binding[:]}}})
		attrs := []tsaAttribute{
			{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}, []asn1.RawValue{raw(encode(tstType))}},
			{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}, []asn1.RawValue{raw(encode(digest[:]))}},
			{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}, []asn1.RawValue{raw(ess)}},
		}
		signed, err := asn1.MarshalWithParams(attrs, "set")
		if err != nil {
			t.Error(err)
			return
		}
		hashed := sha256.Sum256(signed)
		signature, err := identity.Signer.Sign(rand.Reader, hashed[:], crypto.SHA256)
		if err != nil {
			t.Error(err)
			return
		}
		if current == "signature" {
			signature[0] ^= 1
		}
		signed[0] = 0xa0
		alg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}
		signer := tsaSigner{Version: 1, Digest: alg, Attributes: raw(signed), Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, Parameters: asn1.NullRawValue}, Signature: signature}
		signer.ID.Issuer = raw(leaf.RawIssuer)
		signer.ID.Serial = leaf.SerialNumber
		sd := encode(struct {
			Version      int
			Digests      []pkix.AlgorithmIdentifier `asn1:"set"`
			Content      tsaContent
			Certificates asn1.RawValue
			Signers      []tsaSigner `asn1:"set"`
		}{3, []pkix.AlgorithmIdentifier{alg}, tsaContent{tstType, explicit(encode(info))}, explicit(append(bytes.Clone(leafDER), rootDER...)), []tsaSigner{signer}})
		token := tsaContent{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, explicit(sd)}
		response := encode(struct {
			Status struct{ Status int }
			Token  tsaContent
		}{Token: token})
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(200)
		w.(http.Flusher).Flush() // Exercise real chunked HTTP across all three OSes.
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)
	return server, ca, requests, mode
}

func TestCLITimestampHTTP(t *testing.T) {
	server, ca, requests, mode := localTimestampAuthority(t)
	identity := filepath.Join(root, "testdata/identities/rsa-identity.pem")
	cert := filepath.Join(root, "testdata/identities/rsa-cert.pem")
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "signed")
			copyFixture(t, "unsigned-"+arch, target)
			before := requests.Load()
			mustRun(t, binaryPath, "-s", identity, "--timestamp="+server.URL, "--timestamp-root", ca, "--timestamp-timeout", "5s", target)
			mustRun(t, binaryPath, "--verify", "--trust", cert, "--timestamp-root", ca, target)
			report, err := codesign.InspectBytes(nativeRead(t, target))
			if err != nil {
				t.Fatal(err)
			}
			if int(requests.Load()-before) != len(report.Architectures) {
				t.Fatal("expected fresh request per architecture")
			}
			for _, arch := range report.Architectures {
				if arch.Signature.CertificateMetadata.Timestamp == nil {
					t.Fatal("timestamp missing")
				}
			}
		})
	}
	for _, failure := range []string{"status", "nonce", "imprint", "signature", "untrusted", "timeout", "second"} {
		t.Run(failure, func(t *testing.T) {
			mode.Store(failure)
			target := filepath.Join(t.TempDir(), "unchanged")
			fixture := "unsigned-arm64"
			if failure == "second" {
				fixture = "unsigned-universal"
			}
			copyFixture(t, fixture, target)
			before := nativeRead(t, target)
			tsaRoot := ca
			if failure == "untrusted" {
				tsaRoot = "apple"
			}
			timeout := "5s"
			if failure == "timeout" {
				timeout = "50ms"
			}
			count := requests.Load()
			_, stderr, code := run(t, binaryPath, "-s", identity, "--timestamp="+server.URL, "--timestamp-root", tsaRoot, "--timestamp-timeout", timeout, target)
			if code != 1 || !strings.Contains(stderr, "timestamp") {
				t.Fatalf("%d %s", code, stderr)
			}
			nativeEqual(t, "unchanged after timestamp failure", nativeRead(t, target), before)
			if failure == "second" && requests.Load()-count != 2 {
				t.Fatal("expected failure after the first architecture received a valid timestamp")
			}
		})
	}
	mode.Store("ok")
	target := filepath.Join(t.TempDir(), "dryrun")
	copyFixture(t, "unsigned-arm64", target)
	before := nativeRead(t, target)
	mustRun(t, binaryPath, "-s", identity, "--timestamp="+server.URL, "--timestamp-root", ca, "--dryrun", target)
	nativeEqual(t, "timestamp dry run", nativeRead(t, target), before)
	count := requests.Load()
	for _, args := range [][]string{{"-s", identity, "--timestamp=none"}, {"-fs", "-", "--timestamp=" + server.URL}, {"-fs", "-", "--timestamp"}} {
		mustRun(t, binaryPath, append(args, target)...)
	}
	if requests.Load() != count {
		t.Fatal("unexpected timestamp request for none/ad-hoc")
	}
	attest(t, map[string]any{"local_authority": true, "fresh_requests": count, "architectures": []string{"arm64", "x86_64", "universal"}, "failed_signing_preserves_input": true, "dryrun_preserves_input": true, "chunked_http": true})
}

func TestAppleTimestampOptionParity(t *testing.T) {
	native := apple(t)
	for _, option := range []string{"--timestamp", "--timestamp=none", "--timestamp=http://127.0.0.1:1", "--timestamp=", "--timestamp=https://example.test"} {
		t.Run(option, func(t *testing.T) {
			dir := t.TempDir()
			a, b := filepath.Join(dir, "apple"), filepath.Join(dir, "go")
			copyFixture(t, "unsigned-arm64", a)
			copyFixture(t, "unsigned-arm64", b)
			_, nativeErr, nativeCode := run(t, native, "-s", "-", "-i", "org.example.timestamp.options", option, a)
			_, goErr, goCode := run(t, binaryPath, "-s", "-", "-i", "org.example.timestamp.options", option, b)
			if nativeCode != goCode {
				t.Fatalf("native=%d %s; go=%d %s", nativeCode, nativeErr, goCode, goErr)
			}
			nativeEqual(t, "ad-hoc timestamp option", nativeRead(t, a), nativeRead(t, b))
			attest(t, map[string]any{"option": option, "native_exit": nativeCode, "go_exit": goCode, "native_stderr": nativeErr, "byte_equal": true})
		})
	}
}

func TestCLILiveAppleTimestamp(t *testing.T) {
	if os.Getenv("MACOSCODESIGN_LIVE_TIMESTAMP") != "1" {
		t.Skip("opt-in public Apple TSA exchange")
	}
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		t.Run(arch, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "live")
			copyFixture(t, "unsigned-"+arch, target)
			mustRun(t, binaryPath, "-s", filepath.Join(root, "testdata/identities/rsa-identity.pem"), "--timestamp", target)
			mustRun(t, binaryPath, "--verify", "--trust", filepath.Join(root, "testdata/identities/rsa-cert.pem"), "--timestamp-root", "apple", target)
			if runtime.GOOS == "darwin" {
				mustRun(t, apple(t), "--verify", "--strict", target)
			}
			data := nativeRead(t, target)
			report, err := codesign.InspectBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			attest(t, map[string]any{"live_apple_tsa": true, "production_cli_transport": true, "architecture": arch, "sha256": hash(data), "native_strict_verified": runtime.GOOS == "darwin", "timestamp": report.Architectures[0].Signature.CertificateMetadata.Timestamp.Time})
		})
	}
}
