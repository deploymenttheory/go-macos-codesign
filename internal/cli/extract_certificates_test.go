package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestCertificateExtractionOptions(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		prefix string
		paths  []string
	}{
		{[]string{"-d", "--extract-certificates", "input"}, "codesign", []string{"input"}},
		{[]string{"-d", "--extract-certificates=", "input"}, "", []string{"input"}},
		{[]string{"-d", "--extract-certificates=first", "--extract-certificates=last", "input"}, "last", []string{"input"}},
		{[]string{"-d", "--extract-certificates=first", "--extract-certificates", "input"}, "codesign", []string{"input"}},
		{[]string{"-d", "--extract-certificates", "prefix", "input"}, "codesign", []string{"prefix", "input"}},
	} {
		o, err := parse(tc.args)
		if err != nil || !o.extractCertificates || o.certificatePrefix != tc.prefix || !reflect.DeepEqual(o.paths, tc.paths) {
			t.Fatal(tc.args, o, err)
		}
	}
}

func TestCertificateExtractionSelection(t *testing.T) {
	// Distinct certificates prove extraction uses exactly the same architecture
	// selection as display, including the portable arm64 preference.
	r := &codesign.Report{Architectures: []codesign.Architecture{
		{Name: "x86_64", Signature: &codesign.Signature{CertificateMetadata: &codesign.CertificateMetadata{Certificates: [][]byte{[]byte("intel")}}}},
		{Name: "arm64", Signature: &codesign.Signature{CertificateMetadata: &codesign.CertificateMetadata{Certificates: [][]byte{[]byte("arm")}}}},
	}}
	for _, arch := range []string{"", "arm64", "x86_64", "absent"} {
		prefix := filepath.Join(t.TempDir(), "cert")
		err := extractCertificates(r, options{architecture: arch, certificatePrefix: prefix})
		if arch == "absent" {
			if err == nil {
				t.Fatal("missing architecture accepted")
			}
			continue
		}
		got, readErr := os.ReadFile(prefix + "0")
		want := "arm"
		if arch == "x86_64" {
			want = "intel"
		}
		if err != nil || readErr != nil || string(got) != want {
			t.Fatal(got, err, readErr)
		}
	}
	if err := extractCertificates(&codesign.Report{Architectures: []codesign.Architecture{{Name: "arm64"}}}, options{}); !errors.Is(err, codesign.ErrUnsigned) {
		t.Fatal(err)
	}
}

func TestCertificateExtractionJSONAndErrors(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "cert")
	path := write(t, "signed", readCLIFile(t, "../../testdata/certificate-layout/rsa-arm64"))
	out, stderr, code := invoke(t, "-d", "--json", "--extract-certificates="+prefix, path)
	if code != 0 || stderr != "" || !json.Valid([]byte(out)) || bytes.Contains([]byte(out), []byte(`"Certificates"`)) {
		t.Fatal(code, stderr, out)
	}
	certs, err := codesign.ParseCertificatesPEM(readCLIFile(t, "../../testdata/identities/rsa-cert.pem"))
	if err != nil || !bytes.Equal(readCLIFile(t, prefix+"0"), certs[0]) {
		t.Fatal("wrong extracted DER", err)
	}
	// JSON does not bypass signature/architecture checks required to extract.
	if _, _, code := invoke(t, "-d", "--json", "--extract-certificates="+prefix, "-a", "absent", path); code != 1 {
		t.Fatal(code)
	}
	if _, _, code := invoke(t, "-d", "--extract-certificates="+prefix, file(t, "unsigned-arm64")); code != 1 {
		t.Fatal(code)
	}
	// An invalid output name exercises an OS error outside the translated
	// English ENOENT/EACCES/directory profile without touching any output file.
	if err := extractCertificates(&codesign.Report{Architectures: []codesign.Architecture{{Name: "arm64", Signature: &codesign.Signature{CertificateMetadata: &codesign.CertificateMetadata{Certificates: certs}}}}}, options{certificatePrefix: "invalid\x00"}); err == nil {
		t.Fatal("invalid output path accepted")
	}
}

func readCLIFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
