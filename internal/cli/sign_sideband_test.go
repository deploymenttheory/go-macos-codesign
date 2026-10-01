package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

func TestMutableCarrierCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata")
	metadata := appledouble.File{FinderInfo: [32]byte{1}, ResourceFork: []byte("fork"), Attrs: []appledouble.Attr{{Name: "user.control", Value: []byte("keep")}}}
	data, err := metadata.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	m := &mappedCarrier{path: path, info: before}
	for _, name := range []string{appledouble.ResourceForkName, appledouble.FinderInfoName} {
		if err := m.RemoveAttribute(context.Background(), name); err != nil {
			t.Fatal(err)
		}
		actual, e := os.Stat(path)
		if e != nil || !os.SameFile(before, actual) || actual.Mode() != before.Mode() {
			t.Fatal(actual, e)
		}
	}
	got, err := appledouble.DecodeStream(context.Background(), m, appledouble.DefaultStreamLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got.FinderInfo != [32]byte{} || got.ResourceFork.Size() != 0 || len(got.Attrs) != 1 {
		t.Fatal(got)
	}
	value := make([]byte, 4)
	if _, err := got.Attrs[0].Value.ReadAt(value, 0); err != nil || string(value) != "keep" {
		t.Fatal(value, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.RemoveAttribute(ctx, appledouble.FinderInfoName); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := m.RemoveAttribute(context.Background(), "user.control"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveAttribute(context.Background(), appledouble.FinderInfoName); err == nil {
		t.Fatal("accepted changed carrier")
	}
	m.info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveAttribute(context.Background(), appledouble.FinderInfoName); err == nil {
		t.Fatal("accepted malformed carrier")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveAttribute(context.Background(), appledouble.FinderInfoName); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
}

func TestSigningMetadataInputErrors(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ carrier, manifest string }{{"absent", ""}, {t.TempDir(), ""}, {"", "absent"}} {
		if err := signWithMetadata(ctx, "absent", tc.carrier, tc.manifest, codesign.SignOptions{}); err == nil {
			t.Fatal(tc)
		}
	}
	for _, args := range [][]string{{"--strip-disallowed-xattrs=yes"}, {"-s-", "--appledouble", ""}, {"-s-", "--appledouble-map", ""}} {
		if _, err := parse(args); err == nil {
			t.Fatal(args)
		}
	}
	for _, args := range [][]string{{"-s-", "--strip-disallowed-xattrs", "--no-strict", "object"}, {"-v", "--strip-disallowed-xattrs", "object"}, {"-d", "--strip-disallowed-xattrs", "object"}, {"--remove-signature", "--strip-disallowed-xattrs", "object"}} {
		if o, err := parse(args); err != nil || !o.stripDisallowed {
			t.Fatal(o, err)
		}
	}
	// Verification never decodes or rewrites a carrier merely because strip is set.
	var out, stderr bytes.Buffer
	status := Run(ctx, []string{"-v", "--strip-disallowed-xattrs", "absent"}, nil, &out, &stderr)
	if status != 1 {
		t.Fatal(status, out.String(), stderr.String())
	}
}

func TestCarrierCancellationAndSharedManifest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &carrierReader{ctx, bytes.NewReader([]byte("data"))}
	if n, err := r.Read(make([]byte, 4)); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(n, err)
	}
	r.ctx = context.Background()
	if n, err := io.Copy(io.Discard, r); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	dir := t.TempDir()
	data, err := (&appledouble.File{ResourceFork: []byte("fork")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata"), data, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "map.json")
	if err := os.WriteFile(manifest, []byte(`{"a":"metadata","b":"metadata"}`), 0600); err != nil {
		t.Fatal(err)
	}
	values, err := readSidebandManifest(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	if values["a"] != values["b"] {
		t.Fatal("shared carrier identity lost")
	}
	if err := values["a"].(codesign.MutableAppleDouble).RemoveAttribute(context.Background(), appledouble.ResourceForkName); err != nil {
		t.Fatal(err)
	}
	got, err := appledouble.DecodeStream(context.Background(), values["b"], appledouble.DefaultStreamLimits())
	if err != nil || got.ResourceFork.Size() != 0 {
		t.Fatal(got, err)
	}
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, filepath.Join(dir, "absent"))
	}
	if err := values["a"].(codesign.MutableAppleDouble).RemoveAttribute(context.Background(), appledouble.FinderInfoName); err == nil {
		t.Fatal("missing temporary directory accepted")
	}
}
