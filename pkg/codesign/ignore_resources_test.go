package codesign

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestIgnoreResourcesBytePolicy(t *testing.T) {
	ctx := context.Background()
	info, resources := []byte("Info.plist"), []byte("resource envelope")
	data, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), SignOptions{Identifier: "test.ignore", InfoPlist: info, Resources: resources})
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(data)
	for _, supplied := range [][]byte{nil, []byte("changed"), resources} {
		r, err := VerifyBytes(ctx, data, VerifyOptions{InfoPlist: info, Resources: supplied, IgnoreResources: true, StrictSymlinks: true})
		if err != nil || !r.Valid || !r.ResourcesIgnored {
			t.Fatal(r, err)
		}
	}
	if _, err := VerifyBytes(ctx, data, VerifyOptions{InfoPlist: info}); err == nil {
		t.Fatal("default accepted missing envelope")
	}
	if _, err := VerifyBytes(ctx, data, VerifyOptions{InfoPlist: []byte("changed"), IgnoreResources: true}); err == nil {
		t.Fatal("accepted modified Info.plist")
	}
	if _, err := VerifyBytes(ctx, data, VerifyOptions{IgnoreResources: true}); err == nil {
		t.Fatal("accepted missing Info.plist")
	}
	if !bytes.Equal(data, before) {
		t.Fatal("verification modified input")
	}
	data[4096] ^= 1
	if _, err := VerifyBytes(ctx, data, VerifyOptions{InfoPlist: info, IgnoreResources: true, NoStrict: true}); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted damaged executable", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := VerifyBytes(cancelled, before, VerifyOptions{IgnoreResources: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestIgnoreResourcesWithoutResourceSlot(t *testing.T) {
	ctx := context.Background()
	app := testBundle(t)
	data, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), SignOptions{Identifier: "test.ignore", InfoPlist: []byte(testBundleInfo)})
	if err != nil {
		t.Fatal(err)
	}
	bundleFile(t, app, "Contents/MacOS/hello", data)
	if _, err := Verify(ctx, app, VerifyOptions{}); err == nil {
		t.Fatal("default accepted bundle lacking resource seal")
	}
	r, err := Verify(ctx, app, VerifyOptions{IgnoreResources: true})
	if err != nil || !r.Valid || !r.ResourcesIgnored {
		t.Fatal(r, err)
	}
	// An unbound envelope is a rogue metadata entry under structural policy.
	bundleFile(t, app, "Contents/_CodeSignature/CodeResources", []byte("unbound"))
	if _, err := Verify(ctx, app, VerifyOptions{IgnoreResources: true}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, app, VerifyOptions{IgnoreResources: true, NoStrict: true}); err != nil {
		t.Fatal(err)
	}
}

func TestIgnoreResourcesRetainsTrust(t *testing.T) {
	ctx := context.Background()
	id := testIdentity(t, "rsa")
	data, err := SignBytes(ctx, fixture(t, "unsigned-arm64"), SignOptions{Identifier: "test.ignore", Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyBytes(ctx, data, VerifyOptions{IgnoreResources: true})
	if !errors.Is(err, ErrUntrusted) || r == nil || r.Valid || !r.ResourcesIgnored {
		t.Fatal(r, err)
	}
	r, err = VerifyBytes(ctx, data, VerifyOptions{IgnoreResources: true, TrustedCertificates: id.Certificates})
	if err != nil || !r.Valid || !r.ResourcesIgnored {
		t.Fatal(r, err)
	}
}

func TestIgnoreResourcesStructuralBounds(t *testing.T) {
	app := testBundle(t)
	if err := Sign(context.Background(), app, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	b, err := openAppBundleVersion(app, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if _, err := b.structureEntries("Contents/Info.plist"); err == nil {
		t.Fatal("regular file accepted as directory")
	}
	if _, err := b.structureEntries("absent"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for i := range maxBundleEntries {
		// The existing CodeResources entry makes this exceed the shared bound.
		name := filepath.Join(app, "Contents/_CodeSignature", strconv.Itoa(i))
		if err := os.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Verify(context.Background(), app, VerifyOptions{IgnoreResources: true}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), app, VerifyOptions{IgnoreResources: true, NoStrict: true}); err != nil {
		t.Fatal(err)
	}
}
