package codesign

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestStrictLayout(t *testing.T) {
	ctx := context.Background()
	for _, arch := range []string{"arm64", "x86_64", "universal"} {
		original := fixture(t, "adhoc-"+arch)
		for _, extra := range []bool{false, true} {
			data := bytes.Clone(original)
			if extra {
				data = append(data, 0, 0, 0, 0)
			}
			before := bytes.Clone(data)
			for _, disabled := range []bool{false, true} {
				r, e := VerifyBytes(ctx, data, VerifyOptions{NoStrict: disabled})
				want := !extra || disabled
				if (e == nil) != want || r == nil || r.Valid != want {
					t.Fatal(arch, extra, disabled, r, e)
				}
				if !bytes.Equal(data, before) {
					t.Fatal("verification wrote input")
				}
			}
		}
		// Disabling layout checks never disables signed-page integrity.
		data := bytes.Clone(original)
		c, e := parseContainer(data)
		if e != nil {
			t.Fatal(e)
		}
		data[c.slices[0].offset+4096] ^= 1
		if _, e := VerifyBytes(ctx, data, VerifyOptions{NoStrict: true}); e == nil {
			t.Fatal("corrupt code accepted")
		}
	}
	data := fixture(t, "adhoc-universal")
	data[100] = 1
	if e := verifyStrictLayout(data, "", false); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := VerifyBytes(ctx, data, VerifyOptions{NoStrict: true}); e == nil {
		t.Fatal("native universal index failure was suppressed")
	}
	// Excess aligned padding and physical slice order do not change signatures.
	c, e := parseContainer(fixture(t, "adhoc-universal"))
	if e != nil {
		t.Fatal(e)
	}
	data = bytes.Clone(c.data)
	second := c.slices[1]
	gap := int(uint64(1) << second.alignment)
	data = append(data[:second.offset:second.offset], append(make([]byte, gap), data[second.offset:]...)...)
	be.PutUint32(data[36:], uint32(second.offset)+uint32(gap))
	if e := verifyStrictLayout(data, "", false); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := VerifyBytes(ctx, data, VerifyOptions{NoStrict: true}); e != nil {
		t.Fatal(e)
	}
	data = bytes.Clone(c.data)
	first := bytes.Clone(data[8:28])
	copy(data[8:28], data[28:48])
	copy(data[28:48], first)
	if e := verifyStrictLayout(data, "", false); e != nil {
		t.Fatal(e)
	}
	for _, order := range []binary.ByteOrder{be, binary.LittleEndian} {
		for _, is64 := range []bool{false, true} {
			data := syntheticMachO(order, is64)
			if e := verifyStrictLayout(data, "", false); e != nil {
				t.Fatal(e)
			}
			if e := verifyStrictLayout(append(data, 0), "", false); !errors.Is(e, ErrInvalid) {
				t.Fatal(e)
			}
		}
	}
	// Legacy LC_SYMTAB fallback, no usable boundary, and truncated input.
	for _, size := range []uint32{8, 24} {
		data := syntheticMachO(binary.LittleEndian, false)
		binary.LittleEndian.PutUint32(data[28:], 2)
		binary.LittleEndian.PutUint32(data[32:], size)
		binary.LittleEndian.PutUint32(data[16:], 1)
		binary.LittleEndian.PutUint32(data[20:], size)
		binary.LittleEndian.PutUint32(data[44:], 4096)
		binary.LittleEndian.PutUint32(data[48:], 104)
		e := verifyStrictLayout(data, "", false)
		if (e == nil) != (size == 24) {
			t.Fatal(size, e)
		}
	}
	data = syntheticMachO(be, false)
	copy(data[28+56+8:], "__OTHER___")
	if e := verifyStrictLayout(data, "", false); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if e := verifyStrictLayout(nil, "", false); e == nil {
		t.Fatal(e)
	}
	if _, e := VerifyBytes(ctx, fixture(t, "adhoc-arm64"), VerifyOptions{StrictSymlinks: true, Resources: []byte("envelope")}); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
}

func TestStrictLinkScopes(t *testing.T) {
	app := testBundle(t)
	base, e := filepath.EvalSymlinks(filepath.Join(app, "Contents"))
	if e != nil {
		t.Fatal(e)
	}
	bundleFile(t, app, "Contents/Resources/data", []byte("x"))
	bundleFile(t, app, "Contents/Resources/sub/file", []byte("y"))
	bundleFile(t, app, "Contents/Resources/.DS_Store", []byte("x"))
	bundleFile(t, app, "Contents/_CodeSignature/CodeResources", []byte("x"))
	bundleLink(t, app, "Contents/Resources/alias", "sub")
	scope := &verificationLinkScope{base: base, bundle: &appBundle{base: "Contents/", executable: "Contents/MacOS/hello"}}
	opts := VerifyOptions{linkScope: scope, resourceBase: base, StrictSymlinks: true}
	for _, tc := range []struct {
		target string
		valid  bool
	}{{"data", true}, {"..", true}, {"alias/../data", true}, {"../MacOS/hello", true}, {"sub/./file", true}, {"missing", false}, {"data/../data", false}, {".DS_Store", false}, {"../_CodeSignature/CodeResources", false}, {"../../ContentsOther/data", false}, {"/Library/codesign-absent", false}} {
		if e := verifyStrictLink("Resources/link", tc.target, opts); (e == nil) != tc.valid {
			t.Fatal(tc.target, e)
		}
	}
	if e := verifyStrictLink("Resources/link", "data", VerifyOptions{}); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	for _, n := range []int{33, 34} {
		for i := 0; i < n; i++ {
			next := fmt.Sprintf("h%d-%d", n, i+1)
			if i == n-1 {
				next = "data"
			}
			bundleLink(t, app, fmt.Sprintf("Contents/Resources/h%d-%d", n, i), next)
		}
		if e := verifyStrictLink("Resources/link", fmt.Sprintf("h%d-0", n), opts); (e == nil) != (n == 33) {
			t.Fatal(n, e)
		}
	}
	// A child can refer to included resources of its enclosing bundle.
	childBase := filepath.Join(base, "PlugIns", "Child.app", "Contents")
	if e := os.MkdirAll(filepath.Join(childBase, "Resources"), 0755); e != nil {
		t.Fatal(e)
	}
	child := &verificationLinkScope{base: childBase, bundle: scope.bundle, outer: scope}
	opts.linkScope = child
	opts.resourceBase = childBase
	target, e := filepath.Rel(filepath.Join(childBase, "Resources"), filepath.Join(base, "Resources/data"))
	if e != nil {
		t.Fatal(e)
	}
	if e := verifyStrictLink("Resources/link", target, opts); e != nil {
		t.Fatal(e)
	}
	bundleFile(t, childBase, "Resources/.DS_Store", []byte("ignored"))
	if e := verifyStrictLink("Resources/link", ".DS_Store", opts); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}
