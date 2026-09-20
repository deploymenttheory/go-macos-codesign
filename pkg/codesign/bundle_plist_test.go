package codesign

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"howett.net/plist"
)

// Hand-built wire inputs are independent of both the production reader and the
// generic encoder. Widths and references deliberately include uncommon forms.
func rawBundlePlist(objects [][]byte, width, refs byte) []byte {
	b := []byte("bplist00")
	offsets := make([]uint64, len(objects))
	for i, v := range objects {
		offsets[i] = uint64(len(b))
		b = append(b, v...)
	}
	table := uint64(len(b))
	for _, off := range offsets {
		for i := int(width) - 1; i >= 0; i-- {
			b = append(b, byte(off>>(8*i)))
		}
	}
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = width, refs
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[24:], table)
	return append(b, trailer...)
}

func scalarBundlePlist(value []byte) []byte {
	return rawBundlePlist([][]byte{{0xd1, 1, 2}, {0x51, 'k'}, value}, 8, 1)
}

func binaryBundleInfo(t *testing.T) []byte {
	t.Helper()
	var info map[string]any
	if _, err := plist.Unmarshal([]byte(testBundleInfo), &info); err != nil {
		t.Fatal(err)
	}
	info["Unicode"] = "日本語 😀"
	info["Data"] = []byte{0, 1, 0xff}
	info["Nested"] = []any{true, false, map[string]any{"Count": uint64(17)}}
	b, err := plist.Marshal(info, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBinaryBundlePlistValues(t *testing.T) {
	date := time.Date(2026, 9, 20, 0, 1, 2, 500000000, time.UTC)
	want := map[string]any{"text": "é 😀", "ascii": "a fairly long ASCII string", "data": bytes.Repeat([]byte{1}, 32), "empty": []byte{}, "negative": int64(-5), "large": uint64(math.MaxUint64), "real": 1.25, "date": date, "array": []any{true, false, uint64(20), map[string]any{}}}
	b, err := plist.Marshal(want, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeBundlePlist(b)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%#v, %v", got, err)
	}
	for _, tc := range []struct {
		value []byte
		want  any
	}{
		{[]byte{0x10, 0xff}, uint64(255)},
		{[]byte{0x11, 0xff, 0xff}, uint64(65535)},
		{[]byte{0x12, 0xff, 0xff, 0xff, 0xff}, uint64(math.MaxUint32)},
		{append([]byte{0x13}, bytes.Repeat([]byte{0xff}, 8)...), int64(-1)},
		{append([]byte{0x14}, bytes.Repeat([]byte{0xff}, 16)...), int64(-1)},
		{[]byte{0x22, 0x3f, 0xc0, 0, 0}, 1.5},
		{[]byte{0x50}, ""},
		{[]byte{0x60}, ""},
	} {
		m, err := decodeBundlePlist(scalarBundlePlist(tc.value))
		if err != nil || !reflect.DeepEqual(m["k"], tc.want) {
			t.Fatalf("%x: %#v %v", tc.value, m, err)
		}
	}
	// Every 1..8-byte width, nonzero top-object index, and shared scalar refs.
	for width := byte(1); width <= 8; width++ {
		obj := append([]byte{0xd1}, make([]byte, 2*int(width))...)
		obj[width], obj[2*width] = 0, 1
		b := rawBundlePlist([][]byte{{0x51, 'k'}, {9}, obj}, width, width)
		binary.BigEndian.PutUint64(b[len(b)-16:], 2)
		b[7] = '?'
		m, err := decodeBundlePlist(b)
		if err != nil || m["k"] != true {
			t.Fatal(width, m, err)
		}
	}
	shared := rawBundlePlist([][]byte{{0xd1, 1, 2}, {0x51, 'k'}, {0xa2, 3, 3}, {0x51, 'v'}}, 1, 1)
	got, err = decodeBundlePlist(shared)
	if err != nil || !reflect.DeepEqual(got["k"], []any{"v", "v"}) {
		t.Fatal(got, err)
	}
}

func TestBinaryBundlePlistMalformed(t *testing.T) {
	for name, value := range map[string][]byte{
		"null": {0}, "fill": {15}, "uid": {0x80, 0}, "set": {0xc0}, "unknown": {0xf0},
		"huge-int": {0x1f}, "truncated-int": {0x13}, "wide-int": append([]byte{0x14, 1}, make([]byte, 15)...),
		"wrong-real-size": {0x21, 0, 0}, "truncated-real": {0x23}, "wrong-date-size": {0x32},
		"date-infinity": {0x33, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0},
		"date-nan":      {0x33, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0},
		"no-length":     {0x4f}, "truncated-length": {0x4f, 0x13}, "not-integer-length": {0x4f, 0x50},
		"oversized-length": {0x4f, 0x14}, "data-overflow": append([]byte{0x4f, 0x13}, bytes.Repeat([]byte{0xff}, 8)...),
		"short-data": {0x41}, "short-ascii": {0x51}, "short-unicode": {0x61, 0},
		"invalid-ascii": {0x51, 0x80}, "low-surrogate": {0x61, 0xdc, 0}, "high-surrogate": {0x61, 0xd8, 0}, "wrong-pair": {0x62, 0xd8, 0, 0, 'a'},
		"huge-array":  append([]byte{0xaf, 0x13}, bytes.Repeat([]byte{0xff}, 8)...),
		"huge-dict":   append([]byte{0xdf, 0x13}, bytes.Repeat([]byte{0xff}, 8)...),
		"short-array": {0xa2, 1}, "short-dict": {0xd2, 1, 2}, "bad-ref": {0xa1, 99}, "cycle": {0xa1, 2},
		"bad-key": {0xd1, 2, 1}, "non-string-key": {0xd1, 3, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeBundlePlist(scalarBundlePlist(value)); err == nil {
				t.Fatal("accepted malformed object")
			}
		})
	}
	valid := scalarBundlePlist([]byte{9})
	for n := 0; n < len(valid); n++ {
		if _, err := decodeBundlePlist(valid[:n]); err == nil {
			t.Fatal("accepted prefix", n)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"version":          func(b []byte) { b[6] = '1' },
		"no-offset-width":  func(b []byte) { b[len(b)-26] = 0 },
		"wide-offset":      func(b []byte) { b[len(b)-26] = 9 },
		"no-ref-width":     func(b []byte) { b[len(b)-25] = 0 },
		"wide-ref":         func(b []byte) { b[len(b)-25] = 9 },
		"zero-objects":     func(b []byte) { binary.BigEndian.PutUint64(b[len(b)-24:], 0) },
		"huge-objects":     func(b []byte) { binary.BigEndian.PutUint64(b[len(b)-24:], math.MaxUint64) },
		"bad-top":          func(b []byte) { binary.BigEndian.PutUint64(b[len(b)-16:], 3) },
		"table-in-header":  func(b []byte) { binary.BigEndian.PutUint64(b[len(b)-8:], 8) },
		"table-past-end":   func(b []byte) { binary.BigEndian.PutUint64(b[len(b)-8:], math.MaxUint64) },
		"bad-table-length": func(b []byte) { binary.BigEndian.PutUint64(b[len(b)-8:], 9) },
		"object-in-header": func(b []byte) { b[21] = 7 },
		"object-past-end":  func(b []byte) { b[14] = 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(valid)
			mutate(b)
			if _, err := decodeBundlePlist(b); err == nil {
				t.Fatal("accepted malformed trailer")
			}
		})
	}
	for _, b := range [][]byte{
		rawBundlePlist([][]byte{{9}}, 1, 1),
		rawBundlePlist([][]byte{{0xd1, 1, 1}, {9}}, 1, 1),
		rawBundlePlist([][]byte{{0xd2, 1, 2, 3, 3}, {0x51, 'k'}, {0x61, 0, 'k'}, {9}}, 1, 1),
	} {
		if _, err := decodeBundlePlist(b); err == nil {
			t.Fatal("accepted non-dictionary, invalid or duplicate key")
		}
	}
}

func TestBinaryBundlePlistExpansionLimits(t *testing.T) {
	for _, count := range []int{1, 2} {
		objects := [][]byte{{0xd1, 1, 2}, {0x51, 'k'}}
		end := 35
		if count == 2 {
			end = 20
		}
		for i := 2; i < end; i++ {
			objects = append(objects, append([]byte{0xa0 | byte(count)}, bytes.Repeat([]byte{byte(i + 1)}, count)...))
		}
		objects = append(objects, []byte{9})
		if _, err := decodeBundlePlist(rawBundlePlist(objects, 2, 1)); err == nil {
			t.Fatal("accepted deep/expanding graph")
		}
	}
	data := append([]byte{0x4f, 0x12, 0, 0x40, 0, 0}, make([]byte, 4<<20)...)
	b := rawBundlePlist([][]byte{{0xd1, 1, 2}, {0x51, 'k'}, {0xa3, 3, 3, 3}, data}, 4, 1)
	if _, err := decodeBundlePlist(b); err == nil {
		t.Fatal("accepted expanded byte limit")
	}
	objects := make([][]byte, 256)
	for i := range objects {
		objects[i] = []byte{0xd0}
	}
	if _, err := decodeBundlePlist(rawBundlePlist(objects, 2, 1)); err == nil {
		t.Fatal("accepted undersized refs")
	}
	if _, err := decodeBundlePlist(rawBundlePlist(objects, 1, 2)); err == nil {
		t.Fatal("accepted undersized offsets")
	}
}

func TestBinaryBundleLifecycle(t *testing.T) {
	ctx := context.Background()
	app := testBundle(t)
	info := binaryBundleInfo(t)
	bundleFile(t, app, "Contents/Info.plist", info)
	if err := Sign(ctx, app, SignOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(app, bundleResourcesPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run wrote resources", err)
	}
	if err := Sign(ctx, app, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err := Verify(ctx, app, VerifyOptions{})
	if err != nil || !r.Valid || r.Bundle.InfoEntries != 6 {
		t.Fatal(r, err)
	}
	if err := Sign(ctx, app, SignOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(app, "Contents/Info.plist"))
	if err != nil || !bytes.Equal(got, info) {
		t.Fatal("metadata rewritten", err)
	}
	// An equivalent XML dictionary must fail: signatures bind representation bytes.
	m, err := decodeBundlePlist(info)
	if err != nil {
		t.Fatal(err)
	}
	xml, err := plist.Marshal(m, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	bundleFile(t, app, "Contents/Info.plist", xml)
	if _, err := Verify(ctx, app, VerifyOptions{}); err == nil {
		t.Fatal("accepted changed metadata representation")
	}
	bundleFile(t, app, "Contents/Info.plist", info)
	if err := RemoveSignature(ctx, app); err != nil {
		t.Fatal(err)
	}
}

func TestBinaryBundleResourceEnvelope(t *testing.T) {
	m, err := decodeBundlePlist(encodeBundleResources(map[string]any{}, map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := plist.Marshal(m, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBundleResources(b, map[string]any{}); err != nil {
		t.Fatal(err)
	}
}

func TestBinaryBundleClangFacts(t *testing.T) {
	b, err := os.ReadFile("../../spec/apple-bundle-plists.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts struct {
		Targets map[string]struct {
			Constants map[string]string
			Methods   map[string]any
		}
	}
	if err := json.Unmarshal(b, &facts); err != nil {
		t.Fatal(err)
	}
	if len(facts.Targets) != 2 {
		t.Fatal("two Clang targets required")
	}
	for target, f := range facts.Targets {
		for k, v := range map[string]string{"TrailerSize": "32", "OffsetWidth": "6", "ReferenceWidth": "7", "ObjectCount": "8", "TopObject": "16", "OffsetTable": "24", "kCFBinaryPlistMarkerFalse": "8", "kCFBinaryPlistMarkerTrue": "9", "kCFBinaryPlistMarkerInt": "16", "kCFBinaryPlistMarkerReal": "32", "kCFBinaryPlistMarkerDate": "51", "kCFBinaryPlistMarkerData": "64", "kCFBinaryPlistMarkerASCIIString": "80", "kCFBinaryPlistMarkerUnicode16String": "96", "kCFBinaryPlistMarkerArray": "160", "kCFBinaryPlistMarkerDict": "208"} {
			if f.Constants[k] != v {
				t.Fatal(target, k, f.Constants[k])
			}
		}
		for _, name := range []string{"_getSizedInt", "__CFBinaryPlistGetTopLevelInfo", "_readInt", "component", "getDictionary"} {
			if f.Methods[name] == nil {
				t.Fatal(target, name)
			}
		}
	}
}

func TestBinaryMetadataFailurePreservesBundle(t *testing.T) {
	app := testBundle(t)
	ctx := context.Background()
	bundleFile(t, app, "Contents/Info.plist", binaryBundleInfo(t))
	if err := Sign(ctx, app, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	mainPath, envelopePath := filepath.Join(app, "Contents/MacOS/hello"), filepath.Join(app, bundleResourcesPath)
	mainBefore, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBefore, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	bundleFile(t, app, "Contents/Info.plist", scalarBundlePlist([]byte{0xa1, 2}))
	if err := Sign(ctx, app, SignOptions{Force: true}); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	if err := RemoveSignature(ctx, app); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	mainAfter, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	envelopeAfter, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mainBefore, mainAfter) || !bytes.Equal(envelopeBefore, envelopeAfter) {
		t.Fatal("malformed metadata changed signed files")
	}
}
