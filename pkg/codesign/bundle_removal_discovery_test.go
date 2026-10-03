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
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestRemovalDiscoveryEvidence(t *testing.T) {
	hash := func(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
	check := func(path, want string) {
		t.Helper()
		if hash(readTestFile(t, "../../"+path)) != want {
			t.Fatal("stale evidence", path)
		}
	}
	var ast struct {
		Schema  int
		Driver  string            `json:"driver_sha256"`
		Bodies  map[string]string `json:"body_sha256"`
		Targets map[string]map[string]struct {
			Kinds      map[string]int `json:"ast_kinds"`
			References map[string]int
		}
	}
	if err := json.Unmarshal(readTestFile(t, "../../spec/apple-removal-discovery.json"), &ast); err != nil {
		t.Fatal(err)
	}
	check("scripts/extract-removal-discovery.go", ast.Driver)
	if ast.Schema != 1 || len(ast.Bodies) != 27 || len(ast.Targets) != 2 {
		t.Fatal("incomplete AST")
	}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		methods := ast.Targets[target]
		if len(methods) != 27 {
			t.Fatal(target)
		}
		for name := range ast.Bodies {
			if methods[name].Kinds["CompoundStmt"] == 0 {
				t.Fatal(target, name)
			}
		}
		if methods["_CFBundleCopyExecutableName"].References["CFDictionaryGetValue"] != 2 || methods["_urlExists"].References["_CFGetFileProperties"] != 1 {
			t.Fatal("missing lookup contract", target)
		}
		if methods["_CFBundleCopyInfoDictionaryInDirectoryWithVersion"].References["CFDictionaryCreateMutable"] != 2 || methods["_CFBundleCopyInfoPlistURL"].References["CFDictionaryGetValue"] != 2 {
			t.Fatal("missing empty dictionary or real/raw plist URL contract", target)
		}
		if methods["CFDictionaryAddValue"].References["CFBasicHashAddValue"] != 1 || methods["CFDictionarySetValue"].References["CFBasicHashSetValue"] != 1 {
			t.Fatal("missing insertion/replacement distinction", target)
		}
		if methods["encodingForXMLData"].References["CFStringConvertIANACharSetNameToEncoding"] != 1 || methods["encodingForXMLData"].Kinds["ReturnStmt"] < 10 {
			t.Fatal("missing encoding detection body", target)
		}
		if methods["CFUniCharFromUTF32"].References["CFUniCharIsSurrogateHighCharacter"] != 2 || methods["CFUniCharFromUTF32"].References["CFUniCharIsSurrogateLowCharacter"] != 3 || methods["CFUniCharFromUTF32"].Kinds["ReturnStmt"] != 3 {
			t.Fatal("missing strict scalar conversion contract", target)
		}
		if methods["parseStringTag"].References["parseCDSect_pl"] != 1 || methods["parseStringTag"].References["parseEntityReference_pl"] != 1 || methods["parseCDSect_pl"].References["CFDataAppendBytes"] != 1 || methods["parseEntityReference_pl"].References["CFStringGetBytes"] != 1 {
			t.Fatal("missing native string assembly bodies", target)
		}

		if methods["CFStringEncodingCharLengthForBytes"].References["__CFStringEncodingPlatformCharLengthForBytes"] != 1 || methods["CFStringEncodingCharLengthForBytes"].References["__CFStringEncodingICUCharLength"] != 1 {
			t.Fatal("missing converter sizing body", target)
		}
		if methods["CFStringEncodingBytesToUnicode"].References["__CFStringEncodingICUToUnicode"] != 1 || methods["CFStringEncodingBytesToUnicode"].References["__CFStringEncodingPlatformBytesToUnicode"] != 1 || methods["CFStringEncodingBytesToUnicode"].Kinds["WhileStmt"] != 1 {
			t.Fatal("missing complete converter dispatch", target)
		}
		if methods["__CFStringEncodingGetFromICUName"].References["ucnv_getStandardName"] != 3 || methods["_createUniqueStringWithUTF8Bytes"].References["CFStringCreateWithBytes"] != 1 {
			t.Fatal("missing charset alias/string construction bodies", target)
		}
		if methods["__CFStringEncodingGetICUName"].References["ucnv_getAlias"] != 2 || methods["__CFStringEncodingICUToUnicode"].References["ucnv_toUnicode"] != 2 || methods["__CFStringEncodingICUToUnicode"].References["ucnv_getInvalidChars"] != 1 {
			t.Fatal("missing native multibyte conversion contract", target)
		}
		if methods["__CFFromWinLatin1"].References["cp1252_to_uni"] != 1 || methods["__CFFromASCII"].Kinds["ReturnStmt"] != 2 || methods["__CFFromISOLatin1"].Kinds["ReturnStmt"] != 1 {
			t.Fatal("missing byte conversion and invalid-byte branches", target)
		}

		if methods["_CFPropertyListCreateWithData"].References["encodingForXMLData"] != 1 || methods["_CFPropertyListCreateWithData"].References["CFStringCreateWithBytes"] != 1 || methods["_createUTF8DataFromString"].References["CFStringGetBytes"] != 2 || methods["parsePlistObject"].References["parseUnquotedPlistString"] != 1 {
			t.Fatal("missing unmarked conversion or initial-object contract", target)
		}

	}
	var corpus struct {
		Schema  int
		Driver  string `json:"driver_sha256"`
		Fixture string `json:"fixture_info_sha256"`
		Native  string `json:"native_sha256"`
		Cases   []struct {
			Scenario        string
			Status          int
			Removed         bool   `json:"info_signature_removed"`
			Envelope        bool   `json:"envelope_removed"`
			Before          string `json:"info_before_sha256"`
			After           string `json:"info_after_sha256"`
			DiscoveryDenied bool   `json:"go_rooted_stat_permission_denied"`
		}
	}
	if err := json.Unmarshal(readTestFile(t, "../../testdata/bundle-removal/native.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	check("scripts/probe-bundle-removal.go", corpus.Driver)
	check("testdata/bundles/arm64.app/Contents/Info.plist", corpus.Fixture)
	if corpus.Schema != 1 || len(corpus.Cases) != 20 || len(corpus.Native) != 64 {
		t.Fatal("incomplete corpus")
	}
	replayed := 0
	for _, tc := range corpus.Cases {
		if tc.DiscoveryDenied != (tc.Scenario == "readattr" || tc.Scenario == "readsecurity") {
			t.Fatal("discovery permission boundary changed", tc.Scenario)
		}
		// Effective ACL cases run in native/portable acceptance rather than
		// pretending their captured metadata applies permissions on this host.
		// Malformed Info.plist remains an explicit discovery prerequisite.
		if strings.HasPrefix(tc.Scenario, "read") || strings.HasPrefix(tc.Scenario, "write") || tc.Scenario == "malformed-info" {
			continue
		}
		replayed++
		t.Run(tc.Scenario, func(t *testing.T) {
			app := filepath.Join(t.TempDir(), "A.app")
			if err := os.CopyFS(app, os.DirFS("../../testdata/bundles/arm64.app")); err != nil {
				t.Fatal(err)
			}
			main := filepath.Join(app, "Contents/MacOS/hello")
			info := filepath.Join(app, "Contents/Info.plist")
			s := string(readTestFile(t, info))
			remove := func() {
				t.Helper()
				if err := os.Remove(main); err != nil {
					t.Fatal(err)
				}
			}
			move := func(to string) {
				t.Helper()
				to = filepath.Join(app, to)
				if err := os.MkdirAll(filepath.Dir(to), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(main, to); err != nil {
					t.Fatal(err)
				}
			}
			switch tc.Scenario {
			case "missing":
				remove()
			case "missing-key", "stem":
				s = strings.ReplaceAll(s, "<key>CFBundleExecutable</key><string>hello</string>", "")
				if tc.Scenario == "stem" {
					move("Contents/MacOS/A")
				}
			case "empty-key":
				s = strings.ReplaceAll(s, "<string>hello</string>", "<string></string>")
			case "bad-key":
				s = strings.ReplaceAll(s, "<string>hello</string>", "<integer>1</integer>")
			case "legacy-key":
				s = strings.ReplaceAll(s, "CFBundleExecutable", "NSExecutable")
			case "no-id":
				s = strings.ReplaceAll(s, "CFBundleIdentifier", "OtherIdentifier")
			case "no-type":
				s = strings.ReplaceAll(s, "CFBundlePackageType", "OtherType")
			case "installer":
				s = strings.ReplaceAll(s, "</dict>", "<key>IFMajorVersion</key><integer>1</integer></dict>")
				remove()
			case "directory":
				remove()
				if err := os.Mkdir(main, 0755); err != nil {
					t.Fatal(err)
				}
			case "root":
				move("hello")
			case "contents":
				move("Contents/hello")
			case "historical-directory":
				move("Contents/Mac OS X/hello")
			default:
				t.Fatal("unqualified native case", tc.Scenario)
			}
			bundleFile(t, app, "Contents/Info.plist", []byte(s))
			if hash([]byte(s)) != tc.Before {
				t.Fatal("input differs from corpus")
			}
			carrier := &signingCarrier{Reader: sidebandCarrier(t, appledouble.File{Attrs: []appledouble.Attr{{Name: "com.apple.cs.CodeDirectory", Value: []byte("info-signature")}}})}
			original, err := os.Stat(info)
			if err != nil {
				t.Fatal(err)
			}
			err = Remove(context.Background(), app, RemoveOptions{AppleDoubleFiles: map[string]appledouble.Value{"Contents/Info.plist": carrier}})
			if (err == nil) != (tc.Status == 0) {
				t.Fatal("native result mismatch", err, tc.Status)
			}
			after, e := os.Stat(info)
			if e != nil || !os.SameFile(original, after) {
				t.Fatal("Info.plist replaced", e)
			}
			if hash(readTestFile(t, info)) != tc.After {
				t.Fatal("Info.plist changed")
			}
			metadata, e := appledouble.Decode(readCarrier(t, carrier))
			if e != nil {
				t.Fatal(e)
			}
			if (len(metadata.Attrs) == 0) != tc.Removed {
				t.Fatal("wrong carrier selected", metadata.Attrs)
			}
			_, e = os.Stat(filepath.Join(app, "Contents/_CodeSignature/CodeResources"))
			if os.IsNotExist(e) != tc.Envelope {
				t.Fatal("envelope mismatch", e)
			}
		})
	}
	if replayed != 13 {
		t.Fatal("missing portable replay", replayed)
	}
}

func TestRemovalDiscoveryBoundaries(t *testing.T) {
	for _, scenario := range []string{"closed-root", "missing-info", "bad-info", "widget", "resource-spec", "dot", "slash", "reserved", "escape-parent", "current-invalid"} {
		t.Run(scenario, func(t *testing.T) {
			app := testBundle(t)
			s := testBundleInfo
			switch scenario {
			case "current-invalid":
				app = testFramework(t, true)
				if err := os.Remove(filepath.Join(app, "Versions/Current")); err != nil {
					t.Fatal(err)
				}
			case "missing-info":
				if err := os.Remove(filepath.Join(app, "Contents/Info.plist")); err != nil {
					t.Fatal(err)
				}
			case "bad-info":
				s = "invalid plist"
			case "widget":
				s = strings.ReplaceAll(s, "</dict>", "<key>MainHTML</key><string>main.html</string></dict>")
			case "resource-spec":
				s = strings.ReplaceAll(s, "</dict>", "<key>CFBundleResourceSpecification</key><string>rules</string></dict>")
			case "dot":
				s = strings.ReplaceAll(s, "hello", ".")
			case "slash":
				s = strings.ReplaceAll(s, "hello", "../elsewhere")
			case "reserved":
				s = strings.ReplaceAll(s, "hello", "NUL")
			case "escape-parent":
				if err := os.RemoveAll(filepath.Join(app, "Contents/MacOS")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), filepath.Join(app, "Contents/MacOS")); err != nil {
					t.Fatal(err)
				}
			}
			if scenario != "current-invalid" && scenario != "missing-info" {
				bundleFile(t, app, "Contents/Info.plist", []byte(s))
			}
			root, err := os.OpenRoot(app)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "closed-root" {
				if err := root.Close(); err != nil {
					t.Fatal(err)
				}
			}
			b, loadErr := loadRemovalBundle(root, app, "")
			if scenario == "bad-info" {
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				if b.executable != "Contents/Info.plist" {
					t.Fatal("lost raw plist fallback", b.executable)
				}
				b.close()
			} else if loadErr == nil {
				b.close()
				t.Fatal("accepted unsupported discovery")
			}
			if _, err := root.Stat("."); !errors.Is(err, os.ErrClosed) {
				t.Fatal("failed loader leaked root", err)
			}
		})
	}
	// A present malformed executable must not redirect to the plist.
	app := testBundle(t)
	bad := fixture(t, "adhoc-arm64")[:32]
	bundleFile(t, app, "Contents/MacOS/hello", bad)
	before := readTestFile(t, filepath.Join(app, "Contents/Info.plist"))
	if err := RemoveSignature(context.Background(), app); err == nil {
		t.Fatal("malformed Mach-O accepted")
	}
	if !bytes.Equal(before, readTestFile(t, filepath.Join(app, "Contents/Info.plist"))) {
		t.Fatal("failed selection mutated Info.plist")
	}
}
