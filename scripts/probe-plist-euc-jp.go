//go:build ignore

// Capture EUC-JP through the host property-list parser. The C helper is a
// test-only oracle, never linked into production. plutil independently checks
// all singletons and representative two/three-byte observations for every declared name.
// Body values are framed with ASCII x/y to preserve a leading U+FEFF scalar
// through native plist string construction; framing is removed only afterwards.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"unicode/utf8"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(name string, args ...string) []byte {
	c := exec.Command(name, args...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, e := c.Output()
	if e != nil {
		panic(fmt.Sprintf("%s: %v: %s", name, e, stderr.String()))
	}
	return b
}

type table struct {
	Singles, Pairs, Triples []*string
	TailValid               []bool
}
type codec struct {
	Name   string
	Table  int
	SHA256 string
}
type capture struct {
	Schema int     `json:"schema"`
	MacOS  string  `json:"macos"`
	SDK    string  `json:"sdk"`
	Clang  string  `json:"clang"`
	Native string  `json:"native_sha256"`
	Source string  `json:"source_sha256"`
	Oracle string  `json:"oracle_sha256"`
	Codecs []codec `json:"codecs"`
	Tables []table `json:"tables"`
}

const oracle = `#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
 if (argc != 3) return 2;
 int tail = strcmp(argv[2], "tail")==0;
 unsigned char data[1024];
 int prefix = snprintf((char *)data, sizeof(data), "<?xml version=\"1.0\" encoding=\"%s\"?><dict><key>value</key><string><![CDATA[x", argv[1]);
 if(tail) prefix = snprintf((char *)data, sizeof(data), "<?xml version=\"1.0\" encoding=\"%s\"?><dict><key>value</key><string>second</string></dict>", argv[1]);
 if (prefix < 0 || prefix > 512) return 3;
 const char *suffix = tail ? "" : "]]>y</string></dict>";
 for (int n=0;n<256+65536+65536;n++) {
  int size = n<256 ? 1 : (n<256+65536 ? 2 : 3);
  int value = n<256 ? n : (n-256)&65535;
  if(size==1) data[prefix]=value;
  else if(size==2) { data[prefix]=value>>8; data[prefix+1]=value&255; }
  else { data[prefix]=0x8f; data[prefix+1]=value>>8; data[prefix+2]=value&255; }
  memcpy(data+prefix+size,suffix,strlen(suffix));
  CFDataRef input = CFDataCreate(NULL,data,prefix+size+strlen(suffix));
  CFErrorRef error = NULL;
  CFPropertyListRef parsed = CFPropertyListCreateWithData(NULL,input,kCFPropertyListImmutable,NULL,&error);
  CFRelease(input);
  if (!parsed) { puts("-"); if(error) CFRelease(error); continue; }
  if(error || CFGetTypeID(parsed)!=CFDictionaryGetTypeID() || CFDictionaryGetCount(parsed)!=1) return 4;
  CFStringRef str = CFDictionaryGetValue(parsed,CFSTR("value"));
  if(!str || CFGetTypeID(str)!=CFStringGetTypeID()) return 5;
  UInt8 result[64]; CFIndex used=0, length=CFStringGetLength(str);
  if (CFStringGetBytes(str,CFRangeMake(0,length),kCFStringEncodingUTF8,0,false,result,sizeof(result),&used)!=length) return 6;
  for(CFIndex i=0;i<used;i++) printf("%02x",result[i]);
  puts(""); CFRelease(parsed);
 }
 return 0;
}
`

func main() {
	out := flag.String("out", "testdata/bundle-removal/plist-euc-jp-values.json", "capture output")
	check := flag.Bool("check", false, "compare fresh native observations with retained evidence")
	flag.Parse()
	const reference = "testdata/bundle-removal/plist-euc-jp-values.json"
	if *check {
		a, e := filepath.Abs(*out)
		must(e)
		b, e := filepath.Abs(reference)
		must(e)
		if a == b {
			panic("-check requires separate -out path")
		}
	}
	dir, e := os.MkdirTemp("", "plist-euc-jp-")
	must(e)
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "oracle.c")
	exe := filepath.Join(dir, "oracle")
	must(os.WriteFile(src, []byte(oracle), 0600))
	run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", src, "-framework", "CoreFoundation", "-o", exe)
	c := capture{Schema: 1, MacOS: string(run("/usr/bin/sw_vers")), SDK: strings.TrimSpace(string(run("xcrun", "--show-sdk-version"))), Clang: string(run("xcrun", "clang", "--version")), Native: hash(read("/usr/bin/plutil")), Source: hash(read("scripts/probe-plist-euc-jp.go")), Oracle: hash([]byte(oracle))}
	for _, name := range []string{"euc-jp", "euc_jp", "eucjp", "cseucpkdfmtjapanese", "extended_unix_code_packed_format_for_japanese", "x-euc-jp", "cp51932", "windows-51932"} {
		raw := run(exe, name, "body")
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if len(lines) != 256+65536+65536 {
			panic("incomplete native byte inventory")
		}
		values := make([]*string, len(lines))
		for n, line := range lines {
			if line == "-" {
				continue
			}
			b, e := hex.DecodeString(line)
			must(e)
			if !utf8.Valid(b) {
				panic("invalid native UTF-8")
			}
			if len(b) < 2 || b[0] != 'x' || b[len(b)-1] != 'y' {
				panic("native framing changed")
			}
			s := string(b[1 : len(b)-1])
			values[n] = &s
		}
		// Direct plutil independently checks all singleton values and contrasting
		// two/three-byte mappings, invalid trails and incomplete prefixes.
		probes := make([]int, 256)
		for i := range probes {
			probes[i] = i
		}
		for _, v := range []int{0x0000, 0x005c, 0x5c7e, 0x8e00, 0x8e3f, 0xa000, 0xa03f, 0xa422, 0x8ea1, 0x8edf, 0x8ee0, 0x8e80, 0x8eff, 0x8fa1, 0x8ffe, 0xa1a1, 0xa1c1, 0xa1dd, 0xa1ef, 0xa1f1, 0xa1f2, 0xa2cc, 0xa4a2, 0xada1, 0xadb0, 0xada0, 0xf4a6, 0xf5a1, 0xfefe, 0xffff, 0xa180, 0xa1ff, 0x8080} {
			probes = append(probes, 256+v)
		}
		for _, v := range []int{0x0000, 0x0080, 0x8080, 0x8f8f, 0xa0a1, 0xa1a1, 0xa2af, 0xa2b0, 0xa2ed, 0xa4a2, 0xb0a1, 0xedc1, 0xf3f3, 0xf4a1, 0xf5a1, 0xfefe, 0xfffe, 0xfeff, 0xffff} {
			probes = append(probes, 256+65536+v)
		}
		for _, n := range probes {
			input := []byte(`<?xml version="1.0" encoding="` + name + `"?><dict><key>value</key><string><![CDATA[x`)
			if n < 256 {
				input = append(input, byte(n))
			} else if n < 256+65536 {
				input = append(input, byte((n-256)>>8), byte(n-256))
			} else {
				input = append(input, 0x8f, byte((n-256-65536)>>8), byte(n-256-65536))
			}
			input = append(input, []byte(`]]>y</string></dict>`)...)
			path := filepath.Join(dir, "Info.plist")
			must(os.WriteFile(path, input, 0600))
			b, e := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", path).CombinedOutput()
			if values[n] == nil {
				ex, ok := e.(*exec.ExitError)
				if !ok || ex.ExitCode() != 1 {
					panic(fmt.Sprintf("plutil failure drift %s/%x: %s %v", name, n, b, e))
				}
				continue
			}
			must(e)
			var v map[string]string
			must(json.Unmarshal(b, &v))
			s, ok := v["value"]
			if !ok || len(v) != 1 || s != "x"+*values[n]+"y" {
				panic(fmt.Sprintf("plutil value drift %s/%x: %s", name, n, b))
			}
		}
		tailRaw := run(exe, name, "tail")
		tails := strings.Split(strings.TrimSuffix(string(tailRaw), "\n"), "\n")
		if len(tails) != len(values) {
			panic("incomplete tail inventory")
		}
		tailValid := make([]bool, len(tails))
		for n, v := range tails {
			if v != "-" && v != "7365636f6e64" {
				panic("unexpected tail value")
			}
			tailValid[n] = v != "-"
			if tailValid[n] != (values[n] != nil) {
				panic(fmt.Sprintf("body/tail conversion differs %s/%x", name, n))
			}
		}
		t := table{values[:256], values[256 : 256+65536], values[256+65536:], tailValid}
		index := -1
		for i, old := range c.Tables {
			if reflect.DeepEqual(t, old) {
				index = i
				break
			}
		}
		if index < 0 {
			index = len(c.Tables)
			c.Tables = append(c.Tables, t)
		}
		c.Codecs = append(c.Codecs, codec{name, index, hash(append(raw, tailRaw...))})
		fmt.Printf("Captured %s: 262,656 native body/tail observations, %d plutil comparisons\n", name, len(probes))
	}
	if len(c.Tables) != 1 {
		panic("unexpected native mapping families")
	}
	if *check {
		var old capture
		must(json.Unmarshal(read(reference), &old))
		if c.Source != old.Source || c.Oracle != old.Oracle || !reflect.DeepEqual(c.Codecs, old.Codecs) || !reflect.DeepEqual(c.Tables, old.Tables) {
			panic("native EUC-JP evidence changed")
		}
	}
	b, e := json.MarshalIndent(c, "", "  ")
	must(e)
	must(os.WriteFile(*out, append(b, '\n'), 0644))
}
