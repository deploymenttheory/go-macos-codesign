//go:build ignore

// Capture Shift-JIS through the host property-list parser. The C helper is a
// test-only oracle, never linked into production. plutil independently checks
// representative observations for every declared name.
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
	Singles, Pairs []*string
	TailValid      []bool
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
 int prefix = snprintf((char *)data, sizeof(data), "<?xml version=\"1.0\" encoding=\"%s\"?><dict><key>value</key><string><![CDATA[", argv[1]);
 if(tail) prefix = snprintf((char *)data, sizeof(data), "<?xml version=\"1.0\" encoding=\"%s\"?><dict><key>value</key><string>second</string></dict>", argv[1]);
 if (prefix < 0 || prefix > 512) return 3;
 const char *suffix = tail ? "" : "]]></string></dict>";
 for (int n=0;n<256+65536;n++) {
  int size = n<256 ? 1 : 2;
  int value = n<256 ? n : n-256;
  if(size==1) data[prefix]=value; else { data[prefix]=value>>8; data[prefix+1]=value&255; }
  memcpy(data+prefix+size,suffix,strlen(suffix));
  CFDataRef input = CFDataCreate(NULL,data,prefix+size+strlen(suffix));
  CFErrorRef error = NULL;
  CFPropertyListRef parsed = CFPropertyListCreateWithData(NULL,input,kCFPropertyListImmutable,NULL,&error);
  CFRelease(input);
  if (!parsed) { puts("-"); if(error) CFRelease(error); continue; }
  if(error || CFGetTypeID(parsed)!=CFDictionaryGetTypeID() || CFDictionaryGetCount(parsed)!=1) return 4;
  CFStringRef str = CFDictionaryGetValue(parsed,CFSTR("value"));
  if(!str || CFGetTypeID(str)!=CFStringGetTypeID()) return 5;
  CFDataRef result=CFStringCreateExternalRepresentation(NULL,str,kCFStringEncodingUTF8,0);
  if(!result) return 6;
  const UInt8 *b=CFDataGetBytePtr(result);
  for(CFIndex i=0;i<CFDataGetLength(result);i++) printf("%02x",b[i]);
  puts(""); CFRelease(result); CFRelease(parsed);
 }
 return 0;
}
`

func main() {
	out := flag.String("out", "testdata/bundle-removal/plist-shift-jis-values.json", "capture output")
	check := flag.Bool("check", false, "compare fresh native observations with retained evidence")
	flag.Parse()
	const reference = "testdata/bundle-removal/plist-shift-jis-values.json"
	if *check {
		a, e := filepath.Abs(*out)
		must(e)
		b, e := filepath.Abs(reference)
		must(e)
		if a == b {
			panic("-check requires separate -out path")
		}
	}
	dir, e := os.MkdirTemp("", "plist-shift-jis-")
	must(e)
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "oracle.c")
	exe := filepath.Join(dir, "oracle")
	must(os.WriteFile(src, []byte(oracle), 0600))
	run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", src, "-framework", "CoreFoundation", "-o", exe)
	c := capture{Schema: 1, MacOS: string(run("/usr/bin/sw_vers")), SDK: strings.TrimSpace(string(run("xcrun", "--show-sdk-version"))), Clang: string(run("xcrun", "clang", "--version")), Native: hash(read("/usr/bin/plutil")), Source: hash(read("scripts/probe-plist-shift-jis.go")), Oracle: hash([]byte(oracle))}
	for _, name := range []string{"shift_jis", "shift-jis", "sjis", "ms_kanji", "csshiftjis", "cp932", "windows-31j", "windows-932"} {
		raw := run(exe, name, "body")
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if len(lines) != 256+65536 {
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
			s := string(b)
			values[n] = &s
		}
		// Direct plutil comparison includes every singleton and contrasting pair
		// mappings, invalid trails, undefined pairs and lead/ASCII boundaries.
		probes := make([]int, 256)
		for i := range probes {
			probes[i] = i
		}
		for _, v := range []int{0x0000, 0x005c, 0x5c7e, 0x815c, 0x8160, 0x8161, 0x817c, 0x8191, 0x8192, 0x81ca, 0x8140, 0x817f, 0x81fd, 0x81ff, 0x8200, 0x82a0, 0x889f, 0x9873, 0xe040, 0xea9e, 0xed40, 0xeeef, 0xf040, 0xf9fc, 0xfa40, 0xfc4b, 0xfcfc, 0xffff} {
			probes = append(probes, 256+v)
		}
		for _, n := range probes {
			input := []byte(`<?xml version="1.0" encoding="` + name + `"?><dict><key>value</key><string><![CDATA[`)
			if n < 256 {
				input = append(input, byte(n))
			} else {
				input = append(input, byte((n-256)>>8), byte(n-256))
			}
			input = append(input, []byte(`]]></string></dict>`)...)
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
			if !ok || len(v) != 1 || s != *values[n] {
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
		t := table{values[:256], values[256:], tailValid}
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
		fmt.Printf("Captured %s: 131,584 native body/tail observations, %d plutil comparisons\n", name, len(probes))
	}
	if len(c.Tables) != 2 {
		panic("unexpected native mapping families")
	}
	if *check {
		var old capture
		must(json.Unmarshal(read(reference), &old))
		if c.Source != old.Source || c.Oracle != old.Oracle || !reflect.DeepEqual(c.Codecs, old.Codecs) || !reflect.DeepEqual(c.Tables, old.Tables) {
			panic("native Shift-JIS evidence changed")
		}
	}
	b, e := json.MarshalIndent(c, "", "  ")
	must(e)
	must(os.WriteFile(*out, append(b, '\n'), 0644))
}
