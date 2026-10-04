//go:build ignore

// Capture ISO-2022-JP-1/2 through the host property-list parser. The C helper is a
// test-only oracle, never linked into production. plutil independently checks
// all singletons and representative pair/escape observations in every initial state.
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

type stateTable struct {
	Name    string
	Prefix  []byte
	Mapping int
}
type mapping struct {
	Values    []*string
	TailValid []bool
}
type table struct {
	States   []stateTable
	Mappings []mapping
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
 if (argc != 4) return 2;
 const char *states[]={"", "\x1b(J", "\x1b(I", "\x1b$B", "\x1b$(D", "\x1b$A", "\x1b$(C", "\x1b.A\x1bN", "\x1b.F\x1bN", "\x1b(H", "\x1b$@", "\x1b&@", "\x1b(B", "\x1b.A", "\x1b.F"};
 int state=atoi(argv[3]); if(state<0 || state>=15) return 7;
 int tail = strcmp(argv[2], "tail")==0;
 unsigned char data[1024];
 int prefix = snprintf((char *)data, sizeof(data), "<?xml version=\"1.0\" encoding=\"%s\"?><dict><key>value</key><string><![CDATA[x", argv[1]);
 if(tail) prefix = snprintf((char *)data, sizeof(data), "<?xml version=\"1.0\" encoding=\"%s\"?><dict><key>value</key><string>second</string></dict>", argv[1]);
 if (prefix < 0 || prefix > 512) return 3;
 const char *suffix = tail ? "" : "]]>y</string></dict>";
 int start=prefix;
 memcpy(data+start,states[state],strlen(states[state]));start+=strlen(states[state]);
 for (int n=0;n<256+(state==0?3:1)*65536;n++) {
  int size=0, value=(n-256)&65535;
  unsigned char *raw=data+start;
  if(n<256) {raw[0]=n;size=1;}
  else if(n<256+65536) {raw[0]=value>>8;raw[1]=value&255;size=2;}
  else if(n<256+2*65536) {raw[0]=0x1b;raw[1]=value>>8;raw[2]=value&255;raw[3]=0x5c;raw[4]=0x22;size=5;}
  else {raw[0]=0x1b;raw[1]='$';raw[2]=value>>8;raw[3]=value&255;raw[4]=0x5c;raw[5]=0x22;size=6;}
  if(!tail) {memcpy(raw+size,"\x1b(B",3);size+=3;}
  memcpy(raw+size,suffix,strlen(suffix));
  CFDataRef input = CFDataCreate(NULL,data,start+size+strlen(suffix));
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

func vector(n int) []byte {
	if n < 256 {
		return []byte{byte(n)}
	}
	v := n - 256
	if v < 65536 {
		return []byte{byte(v >> 8), byte(v)}
	}
	if v < 2*65536 {
		return []byte{0x1b, byte(v >> 8), byte(v), 0x5c, 0x22}
	}
	return []byte{0x1b, '$', byte(v >> 8), byte(v), 0x5c, 0x22}
}
func main() {
	out := flag.String("out", "testdata/bundle-removal/plist-iso2022-extensions-values.json", "capture output")
	check := flag.Bool("check", false, "compare fresh native observations with retained evidence")
	flag.Parse()
	const reference = "testdata/bundle-removal/plist-iso2022-extensions-values.json"
	if *check {
		a, e := filepath.Abs(*out)
		must(e)
		b, e := filepath.Abs(reference)
		must(e)
		if a == b {
			panic("-check requires separate -out path")
		}
	}
	dir, e := os.MkdirTemp("", "plist-iso2022-extensions-")
	must(e)
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "oracle.c")
	exe := filepath.Join(dir, "oracle")
	must(os.WriteFile(src, []byte(oracle), 0600))
	run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", src, "-framework", "CoreFoundation", "-o", exe)
	c := capture{Schema: 1, MacOS: string(run("/usr/bin/sw_vers")), SDK: strings.TrimSpace(string(run("xcrun", "--show-sdk-version"))), Clang: string(run("xcrun", "clang", "--version")), Native: hash(read("/usr/bin/plutil")), Source: hash(read("scripts/probe-plist-iso2022-extensions.go")), Oracle: hash([]byte(oracle))}
	for _, name := range []string{"iso-2022-jp-1", "iso_2022_jp_1", "iso2022jp1", "iso-2022-jp-2", "iso_2022_jp_2", "iso2022jp2", "csiso2022jp2"} {
		var t table
		var rawAll []byte
		states := []struct{ name, prefix string }{{"ascii", ""}, {"roman", "\x1b(J"}, {"kana", "\x1b(I"}, {"jis0208", "\x1b$B"}, {"jis0212", "\x1b$(D"}, {"gb2312", "\x1b$A"}, {"ksc5601", "\x1b$(C"}, {"latin", "\x1b.A\x1bN"}, {"greek", "\x1b.F\x1bN"}, {"roman-h", "\x1b(H"}, {"jis1978", "\x1b$@"}, {"jis1990", "\x1b&@"}, {"ascii-b", "\x1b(B"}, {"latin-designated", "\x1b.A"}, {"greek-designated", "\x1b.F"}}
		for state, st := range states {
			raw := run(exe, name, "body", fmt.Sprint(state))
			lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
			count := 256 + 65536
			if state == 0 {
				count += 2 * 65536
			}
			if len(lines) != count {
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
			// Every singleton and contrasting pair/transition/error controls are
			// also independently observed through the actual plutil executable.
			probes := make([]int, 256)
			for i := range probes {
				probes[i] = i
			}
			for _, v := range []int{0x0000, 0x1b1b, 0x1b28, 0x1b24, 0x0e0f, 0x2121, 0x2422, 0x5c22, 0x5c7e, 0x6060, 0x7f7f, 0x8080, 0xa4a2, 0xffff} {
				probes = append(probes, 256+v)
			}
			if state == 0 {
				for _, v := range []int{0x2842, 0x2848, 0x2849, 0x284a, 0x2949, 0x2440, 0x2442, 0x2444, 0x2458, 0x2428, 0x2858, 0x2640, 0x1b28, 0x0000, 0xffff} {
					probes = append(probes, 256+65536+v)
				}
				for _, v := range []int{0x2844, 0x2842, 0x2843, 0x284f, 0x2850, 0x2944, 0x1b28, 0xffff} {
					probes = append(probes, 256+2*65536+v)
				}
			}

			for _, n := range probes {
				input := []byte(`<?xml version="1.0" encoding="` + name + `"?><dict><key>value</key><string><![CDATA[x`)
				input = append(input, st.prefix...)
				input = append(input, vector(n)...)
				input = append(input, []byte("\x1b(B")...)
				input = append(input, []byte(`]]>y</string></dict>`)...)
				path := filepath.Join(dir, "Info.plist")
				must(os.WriteFile(path, input, 0600))
				b, e := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", path).CombinedOutput()
				if values[n] == nil {
					ex, ok := e.(*exec.ExitError)
					if !ok || ex.ExitCode() != 1 {
						panic(fmt.Sprintf("plutil failure drift %s/%x: %s %v", name+"/"+st.name, n, b, e))
					}
					continue
				}
				must(e)
				var v map[string]string
				must(json.Unmarshal(b, &v))
				s, ok := v["value"]
				if !ok || len(v) != 1 || s != "x"+*values[n]+"y" {
					panic(fmt.Sprintf("plutil value drift %s/%x: %s", name+"/"+st.name, n, b))
				}
			}
			tailRaw := run(exe, name, "tail", fmt.Sprint(state))
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
			}
			m := mapping{values, tailValid}
			mappingIndex := -1
			for j, old := range t.Mappings {
				if reflect.DeepEqual(m, old) {
					mappingIndex = j
					break
				}
			}
			if mappingIndex < 0 {
				mappingIndex = len(t.Mappings)
				t.Mappings = append(t.Mappings, m)
			}
			t.States = append(t.States, stateTable{st.name, []byte(st.prefix), mappingIndex})
			rawAll = append(rawAll, raw...)
			rawAll = append(rawAll, tailRaw...)
			fmt.Printf("Captured %s/%s: %d body/EOF observations, %d plutil checks\n", name, st.name, 2*count, len(probes))
		}

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
		c.Codecs = append(c.Codecs, codec{name, index, hash(rawAll)})
	}
	if len(c.Tables) != 2 {
		panic("unexpected native mapping families")
	}
	if *check {
		var old capture
		must(json.Unmarshal(read(reference), &old))
		if c.Source != old.Source || c.Oracle != old.Oracle || !reflect.DeepEqual(c.Codecs, old.Codecs) || !reflect.DeepEqual(c.Tables, old.Tables) {
			panic("native ISO-2022-JP-1/2 evidence changed")
		}
	}
	b, e := json.MarshalIndent(c, "", "  ")
	must(e)
	must(os.WriteFile(*out, append(b, '\n'), 0644))
}
