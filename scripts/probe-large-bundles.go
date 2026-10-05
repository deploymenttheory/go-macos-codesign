//go:build ignore

// Research only: native bundle payload boundaries and complete member outcomes.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type member struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Prefix    []byte `json:"prefix"`
	Populated bool   `json:"populated"`
}
type fileState struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type outcome struct {
	Exit           int                  `json:"exit"`
	Diagnostic     string               `json:"diagnostic"`
	Files          map[string]fileState `json:"files"`
	ExecutableSame bool                 `json:"executable_same"`
	NeighbourSame  bool                 `json:"neighbour_same"`
}
type observation struct {
	Name       string             `json:"name"`
	Bundle     string             `json:"bundle"`
	Executable string             `json:"executable"`
	Members    []member           `json:"members"`
	Operations map[string]outcome `json:"operations"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func snapshot(path string) map[string]fileState {
	states := map[string]fileState{}
	must(filepath.WalkDir(path, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		defer f.Close()
		h := sha256.New()
		n, e := io.Copy(h, f)
		if e != nil {
			return e
		}
		name, e := filepath.Rel(path, p)
		if e != nil {
			return e
		}
		states[filepath.ToSlash(name)] = fileState{n, hex.EncodeToString(h.Sum(nil))}
		return nil
	}))
	return states
}
func info(framework bool) []byte {
	kind := "APPL"
	if framework {
		kind = "FMWK"
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleExecutable</key><string>hello</string><key>CFBundleIdentifier</key><string>org.example.large-bundle</string><key>CFBundlePackageType</key><string>` + kind + `</string></dict></plist>`)
}
func main() {
	check := flag.Bool("check", false, "compare native observations")
	out := flag.String("out", "testdata/research/large-bundles.json", "capture destination")
	flag.Parse()
	var macho struct {
		Cases []struct {
			Name   string `json:"name"`
			Length int64  `json:"length"`
			Prefix []byte `json:"prefix"`
		}
	}
	must(json.Unmarshal(read("testdata/research/large-macho.json"), &macho))
	large := func(name, variant string) member {
		for _, r := range macho.Cases {
			if r.Name == variant {
				return member{name, r.Length, r.Prefix, false}
			}
		}
		panic(variant)
	}
	small := func(name string, b []byte) member { return member{name, int64(len(b)), b, false} }
	seed := read("testdata/removal/unsigned-arm64.macho")
	var cases []observation
	for _, size := range []int64{1<<30 - 1, 1 << 30, 1<<30 + 1} {
		cases = append(cases, observation{Name: fmt.Sprint("executable-", size), Bundle: "Large.app", Executable: "Contents/MacOS/hello", Members: []member{small("Contents/Info.plist", info(false)), large("Contents/MacOS/hello", fmt.Sprint(size))}})
	}
	for _, size := range []int64{4<<30 - 1, 4 << 30, 4<<30 + 1} {
		cases = append(cases, observation{Name: fmt.Sprint("resource-", size), Bundle: "Large.app", Executable: "Contents/MacOS/hello", Members: []member{small("Contents/Info.plist", info(false)), small("Contents/MacOS/hello", seed), {"Contents/Resources/payload", size, []byte("resource"), true}}})
	}
	for _, kind := range []string{"nested-app", "nested-helper", "aggregate"} {
		row := observation{Name: kind, Bundle: "Large.app", Executable: "Contents/MacOS/hello", Members: []member{small("Contents/Info.plist", info(false)), small("Contents/MacOS/hello", seed)}}
		if kind == "nested-helper" {
			row.Members = append(row.Members, large("Contents/Helpers/helper", "1073741825"))
		} else {
			row.Members = append(row.Members, small("Contents/Helpers/Child.app/Contents/Info.plist", info(false)), large("Contents/Helpers/Child.app/Contents/MacOS/hello", "1073741825"))
		}
		if kind == "aggregate" {
			row.Members[1] = large(row.Executable, "1073741825")
			for _, name := range []string{"first", "second"} {
				row.Members = append(row.Members, member{"Contents/Resources/" + name, 1<<30 + 1, []byte(name), true})
			}
		}
		cases = append(cases, row)
	}
	cases = append(cases, observation{Name: "framework-universal-2147483649", Bundle: "Large.framework", Executable: "hello", Members: []member{small("Resources/Info.plist", info(true)), large("hello", "universal-2147483649")}})
	tmp, e := os.MkdirTemp("", "codesign-large-bundles-")
	must(e)
	defer os.RemoveAll(tmp)
	tmp, e = filepath.EvalSymlinks(tmp)
	must(e)
	for i := range cases {
		row := &cases[i]
		path := filepath.Join(tmp, row.Bundle)
		must(os.MkdirAll(path, 0755))
		for _, m := range row.Members {
			p := filepath.Join(path, filepath.FromSlash(m.Name))
			must(os.MkdirAll(filepath.Dir(p), 0755))
			f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0755)
			must(e)
			_, e = f.Write(m.Prefix)
			must(e)
			must(f.Truncate(m.Size))
			if m.Populated {
				b := make([]byte, 4<<20+37)
				for i := range b {
					b[i] = byte(i % 251)
				}
				_, e = f.WriteAt(b, 1<<29-17)
				must(e)
			}
			must(f.Close())
		}
		row.Operations = map[string]outcome{}
		args := []string{"-s", "-", "--deep", "--timestamp=none"}
		for _, op := range []struct {
			name string
			args []string
		}{{"sign", args}, {"verify", []string{"--verify", "--strict", "--deep"}}, {"resign", append([]string{"-f"}, args...)}, {"dryrun", append([]string{"-f", "--dryrun"}, args...)}, {"remove", []string{"--remove-signature"}}} {
			executable := filepath.Join(path, filepath.FromSlash(row.Executable))
			link := filepath.Join(tmp, "neighbour")
			must(os.Link(executable, link))
			before, e := os.Stat(link)
			must(e)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			command := exec.CommandContext(ctx, "/usr/bin/codesign", append(op.args, path)...)
			command.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			started := time.Now()
			e = command.Run()
			must(ctx.Err())
			cancel()
			exit := 0
			if e != nil {
				if x, ok := e.(*exec.ExitError); ok {
					exit = x.ExitCode()
				} else {
					panic(e)
				}
			}
			after, e := os.Stat(executable)
			must(e)
			neighbour, e := os.Stat(link)
			must(e)
			row.Operations[op.name] = outcome{exit, strings.ReplaceAll(output.String(), path, "<bundle>"), snapshot(path), os.SameFile(before, after), os.SameFile(before, neighbour)}
			must(os.Remove(link))
			fmt.Printf("%s %s exit=%d elapsed=%s\n", row.Name, op.name, exit, time.Since(started))
			if exit != 0 {
				panic("native large bundle control failed")
			}
		}
		must(os.RemoveAll(path))
	}
	sources := map[string]string{}
	for _, p := range []string{"scripts/probe-large-bundles.go", "testdata/research/large-macho.json", "testdata/removal/unsigned-arm64.macho", "spec/apple-writer.json", "spec/apple-hashing.json", "spec/apple-macho-allocation.json", "/usr/bin/codesign"} {
		sources[p] = hash(read(p))
	}
	host, e := exec.Command("sw_vers").Output()
	must(e)
	capture := map[string]any{"schema": 1, "recipe": "Members contain exact prefixes and lengths, followed by zeros; populated resources contain byte(i%251) for 4 MiB+37 at 512 MiB-17. Execute sign/deep verify/force resign/dryrun/outer removal in order. Every member is hashed in full after each operation. External main-executable hard link records inode effects.", "source_sha256": sources, "host": string(host), "cases": cases}
	data, e := json.MarshalIndent(capture, "", "  ")
	must(e)
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	must(os.WriteFile(*out, append(data, '\n'), 0644))
	if *check {
		var baseline struct{ Cases []observation }
		must(json.Unmarshal(read("testdata/research/large-bundles.json"), &baseline))
		if !reflect.DeepEqual(cases, baseline.Cases) {
			panic("native bundle observations changed")
		}
	}
}
