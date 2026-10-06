package codesign

import (
	"encoding/binary"
	"testing"
)

func TestMachOExecutableSegmentPlatform(t *testing.T) {
	build := func(platform uint32) []byte {
		b := commandTestField(0x32, 24)
		binary.LittleEndian.PutUint32(b[8:], platform)
		return b
	}
	legacy := func(kind uint32) []byte { return commandTestField(kind, 16) }
	for _, tc := range []struct {
		name     string
		commands [][]byte
		platform uint32
	}{
		{"absent", nil, 0},
		{"macos", [][]byte{legacy(0x24)}, 1},
		{"ios", [][]byte{legacy(0x25)}, 2},
		{"tvos", [][]byte{legacy(0x2f)}, 3},
		{"watchos", [][]byte{legacy(0x30)}, 4},
		{"first-legacy", [][]byte{legacy(0x30), legacy(0x24)}, 4},
		{"build-overrides-legacy", [][]byte{legacy(0x24), build(2)}, 2},
		{"zero-build-overrides-legacy", [][]byte{legacy(0x24), build(0)}, 0},
		{"first-build", [][]byte{build(0), build(1)}, 0},
		{"legacy-after-build", [][]byte{build(3), legacy(0x24)}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := syntheticMachO(binary.LittleEndian, true)
			pos := 32 + 2*72
			for _, command := range tc.commands {
				copy(b[pos:], command)
				pos += len(command)
			}
			binary.LittleEndian.PutUint32(b[16:], uint32(2+len(tc.commands)))
			binary.LittleEndian.PutUint32(b[20:], uint32(pos-32))
			im, err := parseImage(b)
			if err != nil || im.execPlatform != tc.platform {
				t.Fatalf("platform summary: %+v, %v", im, err)
			}
			for _, team := range []string{"", "TEAM123456"} {
				for _, runtime := range []bool{false, true} {
					opts := SignOptions{Identifier: "org.example.platform", teamID: team}
					wantVersion, wantLimit := uint32(0x20100), uint64(0)
					if team != "" {
						wantVersion = 0x20200
					}
					if tc.platform != 0 {
						wantVersion, wantLimit = 0x20400, 4096
					}
					if runtime {
						opts.Flags, opts.RuntimeVersion = FlagRuntime, 27<<16
						wantVersion = 0x20500
					}
					out, err := SignBytes(t.Context(), b, opts)
					if err != nil {
						t.Fatal(err)
					}
					r, err := VerifyBytes(t.Context(), out, VerifyOptions{})
					if err != nil {
						t.Fatal(err)
					}
					d := r.Architectures[0].Signature.Directories[0]
					if d.Version != wantVersion || d.ExecLimit != wantLimit || d.TeamID != team {
						t.Fatalf("directory: version=%x limit=%d team=%q; want %x/%d/%q", d.Version, d.ExecLimit, d.TeamID, wantVersion, wantLimit, team)
					}
				}
			}
		})
	}
}
