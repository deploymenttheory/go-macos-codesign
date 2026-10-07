//go:build ignore

package main

import "testing"

func TestCompressedProfileUsesIndependentMountObservation(t *testing.T) {
	for _, build := range []string{"26A428", "26A434"} {
		for _, flags := range []uint32{0, 0x1000, 0x80, 0x1080} {
			got, err := compressedProfile(build, volumeObservation{"apfs", flags, 0x80})
			want := "compressed-signing.json"
			if flags&0x80 != 0 {
				want = "compressed-signing-26A434.json"
			}
			if got != want || err != nil {
				t.Fatal(build, flags, got, err)
			}
		}
	}
	for _, volume := range []volumeObservation{{}, {"apfs", 0, 0}, {"hfs", 0, 0x80}, {"apfs", 0x80, 0x40}} {
		if got, err := compressedProfile("26A434", volume); got != "" || err == nil {
			t.Fatal("uncaptured mount policy accepted", volume, got, err)
		}
	}
	if got, err := compressedProfile("unknown", volumeObservation{"apfs", 0, 0x80}); got != "" || err == nil {
		t.Fatal("unqualified build accepted", got, err)
	}
}
