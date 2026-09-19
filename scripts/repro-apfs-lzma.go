//go:build ignore

// Development-only reproducer: construct an unsigned image without signing it.
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run scripts/repro-apfs-lzma.go OUTPUT.dmg")
	}
	data := bytes.Repeat([]byte("public UDIF fixture payload\n"), 200)
	data = append(data, make([]byte, 8192-len(data))...)
	var out bytes.Buffer
	if err := disk.EncodeUDIF(&out, []disk.SourceBlock{{Name: "fixture", Data: data, SectorCount: 16}}, &disk.EncodeOptions{Compression: disk.CompressionLZMA}); err != nil {
		panic(err)
	}
	f, err := os.OpenFile(os.Args[1], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	_, err = f.Write(out.Bytes())
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		panic(fmt.Sprintf("write: %v; close: %v", err, closeErr))
	}
	fmt.Println("Created unsigned APFS-encoder LZMA reproducer:", os.Args[1])
}
