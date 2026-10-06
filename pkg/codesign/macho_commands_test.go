package codesign

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func commandTestBytes(commands ...[]byte) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b, 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x100000c)
	binary.LittleEndian.PutUint32(b[12:], 2)
	binary.LittleEndian.PutUint32(b[16:], uint32(len(commands)))
	for _, command := range commands {
		b = append(b, command...)
	}
	binary.LittleEndian.PutUint32(b[20:], uint32(len(b)-32))
	return append(b, make([]byte, 64)...)
}
func commandTestField(kind, size uint32) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b, kind)
	binary.LittleEndian.PutUint32(b[4:], size)
	return b
}

func TestMachOCommandSummaryPrecedence(t *testing.T) {
	uuid := commandTestField(0x1b, 24)
	copy(uuid[8:], "0123456789abcdef")
	badUUID := commandTestField(0x1b, 8)
	version := func(v uint32) []byte {
		b := commandTestField(0x32, 24)
		binary.LittleEndian.PutUint32(b[8:], v)
		binary.LittleEndian.PutUint32(b[12:], v+1)
		binary.LittleEndian.PutUint32(b[16:], v+2)
		return b
	}
	for _, badFirst := range []bool{false, true} {
		first, second := uuid, badUUID
		if badFirst {
			first, second = second, first
		}
		b := commandTestBytes(first, second, version(3), version(7))
		c, err := parseContainer(b)
		if err != nil {
			t.Fatal(err)
		}
		// Inspection never promotes a deferred UUID-size error into a parser error.
		r, err := InspectBytes(b)
		if err != nil || r.Architectures[0].VersionPlatform != 7 || r.Architectures[0].VersionMin != 8 || r.Architectures[0].VersionSDK != 9 {
			t.Fatal(r, err)
		}
		if identifier, err := c.identifier("hello.7", true); err != nil || identifier != "hello.7" {
			t.Fatal("canonical ID should not consume malformed UUID", identifier, err)
		}
		for _, adhoc := range []bool{false, true} {
			_, err := c.identifier("hello", adhoc)
			if (err != nil) != (adhoc && badFirst) {
				t.Fatal("UUID precedence", badFirst, adhoc, err)
			}
		}
	}
	for _, symbolsFirst := range []bool{false, true} {
		for _, short := range []bool{false, true} {
			symbols := commandTestField(2, 24)
			if short {
				symbols = commandTestField(2, 8)
			}
			link := commandTestField(0x19, 72)
			copy(link[8:], "__LINKEDIT")
			// A valid zero-length segment at offset zero does not end at EOF.
			commands := [][]byte{link, symbols}
			if symbolsFirst {
				commands = [][]byte{symbols, link}
			}
			b := commandTestBytes(commands...)
			if !short {
				binary.LittleEndian.PutUint32(symbols[16:], uint32(len(b)))
				b = commandTestBytes(commands...)
			}
			err := verifyStrictLayout(b, "", false)
			if (err == nil) != (symbolsFirst && !short) {
				t.Fatal("strict first candidate", symbolsFirst, short, err)
			}
		}
	}
}

func TestMachOCommandReadFailures(t *testing.T) {
	fault := errors.New("command read fault")
	for _, data := range [][]byte{fixture(t, "adhoc-arm64"), syntheticMachO(binary.LittleEndian, false)} {
		var reads int
		run := func(fail int, short, cancelRead bool) error {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reads = 0
			source := codeSource{ctx, outputSource{reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
				reads++
				if reads == fail {
					if cancelRead {
						cancel()
					}
					if short {
						return 0, nil
					}
					return 0, fault
				}
				return bytes.NewReader(data).ReadAt(p, at)
			}), size: int64(len(data))}}
			_, err := source.container()
			return err
		}
		if err := run(0, false, false); err != nil {
			t.Fatal(err)
		}
		total := reads
		for i := 1; i <= total; i++ {
			for _, short := range []bool{false, true} {
				want := fault
				if short {
					want = io.ErrUnexpectedEOF
				}
				if err := run(i, short, false); !errors.Is(err, want) {
					t.Fatal(i, err, want)
				}
				if err := run(i, short, true); !errors.Is(err, context.Canceled) {
					t.Fatal(i, err)
				}
			}
		}
	}
	// Fallback ID hashes all unknown command bytes, with bounded reads and errors.
	unknown := commandTestField(0x7777, 2*transferBufferSize+12)
	for i := 8; i < len(unknown); i++ {
		unknown[i] = byte(i)
	}
	data := commandTestBytes(unknown)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fail := false
	source := codeSource{ctx, outputSource{reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
		if len(p) > transferBufferSize {
			t.Fatal("unbounded ID read", len(p))
		}
		if fail && at >= 32 {
			return 0, fault
		}
		return bytes.NewReader(data).ReadAt(p, at)
	}), size: int64(len(data))}}
	c, err := source.container()
	if err != nil {
		t.Fatal(err)
	}
	h := sha1.New()
	_, _ = h.Write(data[:28])
	_, _ = h.Write(unknown)
	if id, err := c.identifier("hello", true); err != nil || id != "hello-"+hex.EncodeToString(h.Sum(nil)) {
		t.Fatal(id, err)
	}
	fail = true
	if _, err := c.identifier("hello", true); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	cancel()
	if _, err := c.identifier("hello", true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestMachOCommandPatchFailures(t *testing.T) {
	data := fixture(t, "unsigned-arm64")
	im, err := parseImage(data)
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("padding fault")
	reader := transferReaderFunc(func(p []byte, at int64) (int, error) {
		if at >= int64(im.header)+int64(im.commandBytes) {
			return 0, fault
		}
		return bytes.NewReader(data).ReadAt(p, at)
	})
	if _, err := signingCommandOutput(t.Context(), im, outputSource{reader: reader, size: int64(len(data))}, int64(len(data)), 16, int64(len(data))+16); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	// The planner rejects invalid borrowed offsets before publishing a plan.
	if _, err := signingCommandOutput(t.Context(), im, outputSource{reader: bytes.NewReader(data), offset: -1, size: int64(len(data))}, int64(len(data)), 16, int64(len(data))+16); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
}

func TestMachOCommandPhysicalOldLimit(t *testing.T) {
	// This is a parser/storage boundary control, not a fabricated native oracle.
	// One opaque command crosses the former 1 GiB metadata allocation ceiling.
	const commandSize = uint32(1<<30) + 4
	linkAt := int64(32) + int64(commandSize)
	commandsEnd := linkAt + 72
	fileSize := commandsEnd + 16 + 64
	f, err := os.Create(filepath.Join(t.TempDir(), "large-commands"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := prepareCommandSparseFixture(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(fileSize); err != nil {
		t.Fatal(err)
	}
	header := commandTestBytes(commandTestField(0x7777, 8))[:40]
	binary.LittleEndian.PutUint32(header[16:], 2)
	binary.LittleEndian.PutUint32(header[20:], commandSize+72)
	binary.LittleEndian.PutUint32(header[36:], commandSize)
	link := commandTestField(0x19, 72)
	copy(link[8:], "__LINKEDIT")
	binary.LittleEndian.PutUint64(link[40:], uint64(commandsEnd+16))
	binary.LittleEndian.PutUint64(link[48:], 64)
	for _, part := range []struct {
		at int64
		b  []byte
	}{{0, header}, {linkAt, link}, {fileSize - 4, []byte("tail")}} {
		if _, err := f.WriteAt(part.b, part.at); err != nil {
			t.Fatal(err)
		}
	}
	ctx, storage, err := beginWorkingStorage(WithWorkingStorage(t.Context(), WorkingStorageOptions{MemoryBytes: transferBufferSize, TemporaryDirectory: t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	var largest int
	source := codeSource{ctx, outputSource{reader: transferReaderFunc(func(p []byte, at int64) (int, error) { largest = max(largest, len(p)); return f.ReadAt(p, at) }), size: fileSize}}
	c, err := source.container()
	if err != nil {
		t.Fatal(err)
	}
	im := c.slices[0].image
	if im.data != nil || im.commandBytes <= maxFileSize || largest > 72 {
		t.Fatal("command-sized parser retention/read", len(im.data), largest)
	}
	if _, err := source.inspect(); err != nil {
		t.Fatal(err)
	}
	// Patching itself only reads fixed header and padding. Full hashing remains
	// covered by native large-source gates; no giant materialized test buffer.
	codeEnd := (fileSize + 15) &^ 15
	planned, err := signingCommandOutput(ctx, im, source.source, codeEnd, 16, codeEnd+16)
	if err != nil {
		t.Fatal(err)
	}
	if largest > 72 {
		t.Fatal("command-sized mutation read", largest)
	}
	view := codeSource{ctx, planned}
	signedContainer, err := view.container()
	if err != nil {
		t.Fatal(err)
	}
	removed, err := removeImageSource(ctx, signedContainer.slices[0].image, planned)
	if err != nil {
		t.Fatal(err)
	}
	if removed.size != codeEnd || largest > 72 {
		t.Fatal(removed.size, largest)
	}
	for _, part := range []struct {
		at   int64
		want []byte
	}{{0, header[:32]}, {linkAt, link}, {fileSize - 4, []byte("tail")}} {
		want := bytes.Clone(part.want)
		if part.at == linkAt {
			binary.LittleEndian.PutUint64(want[32:], 16384)
			binary.LittleEndian.PutUint64(want[48:], uint64(codeEnd-(commandsEnd+16)))
		}
		got := make([]byte, len(want))
		if _, err := removed.reader.ReadAt(got, part.at); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("restored range at%d differs: %x/%x: %v", part.at, got, want, err)
		}
	}
	// Existing native allocation ceiling remains separate from command parsing.
	oversized := source.source
	oversized.size = int64(math.MaxUint32) + 1
	if _, err := c.mutateSource(ctx, oversized, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	t.Logf("physical %d: command bytes=%d, largest request=%d", fileSize, im.commandBytes, largest)
}

func TestMachOCommandCountStreaming(t *testing.T) {
	const count = uint32(1 << 16)
	header := commandTestBytes()[:32]
	binary.LittleEndian.PutUint32(header[16:], count)
	binary.LittleEndian.PutUint32(header[20:], count*8)
	for _, mode := range []string{"complete", "last-malformed", "cancel-between-commands"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx, storage, err := beginWorkingStorage(WithWorkingStorage(ctx, WorkingStorageOptions{MemoryBytes: transferBufferSize}))
			if err != nil {
				t.Fatal(err)
			}
			defer storage.Close()
			var commandReads uint32
			source := codeSource{ctx, outputSource{size: 32 + int64(count)*8, reader: transferReaderFunc(func(p []byte, at int64) (int, error) {
				if at == 0 {
					return copy(p, header), nil
				}
				if len(p) != 8 || at != 32+int64(commandReads)*8 {
					t.Fatalf("command traversal read length%d offset%d after%d commands", len(p), at, commandReads)
				}
				commandReads++
				binary.LittleEndian.PutUint32(p, 0x7777)
				binary.LittleEndian.PutUint32(p[4:], 8)
				if mode == "last-malformed" && commandReads == count {
					binary.LittleEndian.PutUint32(p[4:], 4)
				}
				if mode == "cancel-between-commands" && commandReads == count/2 {
					cancel()
				}
				return len(p), nil
			})}}
			c, err := source.container()
			switch mode {
			case "complete":
				if err != nil || c.slices[0].image.commandCount != count || c.slices[0].image.data != nil || commandReads != count {
					t.Fatal(c, commandReads, err)
				}
			case "last-malformed":
				if !errors.Is(err, ErrFormat) || commandReads != count {
					t.Fatal(commandReads, err)
				}
			case "cancel-between-commands":
				if !errors.Is(err, context.Canceled) || commandReads != count/2 {
					t.Fatal(commandReads, err)
				}
			}
			if storage.stats.MemoryBytes != 0 || storage.stats.PeakMemoryBytes > transferBufferSize || storage.stats.SpillFiles != 0 {
				t.Fatal("parser retained scratch or spooled command table", storage.stats)
			}
		})
	}
}

func TestMachOCommandCountOverrun(t *testing.T) {
	data := commandTestBytes(commandTestField(0x7777, 16))
	binary.LittleEndian.PutUint32(data[16:], 2)
	_, err := parseImage(data)
	if err == nil || err.Error() != malformed("truncated load command").Error() {
		t.Fatal(err)
	}
}

func TestMachOCommandOffsetWrap(t *testing.T) {
	const commandBytes = uint32(math.MaxUint32 - 3)
	header := commandTestBytes()[:32]
	binary.LittleEndian.PutUint32(header[16:], 2)
	binary.LittleEndian.PutUint32(header[20:], commandBytes)
	unknown := commandTestField(0x7777, 8)
	binary.LittleEndian.PutUint32(unknown[4:], commandBytes-16)
	signature := commandTestField(0x1d, 16)
	binary.LittleEndian.PutUint32(signature[8:], 32)
	signatureAt := uint64(32) + uint64(commandBytes) - 16
	_, err := parseImageRange(uint64(32)+uint64(commandBytes)+64, func(at, n uint64) ([]byte, error) {
		switch at {
		case 0:
			return header[:n], nil
		case 32:
			return unknown[:n], nil
		case signatureAt:
			return signature[:n], nil
		case signatureAt + 8:
			return signature[8 : 8+n], nil
		default:
			t.Fatalf("unexpected command read offset%d length%d", at, n)
			return nil, io.ErrUnexpectedEOF
		}
	})
	if err == nil || err.Error() != malformed("code signature range").Error() {
		t.Fatal("command end narrowed to32bits", err)
	}
}
