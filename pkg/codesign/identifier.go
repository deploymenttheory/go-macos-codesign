package codesign

import (
	"crypto/sha1"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// canonicalIdentifier follows DiskRep's filename/version heuristic.
func canonicalIdentifier(path string) string {
	name := filepath.Base(path)
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 && dot+1 < len(name) && !strings.ContainsRune("0123456789", rune(name[dot+1])) {
		name = name[:dot]
	}
	if name != "" && !strings.ContainsRune("0123456789.", rune(name[0])) {
		p := len(name)
		for p > 0 && strings.ContainsRune("0123456789.", rune(name[p-1])) {
			p--
		}
		if p < len(name) && name[p] == '.' {
			p++
		}
		for p < len(name) && strings.ContainsRune("0123456789", rune(name[p])) {
			p++
		}
		name = name[:p]
	}
	return name
}

func machoIdentifier(path string, data []byte, adhoc bool) (string, error) {
	c, err := parseContainer(data)
	if err != nil {
		return "", err
	}
	return c.identifier(path, adhoc)
}

func (c *container) identifier(path string, adhoc bool) (string, error) {
	name := canonicalIdentifier(path)
	if !adhoc || strings.Contains(name, ".") {
		return name, nil
	}
	// Match the arm64 native baseline on all platforms. Apple's selection is
	// host-dependent for a universal binary; our selection is deterministic.
	im := c.slices[0].image
	for _, s := range c.slices {
		if archName(s.cpu, s.subtype) == "arm64" {
			im = s.image
		}
	}
	if im.uuidOffset >= 0 {
		if im.uuidSize != 24 {
			return "", malformed("UUID command size")
		}
		return name + "-55554944" + hex.EncodeToString(im.uuid[:]), nil
	}
	// Native fallback hashes mach_header (28 bytes, even for 64-bit images)
	// followed by the load commands. This is identification, not trust.
	h := sha1.New()
	_, _ = h.Write(im.headerBytes[:28])
	commands := outputSource{im.source.source.reader, im.source.source.offset + int64(im.header), int64(im.commandBytes)}
	if err := transferOutput(im.source.ctx, hashOutput{h}, commands); err != nil {
		return "", err
	}
	return name + "-" + hex.EncodeToString(h.Sum(nil)), nil
}
