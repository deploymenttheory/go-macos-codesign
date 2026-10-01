package codesign

import (
	"bytes"
	"cmp"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// Apple performs these layout checks after cryptographic/resource validation.
// They do not change the bytes covered by a signature or weaken parsing bounds.
func verifyStrictLayout(data []byte, architecture string, disabled bool) error {
	if isDMG(data) {
		return nil // the UDIF signing limit is already checked by VerifyBytes
	}
	c, err := parseContainer(data)
	if err != nil {
		return err
	}
	if architecture == "" && c.fat && (c.fat64 || c.order != be) {
		if disabled {
			return nil
		}
		return unsupported("strict validation of nonstandard universal headers")
	}
	failure := func(reason string) error {
		return &VerificationError{Diagnostic: "main executable failed strict validation", cause: invalid("strict Mach-O layout: %s", reason), omitArchitecture: true}
	}
	if c.fat && architecture == "" {
		ordered := slices.Clone(c.slices)
		slices.SortFunc(ordered, func(a, b slice) int { return cmp.Compare(a.offset, b.offset) })
		end := uint64(8 + 20*len(ordered))
		if len(ordered) > 100 {
			return unsupported("native universal architecture limit")
		}
		for i, s := range ordered {
			bad := i > 0 && s.offset-end >= uint64(1)<<s.alignment
			for _, b := range data[end:s.offset] {
				if b != 0 {
					bad = true
					break
				}
			}
			if bad {
				// Apple's Universal constructor stops populating its slice-size
				// map at the first suspicious gap. Subsequent all-architecture
				// traversal fails even when strict policy was disabled.
				if i < len(ordered)-1 {
					return &VerificationError{Diagnostic: "An internal error has occurred.", cause: invalid("incomplete native universal size index"), omitArchitecture: true}
				}
				if !disabled {
					return failure("invalid universal padding")
				}
			}
			end = s.offset + s.size
		}
		if !disabled && end != uint64(len(data)) {
			return failure("trailing universal data")
		}
	}
	if disabled {
		return nil
	}
	for _, s := range c.slices {
		if architecture != "" && archName(s.cpu, s.subtype) != architecture {
			continue
		}
		im := s.image
		valid := false
		for _, cmd := range im.commands {
			p := cmd.offset
			switch cmd.kind {
			case 1, 0x19:
				if !bytes.Equal(bytes.TrimRight(im.data[p+8:p+24], "\x00"), []byte("__LINKEDIT")) {
					continue
				}
				var offset, size uint64
				if cmd.kind == 1 {
					offset, size = uint64(im.order.Uint32(im.data[p+32:])), uint64(im.order.Uint32(im.data[p+36:]))
				} else {
					offset, size = im.order.Uint64(im.data[p+40:]), im.order.Uint64(im.data[p+48:])
				}
				valid = offset <= uint64(len(im.data)) && size == uint64(len(im.data))-offset
			case 2: // LC_SYMTAB, the legacy PPC fallback precedes later commands
				if cmd.size >= 24 {
					valid = uint64(im.order.Uint32(im.data[p+16:]))+uint64(im.order.Uint32(im.data[p+20:])) == uint64(len(im.data))
				}
			default:
				continue
			}
			break
		}
		if !valid {
			return failure("link-edit data does not end at the image boundary")
		}
	}
	return nil
}

type verificationLinkScope struct {
	bundle *appBundle
	base   string // physical resource base, distinct from diagnostic aliases
	outer  *verificationLinkScope
}

func (s *verificationLinkScope) includes(name string) bool {
	name = filepath.ToSlash(name)
	first, _, _ := strings.Cut(name, "/")
	if first == "_CodeSignature" || first == "CodeResources" || first == "_MASReceipt" {
		return false
	}
	if name == strings.TrimPrefix(s.bundle.executable, s.bundle.base) {
		return true // Apple's main-executable exclusion is a soft symlink target
	}
	include, _ := resourcePolicy(name, false)
	return include
}

func verifyStrictLink(name, target string, opts VerifyOptions) error {
	scope := opts.linkScope
	if scope == nil {
		return unsupported("strict resource links require a bundle filesystem scope")
	}
	full := filepath.FromSlash(target)
	absolute := filepath.IsAbs(full) || strings.HasPrefix(target, "/")
	if !absolute {
		// Do not Clean/Join target text: link/.. resolves the physical parent.
		base := opts.resourceBase
		if base == "" {
			base = scope.base
		}
		full = filepath.Dir(filepath.Join(base, name)) + string(filepath.Separator) + full
	}
	resolved, err := resolveStrictLink(full)
	if err == nil {
		if absolute {
			resolved = filepath.ToSlash(resolved)
			if strings.HasPrefix(resolved, "/System/") || strings.HasPrefix(resolved, "/Library/") {
				return nil
			}
		} else {
			for current := scope; current != nil; current = current.outer {
				rel, relErr := filepath.Rel(current.base, resolved)
				if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					continue
				}
				if rel == "." {
					return nil
				}
				if current.includes(rel) {
					return nil
				}
				break // excluded in the nearest matching scope; do not try an ancestor
			}
		}
	}
	return &VerificationError{Diagnostic: "invalid destination for symbolic link in bundle", cause: invalid("strict symlink destination: %s", name), ModifiedResources: []string{filepath.Join(opts.resourceBase, name)}, resourceFailure: true}
}

// Native realpath permits 33 followed links in the target text (the sealed
// link itself is not followed). filepath.EvalSymlinks permits 255 instead.
// Resolve one component at a time so that symlink/.. uses the physical parent.
// This is host filesystem policy, not an APFS/HFS image traversal implementation.
func resolveStrictLink(name string) (string, error) {
	return resolveMetadataLink(name, 33, false)
}

// The open(2) sideband path has a 32-link kernel budget, distinct from
// realpath's 33-link strict destination policy. Resolve explicitly on every
// host so Linux and Windows do not inherit their different native budgets.
func resolveMetadataLink(name string, limit int, opening bool) (string, error) {
	volume := filepath.VolumeName(name)
	current := volume + string(filepath.Separator)
	pending := strings.TrimLeft(name[len(volume):], string(filepath.Separator))
	links := 0
	for pending != "" {
		part, rest, separator := strings.Cut(pending, string(filepath.Separator))
		pending = rest
		switch part {
		case "", ".":
			continue
		case "..":
			current = filepath.Dir(current)
			continue
		}
		candidate := filepath.Join(current, part)
		info, err := os.Lstat(candidate)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > limit {
				return "", syscall.ELOOP
			}
			target, err := os.Readlink(candidate)
			if err != nil {
				return "", err
			}
			target = filepath.FromSlash(target)
			if filepath.IsAbs(target) {
				volume = filepath.VolumeName(target)
				current = volume + string(filepath.Separator)
				target = target[len(volume):]
			}
			pending = target
			if rest != "" {
				pending += string(filepath.Separator) + rest
			}
			continue
		}
		if (rest != "" || opening && separator) && !info.IsDir() {
			return "", syscall.ENOTDIR
		}
		current = candidate
	}
	return current, nil
}
