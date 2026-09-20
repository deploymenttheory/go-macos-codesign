package codesign

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const maxNestedFiles = 64

// Only plain Mach-O children are supported in this phase. Dotted directories
// denote native bundle boundaries and must not be traversed as ordinary folders.
var nestedCodeRoots = []string{"MacOS", "Helpers", "Frameworks", "SharedFrameworks", "PlugIns", "Plug-ins", "XPCServices", "Library/Automator", "Library/Spotlight", "Library/LoginItems"}

func nestedCodePath(name string) (inside, container bool) {
	for _, root := range nestedCodeRoots {
		if name == root || strings.HasPrefix(root, name+"/") {
			return false, true
		}
		if strings.HasPrefix(name, root+"/") {
			return true, false
		}
	}
	return false, false
}

type nestedResource struct{ data []byte }
type bundleWrite struct {
	name string
	data []byte
}

func nestedSignature(data []byte) (*Report, int, error) {
	r, err := InspectBytes(data)
	if err != nil {
		return nil, 0, err
	}
	if !strings.HasPrefix(r.Format, "Mach-O ") {
		return nil, 0, unsupported("nested code must be Mach-O")
	}
	selected := 0
	for i, a := range r.Architectures {
		if a.Signature == nil {
			return nil, 0, ErrUnsigned
		}
		if len(a.Signature.Directories) != 1 || a.Signature.Directories[0].HashType != 2 {
			return nil, 0, unsupported("nested code requires one SHA-256 CodeDirectory per architecture")
		}
		if a.Name == "arm64" {
			selected = i
		}
	}
	return r, selected, nil
}

func nestedSeal(data []byte) (map[string]any, error) {
	r, selected, err := nestedSignature(data)
	if err != nil {
		return nil, err
	}
	sig := r.Architectures[selected].Signature
	n, err := designatedRequirement(sig)
	if err != nil {
		return nil, err
	}
	var requirement string
	if n != nil {
		requirement = n.text(3)
	} else {
		if sig.Directories[0].Flags&FlagAdhoc == 0 {
			return nil, unsupported("nested certificate signature without explicit designated requirement")
		}
		// Match the arm64 baseline, independent of the OS executing Go. Remaining
		// architecture hashes follow container order, just as the native oracle.
		order := []int{selected}
		for i := range r.Architectures {
			if i != selected {
				order = append(order, i)
			}
		}
		parts := make([]string, len(order))
		for i, index := range order {
			parts[i] = `cdhash H"` + r.Architectures[index].Signature.Directories[0].CDHash + `"`
		}
		requirement = strings.Join(parts, " or ")
	}
	if _, err := parseRequirement(requirement); err != nil {
		return nil, unsupported("nested designated requirement text: " + err.Error())
	}
	hash, _ := hex.DecodeString(sig.Directories[0].CDHash)
	return map[string]any{"cdhash": hash, "requirement": requirement}, nil
}

// Construct every child signature before modifying any file. The parent seal
// references these final bytes. The write phase can still fail partway through.
func prepareNested(ctx context.Context, files map[string]any, opts SignOptions) ([]bundleWrite, error) {
	names := []string{}
	for name, value := range files {
		if _, ok := value.(nestedResource); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var writes []bundleWrite
	var total int64
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		original := files[name].(nestedResource).data
		data := original
		if opts.Deep {
			r, err := InspectBytes(data)
			if err != nil {
				return nil, err
			}
			signed := true
			for _, a := range r.Architectures {
				signed = signed && a.Signature != nil && a.Signature.Directories[0].Flags&0x20000 == 0
			}
			if !signed || opts.Force {
				child := opts
				child.InfoPlist, child.Resources = nil, nil
				child.Force = true
				if child.Identifier == "" {
					child.Identifier, err = machoIdentifier(name, data, child.Identity == nil)
					if err != nil {
						return nil, err
					}
				}
				data, err = SignBytes(ctx, data, child)
				if err != nil {
					return nil, fmt.Errorf("nested %s: %w", name, err)
				}
				total += int64(len(data))
				if total > maxFileSize {
					return nil, unsupported("nested signature output exceeds 1 GiB")
				}
				writes = append(writes, bundleWrite{"Contents/" + name, data})
			}
		}
		if opts.DryRun {
			// Native dry runs construct a child signature, then seal the bytes
			// still on disk. An unsigned on-disk child therefore fails sealing.
			data = original
		}
		seal, err := nestedSeal(data)
		if err != nil {
			return nil, fmt.Errorf("nested %s: %w", name, err)
		}
		files[name] = seal
	}
	return writes, nil
}

func verifyNestedResource(ctx context.Context, name string, value any, resource nestedResource, opts VerifyOptions) error {
	seal, ok := value.(map[string]any)
	requirement, reqOK := seal["requirement"].(string)
	if !ok || !reqOK || requirement == "" || len(seal) > 2 {
		return invalid("nested resource seal: %s", name)
	}
	if hash, present := seal["cdhash"]; present {
		h, ok := hash.([]byte)
		if !ok || len(h) != 20 {
			return invalid("nested CDHash metadata: %s", name)
		}
	} else if len(seal) != 1 {
		return invalid("nested resource fields: %s", name)
	}
	if _, _, err := nestedSignature(resource.data); err != nil {
		return err
	}
	opts.InfoPlist, opts.Resources = nil, nil
	opts.Requirement = requirement
	opts.Architecture = "" // every child architecture must satisfy the parent seal
	opts.directoryOnly = !opts.Deep
	if _, err := VerifyBytes(ctx, resource.data, opts); err != nil {
		return fmt.Errorf("nested %s: %w", name, err)
	}
	return nil
}
