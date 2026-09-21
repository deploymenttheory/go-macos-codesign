package codesign

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const maxNestedFiles = 64

// Dotted directories denote native bundle boundaries and must not be traversed
// as ordinary folders. The scanner supports the documented app, plug-in, XPC
// and framework profiles.
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

type bundleWriteKind uint8

const (
	bundleMachOWrite bundleWriteKind = iota
	bundleResourceWrite
)

type bundleCleanup uint8

const (
	bundleCleanupNone bundleCleanup = iota
	bundleCleanupKeepResources
	bundleCleanupRemoveAll
)

type bundleWrite struct {
	name    string
	data    []byte
	bundle  *appBundle
	kind    bundleWriteKind
	cleanup bundleCleanup
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
		// Put arm64 first for consistent requirement text across hosts, then
		// preserve container order for the remaining architecture hashes.
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
	return prepareNestedAt(ctx, files, opts, "Contents/")
}

func prepareNestedAt(ctx context.Context, files map[string]any, opts SignOptions, base string) ([]bundleWrite, error) {
	names := []string{}
	for name, value := range files {
		switch value.(type) {
		case nestedResource, *nestedAppResource:
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
		var original []byte
		var app *nestedAppResource
		switch v := files[name].(type) {
		case nestedResource:
			original = v.data
		case *nestedAppResource:
			original, app = v.data, v
		}
		data := original
		var staged []bundleWrite
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
				if app != nil {
					data, staged, err = app.bundle.planSignature(ctx, data, app.files, app.files2, child, true)
				} else {
					child.Force = true
					if child.Identifier == "" {
						child.Identifier, err = machoIdentifier(name, data, child.Identity == nil)
						if err != nil {
							return nil, err
						}
					}
					data, err = SignBytes(ctx, data, child)
					staged = []bundleWrite{{name: base + name, data: data}}
				}
				if err != nil {
					return nil, fmt.Errorf("nested %s: %w", name, err)
				}
				for _, w := range staged {
					total += int64(len(w.data))
				}
				if total > maxFileSize {
					return nil, unsupported("nested signature output exceeds 1 GiB")
				}
				writes = append(writes, staged...)
			}
		}
		if opts.DryRun {
			// Dry runs seal on-disk bytes because no child signature is committed.
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

func nestedRequirement(name string, value any) (string, error) {
	seal, ok := value.(map[string]any)
	requirement, reqOK := seal["requirement"].(string)
	if !ok || !reqOK || requirement == "" || len(seal) > 2 {
		return "", invalid("nested resource seal: %s", name)
	}
	if hash, present := seal["cdhash"]; present {
		h, ok := hash.([]byte)
		if !ok || len(h) != 20 {
			return "", invalid("nested CDHash metadata: %s", name)
		}
	} else if len(seal) != 1 {
		return "", invalid("nested resource fields: %s", name)
	}
	return requirement, nil
}

func verifyNestedResource(ctx context.Context, name string, value any, resource nestedResource, opts VerifyOptions) error {
	requirement, err := nestedRequirement(name, value)
	if err != nil {
		return err
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
