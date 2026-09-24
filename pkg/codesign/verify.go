package codesign

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

func Inspect(ctx context.Context, path string) (*Report, error) {
	return InspectWithOptions(ctx, path, PathOptions{})
}

// InspectWithOptions inspects a selected framework version without verifying it.
func InspectWithOptions(ctx context.Context, path string, opts PathOptions) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, bundle, err := resolveCodePath(path)
	if err != nil {
		return nil, err
	}
	if bundle {
		return inspectBundle(ctx, path, opts)
	}
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	r, err := InspectBytes(data)
	if r != nil {
		r.Path = path
	}
	return r, err
}

func InspectBytes(data []byte) (*Report, error) {
	if isDMG(data) {
		return inspectDMG(data)
	}
	c, err := parseContainer(data)
	if err != nil {
		return nil, err
	}
	r := &Report{Format: "Mach-O thin"}
	if c.fat {
		r.Format = "Mach-O universal"
	}
	for _, s := range c.slices {
		im := s.image
		a := Architecture{Name: archName(s.cpu, s.subtype), CPU: s.cpu, Subtype: s.subtype, Offset: s.offset, Size: s.size, SignatureOffset: uint64(im.sigOffset), SignatureSize: im.sigSize}
		for _, cmd := range im.commands {
			if cmd.kind == 0x32 && cmd.size >= 24 {
				a.VersionPlatform = im.order.Uint32(im.data[cmd.offset+8:])
				a.VersionMin = im.order.Uint32(im.data[cmd.offset+12:])
				a.VersionSDK = im.order.Uint32(im.data[cmd.offset+16:])
			}
		}
		if im.sigCommand >= 0 {
			a.Signature, err = ParseSignature(im.data[im.sigOffset : uint64(im.sigOffset)+uint64(im.sigSize)])
			if err != nil {
				return nil, err
			}
			// Inspection remains possible when a CMS is damaged or unsupported.
			// Metadata is included only when its binding can be verified.
			a.Signature.CertificateMetadata, _ = InspectCertificateMetadata(a.Signature)
		}
		r.Architectures = append(r.Architectures, a)
	}
	return r, nil
}

// InspectCertificateMetadata verifies the CMS binding and orders authorities by
// certificate signatures. It does not validate trust or certificate expiration.
func InspectCertificateMetadata(sig *Signature) (*CertificateMetadata, error) {
	if sig == nil {
		return nil, ErrUnsigned
	}
	cms := sig.find(SlotCMS)
	if len(cms) <= 8 {
		return nil, nil
	}
	dirs := [][]byte{sig.find(SlotDirectory)}
	for slot := uint32(0x1000); slot < 0x1005; slot++ {
		if cd := sig.find(slot); cd != nil {
			dirs = append(dirs, cd)
		}
	}
	info, err := VerifyCMS(cms[8:], dirs)
	if err != nil {
		return nil, err
	}
	path, err := linkedCertificates(info.SignerCertificate, info.Certificates)
	if err != nil {
		return nil, err
	}
	chain, err := describeChain(path)
	if err != nil {
		return nil, err
	}
	return &CertificateMetadata{Authorities: chain.Authorities, Certificates: chain.Certificates, SigningTime: info.SigningTime, Timestamp: info.Timestamp}, nil
}

func Verify(ctx context.Context, path string, opts VerifyOptions) (*Report, error) {
	path, bundle, err := resolveCodePath(path)
	if err != nil {
		return nil, err
	}
	if bundle {
		return verifyBundle(ctx, path, opts)
	}
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	r, err := VerifyBytes(ctx, data, opts)
	if r != nil {
		r.Path = path
	}
	return r, err
}

func VerifyBytes(ctx context.Context, data []byte, opts VerifyOptions) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := InspectBytes(data)
	if err != nil {
		return nil, err
	}
	if len(r.repSpecific) > 0 && (len(opts.InfoPlist) > 0 || len(opts.Resources) > 0) {
		return r, unsupported("external special-slot overrides for disk images")
	}
	found := false
	for _, a := range r.Architectures {
		if opts.Architecture != "" && opts.Architecture != a.Name {
			continue
		}
		found = true
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if a.Signature == nil {
			return r, ErrUnsigned
		}
		var signer []byte
		cms := a.Signature.find(SlotCMS)
		if len(cms) > 8 {
			var directories [][]byte
			// The primary is defined by its slot, not by index-table order.
			directories = append(directories, a.Signature.find(SlotDirectory))
			for slot := uint32(0x1000); slot < 0x1005; slot++ {
				if cd := a.Signature.find(slot); cd != nil {
					directories = append(directories, cd)
				}
			}
			info, err := VerifyCMS(cms[8:], directories)
			if err != nil {
				return r, err
			}
			signer = info.SignerCertificate
			trusted := false
			for _, pin := range opts.TrustedCertificates {
				trusted = trusted || bytes.Equal(pin, signer)
			}
			cert, _ := parseCertificate(signer) // VerifyCMS already parsed it.
			at := opts.CurrentTime
			if at.IsZero() {
				at = time.Now()
			}
			if info.Timestamp != nil {
				if err := verifyTimestampTrust(info.Timestamp, opts.TimestampRoots, at); err != nil {
					return r, err
				}
				at = info.Timestamp.Time
				if a.Signature.CertificateMetadata != nil {
					a.Signature.CertificateMetadata.Timestamp = info.Timestamp
				}
			}
			if err := checkCertificatePurpose(cert, at); err != nil {
				return r, err
			}
			if !trusted {
				chain, err := VerifyCertificateChain(signer, info.Certificates, opts.TrustedRoots, at)
				if err != nil {
					return r, err
				}
				info.Certificates = chain.Certificates
			}
			path, err := linkedCertificates(signer, info.Certificates)
			if err != nil {
				return r, err
			}
			if info.Timestamp != nil {
				if err := checkTimestampApplePolicy(path, info.Timestamp); err != nil {
					return r, err
				}
			}
			for i := range a.Signature.Directories {
				a.Signature.Directories[i].chain = path
				if err := checkTeamID(path, a.Signature.Directories[i].TeamID); err != nil {
					return r, err
				}
			}
		}
		for _, d := range a.Signature.Directories {
			d.certificate = signer
			if len(r.repSpecific) > 0 && d.SpecialSlots < SlotRepSpecific {
				return r, invalid("disk image signature lacks trailer binding")
			}
			if d.CodeLimit != a.SignatureOffset {
				return r, invalid("code limit does not cover complete image")
			}
			page := uint64(1) << d.PageExponent
			if d.PageExponent == 0 {
				page = d.CodeLimit
			}
			if page == 0 {
				return r, invalid("empty code limit")
			}
			expected := (d.CodeLimit + page - 1) / page
			if uint64(d.CodeSlots) != expected {
				return r, invalid("code slot count")
			}
			for i := uint32(0); !opts.directoryOnly && i < d.CodeSlots; i++ {
				start := a.Offset + uint64(i)*page
				end := min(start+page, a.Offset+d.CodeLimit)
				h, _ := digest(d.HashType, data[start:end])
				p := uint64(d.HashOffset) + uint64(i)*uint64(d.HashSize)
				if !bytes.Equal(h, d.Raw[p:p+uint64(d.HashSize)]) {
					return r, invalid("%s: code page %d", a.Name, i)
				}
			}
			for slot := uint32(1); slot <= d.SpecialSlots; slot++ {
				// Apple's shallow validation skips the resource envelope, but
				// still binds Info.plist, requirements and other signed metadata.
				if opts.directoryOnly && slot == SlotResources {
					continue
				}
				p := uint64(d.HashOffset) - uint64(slot)*uint64(d.HashSize)
				want := d.Raw[p : p+uint64(d.HashSize)]
				payload := a.Signature.find(slot)
				if slot == SlotInfo {
					payload = opts.InfoPlist
				}
				if slot == SlotResources {
					payload = opts.Resources
				}
				if slot == SlotRepSpecific && len(r.repSpecific) > 0 {
					payload = r.repSpecific
				}
				zero := bytes.Equal(want, make([]byte, d.HashSize))
				if len(payload) == 0 {
					if zero {
						continue
					}
					if slot == SlotInfo || slot == SlotResources {
						return r, unsupported(fmt.Sprintf("external data for special slot %d is required", slot))
					}
					return r, invalid("missing special slot %d", slot)
				}
				h, _ := digest(d.HashType, payload)
				if !bytes.Equal(h, want) {
					return r, invalid("special slot %d", slot)
				}
			}
			if len(signer) > 0 && d.Flags&FlagAdhoc != 0 {
				return r, invalid("ad-hoc CodeDirectory contains a certificate signature")
			}
			if len(signer) == 0 && d.Flags&FlagAdhoc == 0 {
				return r, invalid("missing certificate signature")
			}
			if !opts.directoryOnly {
				if err := checkDesignatedRequirement(a.Signature.find(SlotRequirements), d); err != nil {
					return r, err
				}
			}
			if opts.Requirement != "" {
				ok, err := EvaluateRequirement(opts.Requirement, d)
				if err != nil {
					return r, err
				}
				if !ok {
					return r, ErrRequirement
				}
			}
		}
	}
	if !found {
		return r, fmt.Errorf("architecture %q not present", opts.Architecture)
	}
	r.Valid = true
	return r, nil
}
