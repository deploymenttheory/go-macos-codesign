package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

func Inspect(ctx context.Context, path string) (*Report, error) {
	return InspectWithOptions(ctx, path, PathOptions{})
}

// InspectWithOptions inspects a selected framework version without verifying it.
func InspectWithOptions(ctx context.Context, path string, opts PathOptions) (report *Report, err error) {
	ctx, storage, err := beginWorkingStorage(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, storage.Close()) }()
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
	r, err := withCodeSource(ctx, path, func(source codeSource, _ *os.File) (*Report, error) { return source.inspect() })
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
	return inspectContainer(c, ownedMemoryRange(data))
}

func inspectContainer(c *container, read rangeReader) (*Report, error) {
	r := &Report{Format: "Mach-O thin"}
	if c.fat {
		r.Format = "Mach-O universal"
	}
	for _, s := range c.slices {
		im := s.image
		a := Architecture{Name: archName(s.cpu, s.subtype), CPU: s.cpu, Subtype: s.subtype, Offset: s.offset, Size: s.size, SignatureOffset: uint64(im.sigOffset), SignatureSize: im.sigSize}
		a.VersionPlatform, a.VersionMin, a.VersionSDK = im.versionPlatform, im.versionMin, im.versionSDK
		if im.sigCommand >= 0 {
			var err error
			a.Signature, err = parseSignatureRange(uint64(im.sigSize), func(offset, length uint64) ([]byte, error) {
				return read(s.offset+uint64(im.sigOffset)+offset, length)
			}, false)
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
	info, err := sig.verifyCMS()
	if err != nil || info == nil {
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

func Verify(ctx context.Context, path string, opts VerifyOptions) (report *Report, err error) {
	ctx, storage, err := beginWorkingStorage(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, storage.Close())
		if err != nil && report != nil {
			report.Valid = false
		}
	}()
	if err := sidebandOptions(ctx, opts, false); err != nil {
		return nil, err
	}
	path, bundle, err := resolveCodePath(path)
	if err != nil {
		return nil, err
	}
	if bundle {
		return verifyBundle(ctx, path, opts)
	}
	if opts.AppleDoubleFiles != nil {
		return nil, unsupported("AppleDoubleFiles requires a bundle operand; use AppleDouble for a standalone file")
	}
	r, err := withCodeSource(ctx, path, func(source codeSource, f *os.File) (*Report, error) {
		opts.sidebandFile, opts.sidebandPath = f, path
		dmg, err := source.isDMG()
		if err != nil {
			return nil, err
		}
		return verifyInput(ctx, opts, dmg, source.inspect, source.digest, source.strict)
	})
	if r != nil {
		r.Path = path
	}
	return r, err
}

func VerifyBytes(ctx context.Context, data []byte, opts VerifyOptions) (report *Report, err error) {
	ctx, storage, err := beginWorkingStorage(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, storage.Close())
		if err != nil && report != nil {
			report.Valid = false
		}
	}()
	return verifyInput(ctx, opts, isDMG(data), func() (*Report, error) { return InspectBytes(data) },
		func(kind uint8, offset, length uint64) ([]byte, error) {
			return digestContext(ctx, kind, data[offset:offset+length])
		},
		func(architecture string, disabled bool) error {
			return verifyStrictLayout(data, architecture, disabled)
		})
}

func verifyInput(ctx context.Context, opts VerifyOptions, dmg bool, inspect func() (*Report, error), pageDigest func(uint8, uint64, uint64) ([]byte, error), strict func(string, bool) error) (report *Report, failure error) {
	var architecture string
	defer func() { failure = verificationArchitecture(failure, architecture) }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.AppleDoubleFiles != nil && opts.sidebandObject == nil {
		return nil, unsupported("AppleDoubleFiles requires a bundle filesystem scope; use Verify")
	}
	if err := sidebandOptions(ctx, opts, !dmg); err != nil {
		return nil, err
	}
	if opts.StrictSymlinks && !opts.NoStrict && !opts.IgnoreResources && opts.linkScope == nil && len(opts.Resources) > 0 {
		return nil, unsupported("strict resource links require a bundle filesystem scope")
	}
	r, err := inspect()
	if err != nil {
		return nil, err
	}
	r.ResourcesIgnored = opts.IgnoreResources
	if len(r.repSpecific) > 0 && (len(opts.InfoPlist) > 0 || len(opts.Resources) > 0) {
		return r, unsupported("external special-slot overrides for disk images")
	}
	found := false
	for _, a := range r.verificationArchitectures() {
		if opts.Architecture != "" && opts.Architecture != a.Name {
			continue
		}
		found = true
		architecture = a.Name
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if a.Signature == nil {
			return r, verificationFailure(ErrUnsigned.Error(), ErrUnsigned)
		}
		var signer []byte
		info, err := a.Signature.verifyCMS()
		if err != nil {
			return r, err
		}
		if info != nil {
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
				h, err := pageDigest(d.HashType, start, end-start)
				if err != nil {
					return r, err
				}
				p := uint64(d.HashOffset) + uint64(i)*uint64(d.HashSize)
				want, err := d.hashAt(p)
				if err != nil {
					return r, err
				}
				if !bytes.Equal(h, want) {
					return r, verificationFailure(signatureDiagnostic, invalid("%s: code page %d", a.Name, i))
				}
			}
			for slot := uint32(1); slot <= d.SpecialSlots; slot++ {
				// Apple's shallow validation skips the resource envelope, but
				// still binds Info.plist, requirements and other signed metadata.
				if (opts.directoryOnly || opts.IgnoreResources) && slot == SlotResources {
					continue
				}
				p := uint64(d.HashOffset) - uint64(slot)*uint64(d.HashSize)
				want, err := d.hashAt(p)
				if err != nil {
					return r, err
				}
				var payload []byte
				external := false
				if slot == SlotInfo {
					payload = opts.InfoPlist
					external = true
				}
				if slot == SlotResources {
					payload = opts.Resources
					external = true
				}
				if slot == SlotRepSpecific && len(r.repSpecific) > 0 {
					payload = r.repSpecific
					external = true
				}
				var h []byte
				present := len(payload) > 0
				if external {
					if present {
						h, err = digestContext(ctx, d.HashType, payload)
					}
				} else {
					h, present, err = a.Signature.componentDigest(ctx, slot, d.HashType)
				}
				if err != nil {
					return r, err
				}
				zero := bytes.Equal(want, make([]byte, d.HashSize))
				if !present {
					if zero {
						continue
					}
					if slot == SlotInfo || slot == SlotResources {
						return r, slotVerificationFailure(slot, unsupported(fmt.Sprintf("external data for special slot %d is required", slot)))
					}
					return r, slotVerificationFailure(slot, invalid("missing special slot %d", slot))
				}
				if !bytes.Equal(h, want) {
					return r, slotVerificationFailure(slot, invalid("special slot %d", slot))
				}
			}
			if len(signer) > 0 && d.Flags&FlagAdhoc != 0 {
				return r, invalid("ad-hoc CodeDirectory contains a certificate signature")
			}
			if len(signer) == 0 && d.Flags&FlagAdhoc == 0 {
				return r, invalid("missing certificate signature")
			}
			set, err := a.Signature.componentBytes(SlotRequirements)
			if err != nil {
				return r, err
			}
			if len(set) != 0 {
				if err := validateRequirements(set); err != nil {
					return r, err
				}
			}
		}
	}
	if !found {
		return r, verificationFailure("object file format unrecognized, invalid, or unsuitable", fmt.Errorf("architecture %q not present", opts.Architecture))
	}
	if opts.linkScope == nil {
		// DiskImageRep overrides SingleDiskRep strict validation and does not
		// apply its sideband restriction. Retain ordinary UDIF signature checks.
		if !dmg {
			if err := verifySideband(ctx, opts); err != nil {
				return r, err
			}
		}
		if err := strict(opts.Architecture, opts.NoStrict); err != nil {
			return r, err
		}
	}
	r.Valid = true
	r.verifiedArchitecture = opts.Architecture
	if opts.CheckDesignatedRequirement && !opts.directoryOnly {
		if err := r.CheckDesignatedRequirement(""); err != nil {
			r.Valid = false
			return r, err
		}
	}
	if opts.Requirement != "" {
		if err := r.CheckRequirement(opts.Requirement, ""); err != nil {
			r.Valid = false
			return r, err
		}
	}
	return r, nil
}
