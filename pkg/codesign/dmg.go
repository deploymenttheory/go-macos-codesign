package codesign

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// The format model is owned by go-apfs-v2. This adapter handles only code
// signatures; it neither decompresses nor reconstructs the image payload.
var dmgFooterSize = binary.Size(disk.DMGFooter{})

type dmgImage struct {
	footer     disk.DMGFooter
	content    []byte
	signature  *Signature
	signed     bool
	priorFlags uint32
}

func isDMG(data []byte) bool {
	if len(data) < dmgFooterSize {
		return false
	}
	// Apple's DiskRep::bestGuess tries Mach-O before a trailing UDIF marker.
	// A crafted trailer must not change how an executable is interpreted.
	switch be.Uint32(data) {
	case 0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca:
		return false
	}
	return string(data[len(data)-dmgFooterSize:][:4]) == "koly"
}

func parseDMG(data []byte) (*dmgImage, error) {
	if len(data) < dmgFooterSize+8 || len(data) > maxFileSize || !isDMG(data) {
		return nil, malformed("UDIF image size or trailer")
	}
	m, err := parseDMGRange(uint64(len(data)), data[len(data)-dmgFooterSize:], ownedMemoryRange(data))
	if err == nil {
		m.content = data[:m.footer.CodeSignatureOffset]
	}
	return m, err
}

type dmgSignatureState struct {
	length uint32
	signed bool
	flags  uint32
}

func parseDMGRange(length uint64, trailer []byte, read rangeReader) (*dmgImage, error) {
	var signature *Signature
	m, err := parseDMGStructure(length, trailer, func(offset, length uint64) (dmgSignatureState, error) {
		var err error
		signature, err = parseSignatureRange(length, func(at, n uint64) ([]byte, error) { return read(offset+at, n) }, true)
		if err != nil {
			return dmgSignatureState{}, err
		}
		state := dmgSignatureState{length: signature.Length, signed: len(signature.Directories) != 0}
		if state.signed {
			state.flags = signature.Directories[0].Flags
		}
		return state, nil
	})
	if err == nil && m.signed {
		m.signature = signature
	}
	return m, err
}

func parseDMGStructure(length uint64, trailer []byte, parse func(uint64, uint64) (dmgSignatureState, error)) (*dmgImage, error) {
	if length < uint64(dmgFooterSize+8) {
		return nil, malformed("UDIF image size or trailer")
	}
	m := &dmgImage{}
	_ = binary.Read(bytes.NewReader(trailer), be, &m.footer)
	h := &m.footer
	if h.Version != 4 || h.HeaderSize != uint32(dmgFooterSize) || h.Flags != 1 || h.SegmentNumber != 1 || h.SegmentCount != 1 || h.RunningDataForkOffset != 0 {
		return nil, unsupported("UDIF version, flags or segmented image")
	}
	end := length - uint64(dmgFooterSize)
	if h.CodeSignatureOffset == 0 {
		if h.CodeSignatureLength != 0 {
			return nil, malformed("UDIF signature length without offset")
		}
	} else {
		if h.CodeSignatureOffset < 8 || !rangeOK(h.CodeSignatureOffset, h.CodeSignatureLength, end) || h.CodeSignatureLength == 0 || h.CodeSignatureOffset+h.CodeSignatureLength != end {
			return nil, malformed("UDIF signature bounds")
		}
		state, err := parse(h.CodeSignatureOffset, end-h.CodeSignatureOffset)
		if err != nil {
			return nil, err
		}
		if uint64(state.length) != h.CodeSignatureLength {
			return nil, malformed("UDIF signature padding")
		}
		// Native dry-run components without a directory remain unsigned.
		m.signed, m.priorFlags = state.signed, state.flags
		end = h.CodeSignatureOffset
	}
	regions := [][2]uint64{{h.DataForkOffset, h.DataForkLength}, {h.RsrcForkOffset, h.RsrcForkLength}, {h.PlistOffset, h.PlistLength}}
	for i, r := range regions {
		if !rangeOK(r[0], r[1], end) {
			return nil, malformed("UDIF data range")
		}
		for _, prior := range regions[:i] {
			if r[1] > 0 && prior[1] > 0 && r[0] < prior[0]+prior[1] && prior[0] < r[0]+r[1] {
				return nil, malformed("overlapping UDIF data ranges")
			}
		}
	}
	if h.PlistLength == 0 {
		return nil, unsupported("UDIF image without a resource plist")
	}
	// Apple binds the trailer with the signature length blinded, and with the
	// future signature offset already set when the source image is unsigned.
	h.CodeSignatureOffset, h.CodeSignatureLength = end, 0
	return m, nil
}

func (m *dmgImage) trailer() []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, be, &m.footer)
	return out.Bytes()
}

func inspectDMG(data []byte) (*Report, error) {
	m, err := parseDMG(data)
	if err != nil {
		return nil, err
	}
	return inspectDMGImage(m, uint64(len(data))), nil
}

func inspectDMGImage(m *dmgImage, length uint64) *Report {
	a := Architecture{Name: "dmg", Size: length, SignatureOffset: m.footer.CodeSignatureOffset, Signature: m.signature}
	if a.Signature != nil {
		a.SignatureSize = a.Signature.Length
		a.Signature.CertificateMetadata, _ = InspectCertificateMetadata(a.Signature)
	}
	return &Report{Format: "disk image", Architectures: []Architecture{a}, repSpecific: m.trailer()}
}

func dmgIdentifier(path string, data []byte, adhoc bool) (string, error) {
	m, err := parseDMG(data)
	if err != nil {
		return "", err
	}
	return m.identifier(path, adhoc), nil
}

func (m *dmgImage) identifier(path string, adhoc bool) string {
	name := canonicalIdentifier(path)
	if adhoc && !strings.Contains(name, ".") {
		sum := sha1.Sum(m.trailer()) // Native identifier suffix, not signature trust.
		name += "-" + hex.EncodeToString(sum[:])
	}
	return name
}

func signDMG(ctx context.Context, data []byte, opts SignOptions, dryRun bool) ([]byte, error) {
	if len(opts.InfoPlist) > 0 || len(opts.Resources) > 0 {
		return nil, unsupported("external special-slot overrides for disk images")
	}
	m, err := parseDMG(data)
	if err != nil {
		return nil, err
	}
	tail, err := signDMGTail(ctx, m, opts, dryRun, func(kind uint8, offset, length uint64) ([]byte, error) {
		return digestContext(ctx, kind, m.content[offset:offset+length])
	})
	if err != nil {
		return nil, err
	}
	if len(m.content) > maxFileSize-len(tail) {
		return nil, unsupported("signed disk image exceeds memory limit")
	}
	out := make([]byte, 0, len(m.content)+len(tail))
	out = append(out, m.content...)
	return append(out, tail...), nil
}

// signDMGTail shares byte and held-source signing policy. Only signature metadata
// is materialized; the immutable payload is supplied through bounded range hashes.
func signDMGTail(ctx context.Context, m *dmgImage, opts SignOptions, dryRun bool, pageDigest func(uint8, uint64, uint64) ([]byte, error)) ([]byte, error) {
	tail, err := signDMGTailSource(ctx, m, opts, dryRun, pageDigest)
	if err != nil {
		return nil, err
	}
	return materializeOutput(ctx, tail)
}

func signDMGTailSource(ctx context.Context, m *dmgImage, opts SignOptions, dryRun bool, pageDigest func(uint8, uint64, uint64) ([]byte, error)) (outputSource, error) {
	if len(opts.InfoPlist) > 0 || len(opts.Resources) > 0 {
		return outputSource{}, unsupported("external special-slot overrides for disk images")
	}
	if (m.signature != nil || m.signed) && !opts.Force {
		return outputSource{}, ErrSigned
	}
	if dryRun && opts.Identity != nil {
		// The reference crashes before writing when it attempts CMS over the absent
		// dry-run CodeDirectory. Keep a bounded error instead of emulating that bug.
		return outputSource{}, unsupported("certificate-signed DMG dry run")
	}
	page := uint64(opts.PageSize)
	if page != 0 && (page < 2 || page&(page-1) != 0 || page > maxFileSize) {
		return outputSource{}, fmt.Errorf("disk image page size must be zero or a power of two from 2 to 1 GiB")
	}
	length := m.footer.CodeSignatureOffset
	nPages := uint64(1)
	if page > 0 {
		nPages = (length-1)/page + 1
	} else {
		page = length
	}
	if nPages > math.MaxUint32 {
		return outputSource{}, unsupported("disk image code slot count")
	}
	reqs := opts.Requirements
	if len(reqs) == 0 {
		reqs = superblob(MagicRequirements, nil)
	}
	blobs := []Blob{{Slot: SlotRequirements, Data: reqs}}
	special := 6
	var execFlags uint64
	if len(opts.Entitlements) > 0 && opts.ForceLibraryEntitlements {
		xml, der, err := EncodeEntitlements(opts.Entitlements)
		if err != nil {
			return outputSource{}, err
		}
		blobs = append(blobs, Blob{Slot: SlotEntitlements, Data: blob(MagicEntitlements, xml)}, Blob{Slot: SlotDEREntitlements, Data: blob(MagicDEREntitlements, der)})
		special = 7
		execFlags = entitlementExecFlags(xml)
	}
	header, version := 48, uint32(0x20100)
	teamSize := 0
	if opts.teamID != "" {
		header, version, teamSize = 52, 0x20200, len(opts.teamID)+1
	}
	if length > math.MaxUint32 {
		header, version = 64, 0x20300
	}
	if opts.Flags&FlagRuntime != 0 && opts.RuntimeVersion != 0 {
		header, version = 96, 0x20500
	}
	hashOff := header + len(opts.Identifier) + 1 + teamSize + special*32
	cdSize := uint64(hashOff) + nPages*32
	if cdSize > math.MaxUint32 {
		return outputSource{}, unsupported("disk image CodeDirectory exceeds 32-bit length")
	}
	cd := make([]byte, header)
	section, err := newWorkingSection(ctx, int64(cdSize))
	if err != nil {
		return outputSource{}, err
	}
	be.PutUint32(cd, MagicDirectory)
	be.PutUint32(cd[4:], uint32(cdSize))
	be.PutUint32(cd[8:], version)
	flags := opts.Flags
	if opts.Identity == nil {
		flags |= FlagAdhoc
	}
	be.PutUint32(cd[12:], flags)
	be.PutUint32(cd[16:], uint32(hashOff))
	be.PutUint32(cd[20:], uint32(header))
	be.PutUint32(cd[24:], uint32(special))
	be.PutUint32(cd[28:], uint32(nPages))
	be.PutUint32(cd[32:], uint32(min(length, math.MaxUint32)))
	if length > math.MaxUint32 {
		be.PutUint64(cd[56:], length)
	}
	cd[36], cd[37] = 32, 2
	if opts.PageSize != 0 {
		cd[39] = byte(bits.TrailingZeros32(opts.PageSize))
	}
	if header >= 96 {
		be.PutUint64(cd[80:], execFlags)
		be.PutUint32(cd[88:], opts.RuntimeVersion)
	}
	if teamSize > 0 {
		offset := header + len(opts.Identifier) + 1
		be.PutUint32(cd[48:], uint32(offset))
	}
	if err := writeDirectoryPrefix(ctx, section, cd, opts.Identifier, opts.teamID); err != nil {
		return outputSource{}, err
	}
	for _, b := range append(blobs, Blob{Slot: SlotRepSpecific, Data: m.trailer()}) {
		h, err := digestContext(ctx, 2, b.Data)
		if err != nil {
			return outputSource{}, err
		}
		if _, err := section.WriteAt(h, int64(hashOff)-int64(b.Slot)*32); err != nil {
			return outputSource{}, err
		}
	}
	for i := uint64(0); i < nPages; i++ {
		h, err := pageDigest(2, i*page, min(page, length-i*page))
		if err != nil {
			return outputSource{}, err
		}
		if _, err := section.WriteAt(h, int64(hashOff)+int64(i)*32); err != nil {
			return outputSource{}, err
		}
	}
	var cms []byte
	if opts.Identity != nil {
		cms, err = signGeneratedCMS(ctx, opts.Identity, section.output(), opts.SigningTime, opts.Timestamp)
		if err != nil {
			return outputSource{}, err
		}
	}
	var sections []signatureSection
	if !dryRun {
		sections = append(sections, signatureSection{SlotDirectory, section.output()})
	}
	blobs = append(blobs, Blob{Slot: SlotCMS, Data: blob(MagicCMS, cms)})
	for _, b := range blobs {
		sections = append(sections, signatureSection{b.Slot, byteOutput(b.Data)})
	}
	sig, err := superblobOutput(MagicSignature, sections)
	if err != nil {
		return outputSource{}, err
	}
	if err := ctx.Err(); err != nil {
		return outputSource{}, err
	}
	m.footer.CodeSignatureLength = uint64(sig.size)
	plan := new(outputPlan)
	if err := plan.append(sig); err != nil {
		return outputSource{}, err
	}
	if err := plan.append(byteOutput(m.trailer())); err != nil {
		return outputSource{}, err
	}
	return plan.output(), nil
}
