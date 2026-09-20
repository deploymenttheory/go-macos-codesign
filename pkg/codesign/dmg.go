package codesign

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// The format model is owned by go-apfs-v2. This adapter handles only code
// signatures; it neither decompresses nor reconstructs the image payload.
var dmgFooterSize = binary.Size(disk.DMGFooter{})

type dmgImage struct {
	footer    disk.DMGFooter
	content   []byte
	signature *Signature
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
	m := &dmgImage{}
	_ = binary.Read(bytes.NewReader(data[len(data)-dmgFooterSize:]), be, &m.footer)
	h := &m.footer
	if h.Version != 4 || h.HeaderSize != uint32(dmgFooterSize) || h.Flags != 1 || h.SegmentNumber != 1 || h.SegmentCount != 1 || h.RunningDataForkOffset != 0 {
		return nil, unsupported("UDIF version, flags or segmented image")
	}
	end := uint64(len(data) - dmgFooterSize)
	if h.CodeSignatureOffset == 0 {
		if h.CodeSignatureLength != 0 {
			return nil, malformed("UDIF signature length without offset")
		}
	} else {
		if h.CodeSignatureOffset < 8 || !rangeOK(h.CodeSignatureOffset, h.CodeSignatureLength, end) || h.CodeSignatureLength == 0 || h.CodeSignatureOffset+h.CodeSignatureLength != end {
			return nil, malformed("UDIF signature bounds")
		}
		var err error
		m.signature, err = ParseSignature(data[h.CodeSignatureOffset:end])
		if err != nil {
			return nil, err
		}
		if uint64(m.signature.Length) != h.CodeSignatureLength {
			return nil, malformed("UDIF signature padding")
		}
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
	m.content = data[:end]
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
	a := Architecture{Name: "dmg", Size: uint64(len(data)), SignatureOffset: uint64(len(m.content)), Signature: m.signature}
	if a.Signature != nil {
		a.SignatureSize = a.Signature.Length
		a.Signature.CertificateMetadata, _ = InspectCertificateMetadata(a.Signature)
	}
	return &Report{Format: "disk image", Architectures: []Architecture{a}, repSpecific: m.trailer()}, nil
}

func dmgIdentifier(path string, data []byte, adhoc bool) (string, error) {
	m, err := parseDMG(data)
	if err != nil {
		return "", err
	}
	name := canonicalIdentifier(path)
	if adhoc && !strings.Contains(name, ".") {
		sum := sha1.Sum(m.trailer()) // Native identifier suffix, not signature trust.
		name += "-" + hex.EncodeToString(sum[:])
	}
	return name, nil
}

func signDMG(ctx context.Context, data []byte, opts SignOptions) ([]byte, error) {
	if len(opts.InfoPlist) > 0 || len(opts.Resources) > 0 {
		return nil, unsupported("external special-slot overrides for disk images")
	}
	m, err := parseDMG(data)
	if err != nil {
		return nil, err
	}
	if m.signature != nil && !opts.Force {
		return nil, ErrSigned
	}
	page := int(opts.PageSize)
	if page != 0 && (page < 2 || page&(page-1) != 0 || page > maxFileSize) {
		return nil, fmt.Errorf("disk image page size must be zero or a power of two from 2 to 1 GiB")
	}
	nPages := 1
	if page > 0 {
		nPages = (len(m.content) + page - 1) / page
	} else {
		page = len(m.content)
	}
	reqs := opts.Requirements
	if len(reqs) == 0 {
		reqs = superblob(MagicRequirements, nil)
	} else if err := validateRequirements(reqs); err != nil {
		return nil, err
	}
	blobs := []Blob{{Slot: SlotRequirements, Data: reqs}}
	special := 6
	var execFlags uint64
	if len(opts.Entitlements) > 0 && opts.ForceLibraryEntitlements {
		xml, der, err := EncodeEntitlements(opts.Entitlements)
		if err != nil {
			return nil, err
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
	if opts.Flags&FlagRuntime != 0 && opts.RuntimeVersion != 0 {
		header, version = 96, 0x20500
	}
	hashOff := header + len(opts.Identifier) + 1 + teamSize + special*32
	cdSize := hashOff + nPages*32
	if cdSize > maxFileSize-len(data) {
		return nil, unsupported("disk image signature exceeds memory limit")
	}
	cd := make([]byte, cdSize)
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
	be.PutUint32(cd[32:], uint32(len(m.content)))
	cd[36], cd[37] = 32, 2
	if opts.PageSize != 0 {
		cd[39] = byte(bits.TrailingZeros32(opts.PageSize))
	}
	if header >= 96 {
		be.PutUint64(cd[80:], execFlags)
		be.PutUint32(cd[88:], opts.RuntimeVersion)
	}
	copy(cd[header:], opts.Identifier)
	if teamSize > 0 {
		offset := header + len(opts.Identifier) + 1
		be.PutUint32(cd[48:], uint32(offset))
		copy(cd[offset:], opts.teamID)
	}
	for _, b := range append(blobs, Blob{Slot: SlotRepSpecific, Data: m.trailer()}) {
		h, _ := digest(2, b.Data)
		copy(cd[hashOff-int(b.Slot)*32:], h)
	}
	for i := 0; i < nPages; i++ {
		h, _ := digest(2, m.content[i*page:min((i+1)*page, len(m.content))])
		copy(cd[hashOff+i*32:], h)
	}
	var cms []byte
	if opts.Identity != nil {
		cms, err = SignCMS(ctx, opts.Identity, [][]byte{cd}, opts.SigningTime)
		if err != nil {
			return nil, err
		}
		if opts.Timestamp != nil {
			cms, err = TimestampCMS(ctx, cms, [][]byte{cd}, *opts.Timestamp)
			if err != nil {
				return nil, err
			}
		}
	}
	blobs = append(blobs, Blob{Slot: SlotDirectory, Data: cd}, Blob{Slot: SlotCMS, Data: blob(MagicCMS, cms)})
	sig := superblob(MagicSignature, blobs)
	if len(m.content)+len(sig)+dmgFooterSize > maxFileSize {
		return nil, unsupported("signed disk image exceeds memory limit")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.footer.CodeSignatureLength = uint64(len(sig))
	out := make([]byte, 0, len(m.content)+len(sig)+dmgFooterSize)
	out = append(out, m.content...)
	out = append(out, sig...)
	return append(out, m.trailer()...), nil
}
