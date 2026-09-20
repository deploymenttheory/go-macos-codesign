package codesign

import (
	"bytes"
	"context"
	"fmt"
	"math/bits"
	"os"
	"time"
)

// maxFileSize bounds in-memory operations. Larger files fail explicitly.
const maxFileSize = 1 << 30

// Apple CodeSigner.cpp's default CMS blob budget, including its wrapper.
const defaultCMSSize = 18000

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, unsupported("non-regular file")
	}
	if st.Size() > maxFileSize {
		return nil, unsupported("file exceeds 1 GiB memory limit")
	}
	// Read through a bounded reader; a concurrent growing file cannot defeat Stat.
	return readBounded(f, maxFileSize)
}

// Sign constructs complete signatures before writing a Mach-O, supported app
// bundle, or UDIF disk image to path.
func Sign(ctx context.Context, path string, opts SignOptions) error {
	if isBundle(path) {
		return signBundle(ctx, path, opts)
	}
	data, err := readFile(path)
	if err != nil {
		return err
	}
	if opts.Identifier == "" {
		if isDMG(data) {
			opts.Identifier, err = dmgIdentifier(path, data, opts.Identity == nil)
		} else {
			opts.Identifier, err = machoIdentifier(path, data, opts.Identity == nil)
		}
		if err != nil {
			return err
		}
	}
	out, err := SignBytes(ctx, data, opts)
	if err != nil {
		return err
	}
	if opts.DryRun {
		return nil
	}
	return replaceFile(ctx, path, out)
}

// SignBytes returns a new signed Mach-O or UDIF image; input bytes are never mutated.
func SignBytes(ctx context.Context, data []byte, opts SignOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.Identifier == "" || bytes.IndexByte([]byte(opts.Identifier), 0) >= 0 {
		return nil, fmt.Errorf("identifier must be nonempty and contain no NUL")
	}
	if opts.Timestamp != nil && (opts.Identity == nil || opts.Timestamp.Provider == nil || len(opts.Timestamp.TrustedRoots) == 0) {
		return nil, invalid("timestamp requires a signing identity, provider and TSA roots")
	}
	if opts.Identity != nil {
		if opts.Flags&FlagAdhoc != 0 {
			return nil, invalid("ad-hoc flag conflicts with signing identity")
		}
		if _, err := opts.Identity.validate(); err != nil {
			return nil, err
		}
		if opts.SigningTime.IsZero() {
			opts.SigningTime = time.Now()
		}
		if err := prepareIdentity(&opts); err != nil {
			return nil, err
		}
	}
	if opts.Flags & ^uint32(0x33f02) != 0 {
		return nil, unsupported("code signing flags")
	}
	if isDMG(data) {
		return signDMG(ctx, data, opts)
	}
	c, err := parseContainer(data)
	if err != nil {
		return nil, err
	}
	parts := make([][]byte, len(c.slices))
	for i, s := range c.slices {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parts[i], err = signImage(ctx, s.image, opts)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", archName(s.cpu, s.subtype), err)
		}
		if c.fat && c.slices[i].alignment < 14 {
			c.slices[i].alignment = 14
		}
	}
	return c.assemble(parts)
}

func signImage(ctx context.Context, im *image, opts SignOptions) ([]byte, error) {
	if im.sigCommand >= 0 && !opts.Force {
		return nil, ErrSigned
	}
	if im.filetype != 2 && im.filetype != 6 && im.filetype != 8 {
		return nil, unsupported(fmt.Sprintf("Mach-O file type %d", im.filetype))
	}
	if im.linkedit < 0 {
		return nil, malformed("missing LINKEDIT")
	}
	page := opts.PageSize
	if page == 0 {
		page = 4096
		if im.cpu == 0x100000c {
			page = 16384
		}
	}
	if page < 1 || page&(page-1) != 0 || page > 1<<30 {
		return nil, fmt.Errorf("page size must be a power of two at most 1 GiB")
	}
	reqs := opts.Requirements
	if len(reqs) == 0 {
		reqs = superblob(MagicRequirements, nil)
	} else if err := validateRequirements(reqs); err != nil {
		return nil, err
	}
	codeEnd := len(im.data)
	if im.sigCommand >= 0 {
		if uint64(im.sigOffset)+uint64(im.sigSize) != uint64(len(im.data)) {
			return nil, unsupported("signature is not at end of slice")
		}
		codeEnd = int(im.sigOffset)
	}
	codeEnd = (codeEnd + 15) &^ 15
	nPages := (codeEnd + int(page) - 1) / int(page)
	special := uint32(2)
	if len(opts.Resources) > 0 {
		special = 3
	}
	blobs := []Blob{{Slot: SlotRequirements, Data: reqs}, {Slot: SlotCMS, Data: blob(MagicCMS, nil)}}
	var execFlags uint64
	if im.filetype == 2 {
		execFlags = 1
	}
	if len(opts.Entitlements) > 0 && (im.filetype == 2 || opts.ForceLibraryEntitlements) {
		xml, der, err := EncodeEntitlements(opts.Entitlements)
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, Blob{Slot: SlotEntitlements, Data: blob(MagicEntitlements, xml)}, Blob{Slot: SlotDEREntitlements, Data: blob(MagicDEREntitlements, der)})
		execFlags |= entitlementExecFlags(xml)
		special = 7
	}
	header, version := 88, uint32(0x20400)
	if opts.Flags&FlagRuntime != 0 {
		header, version = 96, 0x20500
		if opts.RuntimeVersion == 0 {
			for _, cmd := range im.commands {
				if cmd.kind == 0x32 && cmd.size >= 24 {
					opts.RuntimeVersion = im.order.Uint32(im.data[cmd.offset+16:])
				}
			}
			if opts.RuntimeVersion == 0 {
				opts.RuntimeVersion = 27 << 16
			}
		}
	}
	teamSize := 0
	if opts.teamID != "" {
		teamSize = len(opts.teamID) + 1
	}
	cdSize := header + len(opts.Identifier) + 1 + teamSize + (int(special)+nPages)*32
	sigLen := 12 + (len(blobs)+1)*8 + cdSize
	for _, b := range blobs {
		sigLen += len(b.Data)
	}
	// Apple's first pass reserves a current-version CodeDirectory, even when
	// the emitted directory needs the shorter 0x20400 header. The 8-byte delta
	// affects page hashes through LC_CODE_SIGNATURE and must be reproduced.
	if opts.Identity != nil {
		// SuperBlob::Maker::size counts the estimate as the entire CMS blob.
		// Replace the empty wrapper already counted above, then align once.
		sigLen += defaultCMSSize - 8
	}
	sigSize := (sigLen + max(96-header, 0) + 15) &^ 15
	if codeEnd+sigSize > maxFileSize {
		return nil, unsupported("output exceeds memory limit")
	}
	out := make([]byte, codeEnd+sigSize)
	copy(out, im.data[:min(len(im.data), codeEnd)])
	pos := im.sigCommand
	if pos < 0 {
		pos = im.header + int(im.order.Uint32(out[20:]))
		if uint64(pos+16) > im.firstSection || !bytes.Equal(out[pos:pos+16], make([]byte, 16)) {
			return nil, unsupported("no room for LC_CODE_SIGNATURE")
		}
		im.order.PutUint32(out[16:], im.order.Uint32(out[16:])+1)
		im.order.PutUint32(out[20:], im.order.Uint32(out[20:])+16)
	}
	o := im.order
	o.PutUint32(out[pos:], 0x1d)
	o.PutUint32(out[pos+4:], 16)
	o.PutUint32(out[pos+8:], uint32(codeEnd))
	o.PutUint32(out[pos+12:], uint32(sigSize))
	updateLinkedit(out, im, len(out))
	cd := make([]byte, cdSize)
	be.PutUint32(cd, MagicDirectory)
	be.PutUint32(cd[4:], uint32(cdSize))
	be.PutUint32(cd[8:], version)
	flags := opts.Flags
	if opts.Identity == nil {
		flags |= FlagAdhoc
	}
	be.PutUint32(cd[12:], flags)
	hashOff := header + len(opts.Identifier) + 1 + teamSize + int(special)*32
	be.PutUint32(cd[16:], uint32(hashOff))
	be.PutUint32(cd[20:], uint32(header))
	be.PutUint32(cd[24:], special)
	be.PutUint32(cd[28:], uint32(nPages))
	be.PutUint32(cd[32:], uint32(codeEnd))
	cd[36] = 32
	cd[37] = 2
	cd[39] = byte(bits.TrailingZeros32(page))
	be.PutUint64(cd[64:], im.textBase)
	be.PutUint64(cd[72:], im.textSize)
	be.PutUint64(cd[80:], execFlags)
	if header >= 96 {
		be.PutUint32(cd[88:], opts.RuntimeVersion)
	}
	copy(cd[header:], opts.Identifier)
	if teamSize > 0 {
		offset := header + len(opts.Identifier) + 1
		be.PutUint32(cd[48:], uint32(offset))
		copy(cd[offset:], opts.teamID)
	}
	for _, b := range blobs {
		if b.Slot < 0x1000 {
			h, _ := digest(2, b.Data)
			copy(cd[hashOff-int(b.Slot)*32:], h)
		}
	}
	for slot, data := range map[uint32][]byte{SlotInfo: opts.InfoPlist, SlotResources: opts.Resources} {
		if len(data) > 0 {
			h, _ := digest(2, data)
			copy(cd[hashOff-int(slot)*32:], h)
		}
	}
	for i := 0; i < nPages; i++ {
		start := i * int(page)
		h, _ := digest(2, out[start:min(start+int(page), codeEnd)])
		copy(cd[hashOff+i*32:], h)
	}
	if opts.Identity != nil {
		cms, err := SignCMS(ctx, opts.Identity, [][]byte{cd}, opts.SigningTime)
		if err != nil {
			return nil, err
		}
		if opts.Timestamp != nil {
			cms, err = TimestampCMS(ctx, cms, [][]byte{cd}, *opts.Timestamp)
			if err != nil {
				return nil, err
			}
		}
		for i := range blobs {
			if blobs[i].Slot == SlotCMS {
				blobs[i].Data = blob(MagicCMS, cms)
			}
		}
	}
	sig := superblob(MagicSignature, append(blobs, Blob{Slot: SlotDirectory, Data: cd}))
	if len(sig) > sigSize {
		return nil, invalid("CMS exceeds reserved signature space")
	}
	copy(out[codeEnd:], sig)
	return out, nil
}

func updateLinkedit(out []byte, im *image, end int) {
	p := im.linkedit
	o := im.order
	if o.Uint32(out[p:]) == 0x19 {
		size := uint64(end) - o.Uint64(out[p+40:])
		o.PutUint64(out[p+48:], size)
		o.PutUint64(out[p+32:], (size+16383)&^uint64(16383))
	} else {
		size := uint32(end) - o.Uint32(out[p+32:])
		o.PutUint32(out[p+36:], size)
		o.PutUint32(out[p+28:], (size+16383)&^uint32(16383))
	}
}

// RemoveSignature removes embedded Mach-O and supported app-bundle signatures.
// Native codesign does not support removing a UDIF signature; that returns ErrUnsupported.
func RemoveSignature(ctx context.Context, path string) error {
	if isBundle(path) {
		return removeBundle(ctx, path)
	}
	data, err := readFile(path)
	if err != nil {
		return err
	}
	out, err := RemoveSignatureBytes(ctx, data)
	if err != nil {
		return err
	}
	return replaceFile(ctx, path, out)
}

func RemoveSignatureBytes(ctx context.Context, data []byte) ([]byte, error) {
	if isDMG(data) {
		return nil, unsupported("signature removal for disk images")
	}
	c, err := parseContainer(data)
	if err != nil {
		return nil, err
	}
	parts := make([][]byte, len(c.slices))
	for i, s := range c.slices {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		im := s.image
		if im.sigCommand < 0 {
			parts[i] = bytes.Clone(im.data)
			continue
		}
		if uint64(im.sigOffset)+uint64(im.sigSize) != uint64(len(im.data)) || im.linkedit < 0 {
			return nil, unsupported("nonterminal signature or missing LINKEDIT")
		}
		out := bytes.Clone(im.data[:im.sigOffset])
		end := im.header + int(im.order.Uint32(out[20:]))
		copy(out[im.sigCommand:], out[im.sigCommand+16:end])
		clear(out[end-16 : end])
		im.order.PutUint32(out[16:], im.order.Uint32(out[16:])-1)
		im.order.PutUint32(out[20:], im.order.Uint32(out[20:])-16)
		// Account for a LINKEDIT command located after the signature command.
		copyImage := *im
		if copyImage.linkedit > im.sigCommand {
			copyImage.linkedit -= 16
		}
		updateLinkedit(out, &copyImage, len(out))
		parts[i] = out
	}
	return c.assemble(parts)
}
