package codesign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/accesstime"
)

// maxFileSize bounds legacy byte paths and metadata, not held-source payloads.
const maxFileSize = 1 << 30

// Apple CodeSigner.cpp's default CMS blob budget, including its wrapper.
const defaultCMSSize = 18000

func readFile(path string) ([]byte, error) {
	return readFileWithAccess(path, false)
}

func readFileWithAccess(path string, recordAccess bool) ([]byte, error) {
	return readFileContext(context.Background(), path, recordAccess)
}

func readFileContext(ctx context.Context, path string, recordAccess bool) (_ []byte, result error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, f.Close()) }()
	return readOpenFileContext(ctx, f, recordAccess)
}

func readOpenFileContext(ctx context.Context, f *os.File, recordAccess bool) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	data, err := readBoundedContext(ctx, f, maxFileSize)
	if err != nil {
		return nil, err
	}
	// Native Mach-O signing maps its input; UDIF and read-only operations do not.
	if recordAccess && !isDMG(data) {
		if err := recordMachORead(f); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func recordMachORead(f *os.File) error {
	if err := accesstime.RecordReadAccess(f); err != nil && !errors.Is(err, accesstime.ErrReadAccessUnsupported) {
		return err
	}
	return nil
}

// Sign constructs output before writing a Mach-O, supported app bundle, or UDIF
// disk image to path. A DMG ad-hoc dry run writes unsigned components in place,
// matching codesign; see SignOptions.DryRun.
func Sign(ctx context.Context, path string, opts SignOptions) (err error) {
	defer func() { err = signingIOError(err) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	path, bundle, err := resolveCodePath(path)
	if err != nil {
		return err
	}
	if bundle {
		return signBundle(ctx, path, opts)
	}
	if opts.AppleDoubleFiles != nil {
		return unsupported("standalone signing requires AppleDouble, not AppleDoubleFiles")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	fileCloser := operationCloser{file.Close}
	defer func() { err = errors.Join(err, fileCloser.Close()) }()
	source, err := openCodeSource(ctx, file)
	if err != nil {
		return err
	}
	dmg, err := source.isDMG()
	if err != nil {
		return err
	}
	if dmg {
		return signDMGFile(ctx, file, path, source, opts)
	}
	return mutateMachOFile(ctx, file, &fileCloser, path, source, &opts)
}

// A replacement notice describes a readable signature, not its validity. Reuse
// inspection without verifying pages, certificate trust, or resource seals.
// A malformed or unsupported signature supplies no notification; the signer
// retains responsibility for the operation's error and supported input profile.
func notifyInspectedReplacement(r *Report, err error, opts SignOptions) {
	if err != nil {
		return
	}
	for _, arch := range r.Architectures {
		if arch.Signature != nil {
			opts.OnReplace()
			return
		}
	}
}

// SignBytes returns a new signed Mach-O or UDIF image; input bytes are never mutated.
// DryRun is a path-operation option and does not suppress the returned signature.
func SignBytes(ctx context.Context, data []byte, opts SignOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.AppleDouble != nil || opts.AppleDoubleFiles != nil {
		return nil, unsupported("signing AppleDouble metadata requires a filesystem object; use Sign")
	}
	return signBytes(ctx, data, opts, false)
}

func prepareSigningOptions(opts *SignOptions) error {
	if opts.Identifier == "" || bytes.IndexByte([]byte(opts.Identifier), 0) >= 0 {
		return fmt.Errorf("identifier must be nonempty and contain no NUL")
	}
	if opts.Timestamp != nil && (opts.Identity == nil || opts.Timestamp.Provider == nil || len(opts.Timestamp.TrustedRoots) == 0) {
		return invalid("timestamp requires a signing identity, provider and TSA roots")
	}
	if opts.Identity != nil {
		if opts.Flags&FlagAdhoc != 0 {
			return invalid("ad-hoc flag conflicts with signing identity")
		}
		if _, err := opts.Identity.validate(); err != nil {
			return err
		}
		if opts.SigningTime.IsZero() {
			opts.SigningTime = time.Now()
		}
		if err := prepareIdentity(opts); err != nil {
			return err
		}
	}
	if opts.Flags & ^uint32(0x33f02) != 0 {
		return unsupported("code signing flags")
	}
	if opts.Identity == nil {
		if err := prepareRequirements(opts, nil); err != nil {
			return err
		}
	}
	return nil
}

func signBytes(ctx context.Context, data []byte, opts SignOptions, dmgDryRun bool) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := prepareSigningOptions(&opts); err != nil {
		return nil, err
	}
	if isDMG(data) {
		return signDMG(ctx, data, opts, dmgDryRun)
	}
	c, err := parseContainer(data)
	if err != nil {
		return nil, err
	}
	out, err := c.mutateSource(ctx, byteOutput(data), &opts)
	if err != nil {
		return nil, err
	}
	return materializeOutput(ctx, out)
}

func signImageSource(ctx context.Context, im *image, source outputSource, opts SignOptions) (outputSource, error) {
	if im.sigCommand >= 0 && !opts.Force {
		return outputSource{}, ErrSigned
	}
	if im.filetype != 2 && im.filetype != 6 && im.filetype != 8 {
		return outputSource{}, unsupported(fmt.Sprintf("Mach-O file type %d", im.filetype))
	}
	if im.linkedit < 0 {
		return outputSource{}, malformed("missing LINKEDIT")
	}
	page := opts.PageSize
	if page == 0 {
		page = 4096
		if im.cpu == 0x100000c {
			page = 16384
		}
	}
	if page < 1 || page&(page-1) != 0 || page > 1<<30 {
		return outputSource{}, fmt.Errorf("page size must be a power of two at most 1 GiB")
	}
	reqs := opts.Requirements
	if len(reqs) == 0 {
		reqs = superblob(MagicRequirements, nil)
	}
	codeEnd := source.size
	if im.sigCommand >= 0 {
		if uint64(im.sigOffset)+uint64(im.sigSize) != uint64(source.size) {
			return outputSource{}, unsupported("signature is not at end of slice")
		}
		codeEnd = int64(im.sigOffset)
	}
	if source.size < 0 || source.size > math.MaxUint32 {
		return outputSource{}, allocationError("Mach-O input exceeds 32-bit allocation size")
	}
	codeEnd = (codeEnd + 15) &^ 15
	nPages := (codeEnd + int64(page) - 1) / int64(page)
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
			return outputSource{}, err
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
	cdSize := int64(header) + int64(len(opts.Identifier)) + 1 + int64(teamSize) + (int64(special)+nPages)*32
	sigLen := int64(12+(len(blobs)+1)*8) + cdSize
	for _, b := range blobs {
		sigLen += int64(len(b.Data))
	}
	// Apple's first pass reserves a current-version CodeDirectory, even when
	// the emitted directory needs the shorter 0x20400 header. The 8-byte delta
	// affects page hashes through LC_CODE_SIGNATURE and must be reproduced.
	if opts.Identity != nil {
		// SuperBlob::Maker::size counts the estimate as the entire CMS blob.
		// Replace the empty wrapper already counted above, then align once.
		sigLen += defaultCMSSize - 8
	}
	sigSize := (sigLen + int64(max(96-header, 0)) + 15) &^ 15
	if cdSize > maxFileSize || sigSize > maxFileSize {
		return outputSource{}, unsupported("signature metadata exceeds memory limit")
	}
	end := codeEnd + sigSize
	if end > math.MaxUint32 {
		return outputSource{}, allocationError("Mach-O output exceeds 32-bit allocation size")
	}
	headSize := im.header + int(im.order.Uint32(im.data[20:]))
	if im.sigCommand < 0 {
		headSize += 16
	}
	if int64(headSize) > source.size {
		return outputSource{}, unsupported("no room for LC_CODE_SIGNATURE")
	}
	out, err := (codeSource{ctx, source}).read(0, uint64(headSize))
	if err != nil {
		return outputSource{}, err
	}
	pos := im.sigCommand
	if pos < 0 {
		pos = im.header + int(im.order.Uint32(out[20:]))
		if uint64(pos+16) > im.firstSection || !bytes.Equal(out[pos:pos+16], make([]byte, 16)) {
			return outputSource{}, unsupported("no room for LC_CODE_SIGNATURE")
		}
		im.order.PutUint32(out[16:], im.order.Uint32(out[16:])+1)
		im.order.PutUint32(out[20:], im.order.Uint32(out[20:])+16)
	}
	o := im.order
	o.PutUint32(out[pos:], 0x1d)
	o.PutUint32(out[pos+4:], 16)
	o.PutUint32(out[pos+8:], uint32(codeEnd))
	o.PutUint32(out[pos+12:], uint32(sigSize))
	updateLinkedit(out, im, end)
	patched, err := patchedOutput(source, end, outputSpan{0, byteOutput(out)})
	if err != nil {
		return outputSource{}, err
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
			h, err := digestContext(ctx, 2, b.Data)
			if err != nil {
				return outputSource{}, err
			}
			copy(cd[hashOff-int(b.Slot)*32:], h)
		}
	}
	for slot, data := range map[uint32][]byte{SlotInfo: opts.InfoPlist, SlotResources: opts.Resources} {
		if len(data) > 0 {
			h, err := digestContext(ctx, 2, data)
			if err != nil {
				return outputSource{}, err
			}
			copy(cd[hashOff-int(slot)*32:], h)
		}
	}
	if err := hashCodePages(ctx, outputSource{patched.reader, 0, codeEnd}, page, cd[hashOff:]); err != nil {
		return outputSource{}, err
	}
	if opts.Identity != nil {
		cms, err := SignCMS(ctx, opts.Identity, [][]byte{cd}, opts.SigningTime)
		if err != nil {
			return outputSource{}, err
		}
		if opts.Timestamp != nil {
			cms, err = TimestampCMS(ctx, cms, [][]byte{cd}, *opts.Timestamp)
			if err != nil {
				return outputSource{}, err
			}
		}
		for i := range blobs {
			if blobs[i].Slot == SlotCMS {
				blobs[i].Data = blob(MagicCMS, cms)
			}
		}
	}
	sig := superblob(MagicSignature, append(blobs, Blob{Slot: SlotDirectory, Data: cd}))
	if int64(len(sig)) > sigSize {
		return outputSource{}, invalid("CMS exceeds reserved signature space")
	}
	return patchedOutput(source, end, outputSpan{0, byteOutput(out)}, outputSpan{codeEnd, byteOutput(sig)})
}

func updateLinkedit(out []byte, im *image, end int64) {
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

// RemoveSignature removes embedded Mach-O, generic attached and supported
// app-bundle signatures. Use Remove to supply explicit AppleDouble metadata.
// Native codesign does not support removing a UDIF signature; that returns ErrUnsupported.
func RemoveSignature(ctx context.Context, path string) error {
	return RemoveSignatureWithOptions(ctx, path, PathOptions{})
}

// RemoveSignatureWithOptions removes only the selected version's signature.
func RemoveSignatureWithOptions(ctx context.Context, path string, opts PathOptions) error {
	return Remove(ctx, path, RemoveOptions{BundleVersion: opts.BundleVersion})
}

// Remove removes the selected embedded or generic attached signature. Generic
// removal preserves the data fork and hard links; completed attribute removals
// survive later failures. Only explicit AppleDouble inputs are considered.
func Remove(ctx context.Context, path string, opts RemoveOptions) (err error) {
	defer func() { err = signingIOError(err) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	path, bundle, err := resolveCodePath(path)
	if err != nil {
		return err
	}
	if bundle {
		return removeBundle(ctx, path, opts)
	}
	if opts.AppleDoubleFiles != nil {
		return unsupported("standalone removal requires AppleDouble, not AppleDoubleFiles")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	fileCloser := operationCloser{f.Close}
	defer func() { err = errors.Join(err, fileCloser.Close()) }()
	generic, err := genericRemovalCandidate(ctx, f)
	if err != nil {
		return err
	}
	if generic {
		return removeGenericSignature(ctx, f, func() (*os.File, error) { return os.OpenFile(path, os.O_RDWR, 0) }, opts.AppleDouble)
	}
	source, err := openCodeSource(ctx, f)
	if err != nil {
		return err
	}
	dmg, err := source.isDMG()
	if err != nil {
		return err
	}
	if dmg {
		return unsupported("signature removal for disk images")
	}
	return mutateMachOFile(ctx, f, &fileCloser, path, source, nil)
}

func RemoveSignatureBytes(ctx context.Context, data []byte) ([]byte, error) {
	if isDMG(data) {
		return nil, unsupported("signature removal for disk images")
	}
	c, err := parseContainer(data)
	if err != nil {
		return nil, err
	}
	out, err := c.mutateSource(ctx, byteOutput(data), nil)
	if err != nil {
		return nil, err
	}
	return materializeOutput(ctx, out)
}
