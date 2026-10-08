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
	ctx = context.WithValue(ctx, preserveCompressionKey{}, opts.PreserveAFSC)
	ctx, storage, err := beginWorkingStorage(ctx)
	if err != nil {
		return err
	}
	defer func() { err = signingIOError(errors.Join(err, storage.Close())) }()
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
func SignBytes(ctx context.Context, data []byte, opts SignOptions) (output []byte, err error) {
	ctx, storage, err := beginWorkingStorage(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, storage.Close()) }()
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
	// MachORep::needsExecSeg requires a platform command. The directory
	// builder selects the shortest version that represents the populated fields.
	header, version := 48, uint32(0x20100)
	if opts.teamID != "" {
		header, version = 52, 0x20200
	}
	if im.execPlatform != 0 && im.textSize > 0 {
		header, version = 88, 0x20400
	}
	if opts.Flags&FlagRuntime != 0 {
		header, version = 96, 0x20500
		if opts.RuntimeVersion == 0 {
			opts.RuntimeVersion = im.versionSDK
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
	// the emitted directory needs a shorter header. The size delta
	// affects page hashes through LC_CODE_SIGNATURE and must be reproduced.
	if opts.Identity != nil {
		// SuperBlob::Maker::size counts the estimate as the entire CMS blob.
		// Replace the empty wrapper already counted above, then align once.
		sigLen += defaultCMSSize - 8
	}
	sigSize := (sigLen + int64(max(96-header, 0)) + 15) &^ 15
	if cdSize > math.MaxUint32 || sigSize > math.MaxUint32 {
		return outputSource{}, allocationError("signature metadata exceeds 32-bit representation")
	}
	end := codeEnd + sigSize
	if end > math.MaxUint32 {
		return outputSource{}, allocationError("Mach-O output exceeds 32-bit allocation size")
	}
	patched, err := signingCommandOutput(ctx, im, source, codeEnd, sigSize, end)
	if err != nil {
		return outputSource{}, err
	}
	hashOff := header + len(opts.Identifier) + 1 + teamSize + int(special)*32
	cd := make([]byte, header)
	section, err := newWorkingSection(ctx, cdSize)
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
	be.PutUint32(cd[24:], special)
	be.PutUint32(cd[28:], uint32(nPages))
	be.PutUint32(cd[32:], uint32(codeEnd))
	cd[36] = 32
	cd[37] = 2
	cd[39] = byte(bits.TrailingZeros32(page))
	if header >= 88 {
		if im.execPlatform != 0 {
			be.PutUint64(cd[64:], im.textBase)
			be.PutUint64(cd[72:], im.textSize)
		}
		be.PutUint64(cd[80:], execFlags)
	}
	if header >= 96 {
		be.PutUint32(cd[88:], opts.RuntimeVersion)
	}
	if teamSize > 0 {
		offset := header + len(opts.Identifier) + 1
		be.PutUint32(cd[48:], uint32(offset))
	}
	if err := writeDirectoryPrefix(ctx, section, cd, opts.Identifier, opts.teamID); err != nil {
		return outputSource{}, err
	}
	for _, b := range blobs {
		if b.Slot < 0x1000 {
			h, err := digestContext(ctx, 2, b.Data)
			if err != nil {
				return outputSource{}, err
			}
			if _, err := section.WriteAt(h, int64(hashOff)-int64(b.Slot)*32); err != nil {
				return outputSource{}, err
			}
		}
	}
	for slot, data := range map[uint32][]byte{SlotInfo: opts.InfoPlist, SlotResources: opts.Resources} {
		if len(data) > 0 {
			h, err := digestContext(ctx, 2, data)
			if err != nil {
				return outputSource{}, err
			}
			if _, err := section.WriteAt(h, int64(hashOff)-int64(slot)*32); err != nil {
				return outputSource{}, err
			}
		}
	}
	if err := hashCodePagesTo(ctx, outputSource{patched.reader, 0, codeEnd}, page, section, int64(hashOff)); err != nil {
		return outputSource{}, err
	}
	if opts.Identity != nil {
		cms, err := signGeneratedCMS(ctx, opts.Identity, section.output(), opts.SigningTime, opts.Timestamp)
		if err != nil {
			return outputSource{}, err
		}
		for i := range blobs {
			if blobs[i].Slot == SlotCMS {
				blobs[i].Data = blob(MagicCMS, cms)
			}
		}
	}
	sections := []signatureSection{{SlotDirectory, section.output()}}
	for _, b := range blobs {
		sections = append(sections, signatureSection{b.Slot, byteOutput(b.Data)})
	}
	sig, err := superblobOutput(MagicSignature, sections)
	if err != nil {
		return outputSource{}, err
	}
	if sig.size > sigSize {
		return outputSource{}, invalid("CMS exceeds reserved signature space")
	}
	return patchedOutput(patched, end, outputSpan{codeEnd, sig})
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
// survive later failures. The filesystem selects native or associated AppleDouble
// storage; callers may also supply explicit library metadata bindings.
func Remove(ctx context.Context, path string, opts RemoveOptions) (err error) {
	ctx, storage, err := beginWorkingStorage(ctx)
	if err != nil {
		return err
	}
	defer func() { err = signingIOError(errors.Join(err, storage.Close())) }()
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

func RemoveSignatureBytes(ctx context.Context, data []byte) (output []byte, err error) {
	ctx, storage, err := beginWorkingStorage(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, storage.Close()) }()
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
