package codesign

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
)

func allocationError(detail string) error {
	return &VerificationError{Diagnostic: "internal error in Code Signing subsystem", cause: unsupported(detail), omitArchitecture: true}
}

func (c *container) assembleSources(parts []outputSource) (outputSource, error) {
	if !c.fat {
		return parts[0], nil
	}
	entry := 20
	if c.fat64 {
		entry = 32
	}
	header := bytes.Clone(c.data[:8+len(parts)*entry])
	p := new(outputPlan)
	if err := p.append(byteOutput(header)); err != nil {
		return outputSource{}, err
	}
	for i, part := range parts {
		alignment := int64(1) << c.slices[i].alignment
		padding := (-p.size) & (alignment - 1)
		if err := p.append(outputSource{reader: zeroSource{}, size: padding}); err != nil {
			return outputSource{}, err
		}
		offset := p.size
		if err := p.append(part); err != nil {
			return outputSource{}, err
		}
		if !c.fat64 && p.size > math.MaxUint32 {
			return outputSource{}, allocationError("universal file exceeds 32-bit offsets")
		}
		at := 8 + i*entry
		if c.fat64 {
			c.order.PutUint64(header[at+8:], uint64(offset))
			c.order.PutUint64(header[at+16:], uint64(part.size))
			c.order.PutUint32(header[at+24:], c.slices[i].alignment)
		} else {
			c.order.PutUint32(header[at+8:], uint32(offset))
			c.order.PutUint32(header[at+12:], uint32(part.size))
			c.order.PutUint32(header[at+16:], c.slices[i].alignment)
		}
	}
	return p.output(), nil
}

func (c *container) mutateSource(ctx context.Context, source outputSource, opts *SignOptions) (outputSource, error) {
	if source.size > math.MaxUint32 {
		return outputSource{}, allocationError("Mach-O input exceeds 32-bit allocation size")
	}
	parts := make([]outputSource, len(c.slices))
	for i, s := range c.slices {
		if err := ctx.Err(); err != nil {
			return outputSource{}, err
		}
		part := outputSource{source.reader, source.offset + int64(s.offset), int64(s.size)}
		var err error
		if opts == nil {
			parts[i], err = removeImageSource(ctx, s.image, part)
			if c.fat {
				c.slices[i].alignment = 14
			}
		} else {
			parts[i], err = signImageSource(ctx, s.image, part, *opts)
			if err != nil {
				err = fmt.Errorf("%s: %w", archName(s.cpu, s.subtype), err)
			}
			if c.fat && c.slices[i].alignment < 14 {
				c.slices[i].alignment = 14
			}
		}
		if err != nil {
			return outputSource{}, err
		}
	}
	return c.assembleSources(parts)
}

func mutateMachOFile(ctx context.Context, file *os.File, closer *operationCloser, path string, source codeSource, opts *SignOptions) error {
	before, err := file.Stat()
	if err != nil {
		return err
	}
	if err := recordMachORead(file); err != nil {
		return err
	}
	c, err := source.container()
	if err != nil {
		return err
	}
	dryRun := false
	if opts != nil {
		// Match byte-path notice/already-signed precedence using only signature
		// ranges. An unreadable signature supplies no replacement notice.
		states, inspectErr := source.signingSignatures(c)
		if inspectErr == nil {
			for _, state := range states {
				if !state.present {
					continue
				}
				if opts.Force && opts.OnReplace != nil {
					opts.OnReplace()
					break
				}
				if !opts.Force && state.flags&0x20000 == 0 {
					return ErrSigned
				}
			}
		}
		if err := signingSideband(ctx, file, path, opts.AppleDouble, *opts, false); err != nil {
			return err
		}
		if opts.Identifier == "" {
			opts.Identifier, err = c.identifier(path, opts.Identity == nil)
			if err != nil {
				return err
			}
		}
		if err := prepareSigningOptions(opts); err != nil {
			return err
		}
		dryRun = opts.DryRun
	}
	out, err := c.mutateSource(ctx, source.source, opts)
	if err != nil {
		return err
	}
	return replaceSource(ctx, path, file, closer, before, out, dryRun)
}
