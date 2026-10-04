package codesign

import (
	"context"
	"errors"
	"os"
)

// A bundle owns every executable descriptor borrowed by its output plans.
// Resource payloads are hashed and closed individually; executable handles stay
// open until their staged output is complete, then close before Windows rename.
type bundleSource struct {
	file     *os.File
	info     os.FileInfo
	closer   operationCloser
	released bool
}

func (b *appBundle) holdCode(ctx context.Context, name string) (codeSource, error) {
	if err := ctx.Err(); err != nil {
		return codeSource{}, err
	}
	held := b.sources[name]
	if held == nil {
		file, err := b.openRegular(name)
		if err != nil {
			return codeSource{}, err
		}
		info, err := file.Stat()
		if err != nil {
			return codeSource{}, errors.Join(err, file.Close())
		}
		held = &bundleSource{file: file, info: info, closer: operationCloser{file.Close}}
		if b.sources == nil {
			b.sources = map[string]*bundleSource{}
		}
		b.sources[name] = held
	}
	if err := b.checkCode(name, held); err != nil {
		return codeSource{}, err
	}
	b.observeSideband(name, held.file)
	return codeSource{ctx, outputSource{reader: held.file, size: held.info.Size()}}, nil
}

func (b *appBundle) checkCode(name string, held *bundleSource) error {
	current, err := b.root.Lstat(name)
	if err != nil {
		return err
	}
	if !os.SameFile(held.info, current) {
		return invalid("bundle source changed: %s", name)
	}
	return sourceUnchanged(held.file, held.info)
}

func signCodeSource(source codeSource, opts SignOptions) (outputSource, error) {
	if err := source.ctx.Err(); err != nil {
		return outputSource{}, err
	}
	if err := prepareSigningOptions(&opts); err != nil {
		return outputSource{}, err
	}
	c, err := source.container()
	if err != nil {
		return outputSource{}, err
	}
	return c.mutateSource(source.ctx, source.source, &opts)
}

func verifyCodeSource(source codeSource, opts VerifyOptions) (*Report, error) {
	return verifyInput(source.ctx, opts, false, source.inspect, source.digest, source.strict)
}
