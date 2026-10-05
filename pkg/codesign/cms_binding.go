package codesign

import (
	"context"
	"crypto/sha256"
	"time"
)

type cmsDirectoryBinding struct {
	pl      cdHashPlist
	agility [][]byte
	primary []byte
}

func bindCMSDirectories(directories [][]byte) (cmsDirectoryBinding, error) {
	pl, agility, err := directoryHashes(directories)
	if err != nil {
		return cmsDirectoryBinding{}, err
	}
	primary := sha256.Sum256(directories[0])
	return cmsDirectoryBinding{pl, agility, primary[:]}, nil
}

// A generated directory has already passed sizing/format checks in the builder
// and always uses SHA-256. Hash its complete range, including spilled slots,
// without materializing it merely to construct or verify its CMS binding.
func signGeneratedCMS(ctx context.Context, id *Identity, directory outputSource, signingTime time.Time, timestamp *TimestampOptions) ([]byte, error) {
	var bound cmsDirectoryBinding
	cms, err := signCMSBound(ctx, id, signingTime, func() (cmsDirectoryBinding, error) {
		h, err := digestSource(ctx, 2, directory)
		if err != nil {
			return cmsDirectoryBinding{}, err
		}
		bound = cmsDirectoryBinding{cdHashPlist{CDHashes: [][]byte{h[:20]}}, [][]byte{derSequence(derOID(oidSHA256), derWrap(4, h))}, h}
		return bound, nil
	})
	if err != nil || timestamp == nil {
		return cms, err
	}
	return timestampCMSBound(ctx, cms, *timestamp, func() (*CMSInfo, error) { return verifyCMSBound(cms, bound) })
}
