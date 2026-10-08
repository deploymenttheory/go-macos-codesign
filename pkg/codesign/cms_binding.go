package codesign

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"time"
)

type cmsDirectoryBinding struct {
	pl      cdHashPlist
	agility [][]byte
	primary []byte
}

func (s *Signature) verifyCMS() (*CMSInfo, error) {
	if s.view == nil {
		cms, err := s.componentBytes(SlotCMS)
		if err != nil || len(cms) <= 8 {
			return nil, err
		}
		directories := [][]byte{s.find(SlotDirectory)}
		for slot := uint32(0x1000); slot < 0x1005; slot++ {
			if cd := s.find(slot); cd != nil {
				directories = append(directories, cd)
			}
		}
		return VerifyCMS(cms[8:], directories)
	}
	source, found, err := s.view.component(SlotCMS)
	if err != nil || !found || source.source.size <= 8 {
		return nil, err
	}
	source.source.offset += 8
	source.source.size -= 8
	bound, err := s.view.cmsBinding()
	if err != nil {
		return nil, err
	}
	return verifyCMSSourceBound(source, bound)
}

func (v *signatureView) cmsBinding() (cmsDirectoryBinding, error) {
	var bound cmsDirectoryBinding
	if v.directoryCount == 0 || v.directoryCount > 5 {
		return bound, malformed("CMS CodeDirectory count")
	}
	seen := map[string]bool{}
	// CMS hashes follow slot order, regardless of the SuperBlob index order.
	for _, slot := range [...]uint32{0, 0x1000, 0x1001, 0x1002, 0x1003, 0x1004} {
		for i := 0; i < v.directoryCount; i++ {
			d := &v.directories[i]
			if d.slot != slot {
				continue
			}
			kind := d.metadata.HashType
			var oid asn1.ObjectIdentifier
			switch kind {
			case 1:
				oid = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
			case 2, 3:
				oid, kind = oidSHA256, 2
			case 4:
				oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
			}
			if seen[oid.String()] {
				return bound, unsupported("multiple CodeDirectories using the same digest")
			}
			seen[oid.String()] = true
			sum, err := d.source.digest(kind, 0, uint64(d.source.source.size))
			if err != nil {
				return bound, err
			}
			bound.pl.CDHashes = append(bound.pl.CDHashes, sum[:20])
			bound.agility = append(bound.agility, derSequence(derOID(oid), derWrap(4, sum)))
			if slot == 0 {
				bound.primary, err = d.source.digest(2, 0, uint64(d.source.source.size))
				if err != nil {
					return bound, err
				}
			}
		}
	}
	return bound, nil
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
