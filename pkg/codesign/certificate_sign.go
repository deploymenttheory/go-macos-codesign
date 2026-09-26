package codesign

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"strconv"
)

func prepareIdentity(opts *SignOptions) error {
	path, err := linkedCertificates(opts.Identity.Certificates[0], opts.Identity.Certificates)
	if err != nil {
		return err
	}
	if len(path) != len(opts.Identity.Certificates) {
		return malformed("identity certificates are not one linked chain")
	}
	for i, c := range path {
		if !bytes.Equal(c.raw, opts.Identity.Certificates[i]) {
			return malformed("identity certificates must be leaf first")
		}
		if err := certificatePolicy(c, opts.SigningTime, i > 0, max(0, i-1)); err != nil {
			return err
		}
	}
	if appleDeveloper(path) {
		opts.teamID, err = subjectAttribute(path[0], "2.5.4.11")
		if err != nil {
			return err
		}
		if opts.teamID == "" || bytes.IndexByte([]byte(opts.teamID), 0) >= 0 {
			return malformed("certificate Team ID is missing or contains NUL")
		}
	}
	return prepareRequirements(opts, path)
}

func defaultCertificateRequirement(identifier string, path []*certificate) ([]byte, error) {
	if appleAnchor(path) {
		return appleCertificateRequirement(identifier, path)
	}
	org, err := subjectAttribute(path[0], "2.5.4.10")
	if err != nil {
		return nil, err
	}
	slot := 0
	if org != "" {
		for i := 1; i < len(path); i++ {
			next, err := subjectAttribute(path[i], "2.5.4.10")
			if err != nil {
				return nil, err
			}
			if next != org {
				break
			}
			slot = i
		}
	}
	label := strconv.Itoa(slot)
	if org != "" && slot == len(path)-1 {
		label = "root"
	}
	h := sha1.Sum(path[slot].raw)
	return CompileRequirements("identifier " + strconv.Quote(identifier) + " and certificate " + label + ` = H"` + hex.EncodeToString(h[:]) + `"`)
}

func appleCertificateRequirement(identifier string, path []*certificate) ([]byte, error) {
	expression := "anchor apple generic"
	if len(path) == 3 && extension(path[1], "1.2.840.113635.100.6.2.1") != nil {
		cn, err := subjectAttribute(path[0], "2.5.4.3")
		if err != nil {
			return nil, err
		}
		expression += " and (certificate leaf[subject.CN] = " + strconv.Quote(cn) + " and certificate 1[field.1.2.840.113635.100.6.2.1] exists)"
	} else if len(path) == 3 && extension(path[1], "1.2.840.113635.100.6.2.6") != nil {
		team, err := subjectAttribute(path[0], "2.5.4.11")
		if err != nil {
			return nil, err
		}
		expression += " and (certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = " + strconv.Quote(team) + "))"
	} else {
		return nil, unsupported("Apple proper designated requirement synthesis")
	}
	// Apple's maker nests the complete anchor expression under identifier.
	return CompileRequirements("identifier " + strconv.Quote(identifier) + " and (" + expression + ")")
}
