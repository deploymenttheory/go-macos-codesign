package codesign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // SHA-384/512 certificate signatures.
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"time"
)

// CertificateInfo is descriptive metadata, not a trust decision.
type CertificateInfo struct {
	CommonName          string
	Organization        string
	OrganizationalUnit  string
	SerialNumber        string
	SHA256              string
	NotBefore, NotAfter time.Time
}

// CertificateChain is a validated leaf-first path to an explicitly supplied CA.
// It does not imply revocation, notarization, or system/keychain trust.
type CertificateChain struct {
	Certificates [][]byte
	Authorities  []CertificateInfo
	TeamID       string
}

func subjectAttribute(c *certificate, oid string) (string, error) {
	type attribute struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	type attributeSET []attribute
	var name []attributeSET
	if err := decodeDER(c.tbs.Subject.FullBytes, &name); err != nil {
		return "", err
	}
	for _, set := range name {
		for _, a := range set {
			if a.ID.String() == oid {
				var s string
				if err := decodeDER(a.Value.FullBytes, &s); err != nil {
					return "", err
				}
				return s, nil
			}
		}
	}
	return "", nil
}

func certificateInfo(c *certificate) (CertificateInfo, error) {
	sum := sha256.Sum256(c.raw)
	i := CertificateInfo{SerialNumber: c.tbs.Serial.Text(16), SHA256: hex.EncodeToString(sum[:]), NotBefore: c.tbs.Validity.NotBefore, NotAfter: c.tbs.Validity.NotAfter}
	for oid, dest := range map[string]*string{"2.5.4.3": &i.CommonName, "2.5.4.10": &i.Organization, "2.5.4.11": &i.OrganizationalUnit} {
		v, err := subjectAttribute(c, oid)
		if err != nil {
			return i, err
		}
		*dest = v
	}
	return i, nil
}

func extension(c *certificate, oid string) []byte {
	for _, e := range c.tbs.Extensions {
		if e.ID.String() == oid {
			return e.Value
		}
	}
	return nil
}

func certificateSignature(child, parent *certificate) error {
	if !bytes.Equal(child.tbs.Issuer.FullBytes, parent.tbs.Subject.FullBytes) {
		return invalid("certificate issuer does not match parent subject")
	}
	var h crypto.Hash
	var rsaAlgorithm bool
	switch child.tbs.Signature.Algorithm.String() {
	case "1.2.840.113549.1.1.11":
		h, rsaAlgorithm = crypto.SHA256, true
	case "1.2.840.113549.1.1.12":
		h, rsaAlgorithm = crypto.SHA384, true
	case "1.2.840.113549.1.1.13":
		h, rsaAlgorithm = crypto.SHA512, true
	case "1.2.840.10045.4.3.2":
		h = crypto.SHA256
	case "1.2.840.10045.4.3.3":
		h = crypto.SHA384
	case "1.2.840.10045.4.3.4":
		h = crypto.SHA512
	default:
		return unsupported("certificate signature algorithm " + child.tbs.Signature.Algorithm.String())
	}
	params := child.tbs.Signature.Parameters
	if rsaAlgorithm && !nullOrAbsent(params) || !rsaAlgorithm && len(params.FullBytes) != 0 {
		return malformed("certificate signature parameters")
	}
	d := h.New()
	_, _ = d.Write(child.tbs.Raw)
	digest := d.Sum(nil)
	switch key := parent.public.(type) {
	case *rsa.PublicKey:
		if rsaAlgorithm && rsa.VerifyPKCS1v15(key, h, digest, child.signature) == nil {
			return nil
		}
	case *ecdsa.PublicKey:
		if !rsaAlgorithm && ecdsa.VerifyASN1(key, digest, child.signature) {
			return nil
		}
	}
	return invalid("certificate signature")
}

type basicConstraints struct {
	CA      bool `asn1:"optional"`
	PathLen int  `asn1:"optional,default:-1"`
}

// This deliberately conservative policy rejects unsupported path constraints,
// including noncritical constraints, rather than silently ignoring restrictions.
func certificatePolicy(c *certificate, at time.Time, ca bool, below int) error {
	if at.Before(c.tbs.Validity.NotBefore) || at.After(c.tbs.Validity.NotAfter) {
		return invalid("certificate is not valid at verification time")
	}
	constraints := basicConstraints{PathLen: -1}
	for _, e := range c.tbs.Extensions {
		switch e.ID.String() {
		case "2.5.29.15":
			var ku asn1.BitString
			if err := decodeDER(e.Value, &ku); err != nil {
				return err
			}
			bit := 0
			if ca {
				bit = 5
			}
			if ku.At(bit) == 0 {
				return invalid("certificate key usage")
			}
		case "2.5.29.19":
			if err := decodeDER(e.Value, &constraints); err != nil {
				return err
			}
			if constraints.PathLen < -1 || !constraints.CA && constraints.PathLen != -1 {
				return malformed("certificate basic constraints")
			}
		case "2.5.29.37":
			var purposes []asn1.ObjectIdentifier
			if err := decodeDER(e.Value, &purposes); err != nil {
				return err
			}
			allowed := false
			for _, oid := range purposes {
				allowed = allowed || oid.String() == "1.3.6.1.5.5.7.3.3" || oid.String() == "2.5.29.37.0"
			}
			if !allowed {
				return invalid("certificate does not permit code signing")
			}
		case "2.5.29.30", "2.5.29.33", "2.5.29.36", "2.5.29.54":
			return unsupported("certificate path constraint " + e.ID.String())
		default:
			// Developer ID marker extensions are understood as membership
			// predicates only; they confer no trust without an Apple anchor.
			known := e.ID.String() == "1.2.840.113635.100.6.1.13" || e.ID.String() == "1.2.840.113635.100.6.1.18" || e.ID.String() == "1.2.840.113635.100.6.2.6"
			if known && !bytes.Equal(e.Value, []byte{5, 0}) {
				return malformed("Apple certificate marker")
			}
			if e.Critical && !known {
				return unsupported("critical certificate extension " + e.ID.String())
			}
		}
	}
	if ca && (!constraints.CA || c.tbs.Version != 2 || constraints.PathLen >= 0 && below > constraints.PathLen) {
		return invalid("certificate CA or path length constraint")
	}
	return nil
}

// VerifyCertificateChain constructs a bounded path from leaf through untrusted
// intermediates to an exact DER root supplied by the caller. It validates every
// link, time, CA/path-length, key usage and code-signing EKU. It never fetches
// issuers or consults the OS. Names must match in DER. Unsupported constraints
// and weak/unknown link algorithms fail closed. Zero at uses the current time.
func VerifyCertificateChain(leaf []byte, intermediates, roots [][]byte, at time.Time) (*CertificateChain, error) {
	if len(roots) == 0 {
		return nil, ErrUntrusted
	}
	if len(intermediates)+len(roots) > 64 {
		return nil, malformed("certificate pool limit")
	}
	c, err := parseCertificate(leaf)
	if err != nil {
		return nil, err
	}
	if at.IsZero() {
		at = time.Now()
	}
	if err := certificatePolicy(c, at, false, 0); err != nil {
		return nil, err
	}
	var pool []*certificate
	anchors := map[string]bool{}
	for _, root := range roots {
		anchors[string(root)] = true
	}
	seen := map[string]bool{string(leaf): true}
	for _, der := range append(append([][]byte(nil), roots...), intermediates...) {
		if seen[string(der)] {
			continue
		}
		seen[string(der)] = true
		p, err := parseCertificate(der)
		if err != nil {
			return nil, err
		}
		pool = append(pool, p)
	}
	visits := 0
	var search func([]*certificate, int) ([]*certificate, error)
	search = func(path []*certificate, below int) ([]*certificate, error) {
		visits++
		if visits > 256 || len(path) > 32 {
			return nil, malformed("certificate path search limit")
		}
		last := path[len(path)-1]
		if anchors[string(last.raw)] {
			if err := certificatePolicy(last, at, true, below); err != nil {
				return nil, err
			}
			return path, nil
		}
		reason := ErrUntrusted
		for _, parent := range pool {
			if !bytes.Equal(last.tbs.Issuer.FullBytes, parent.tbs.Subject.FullBytes) {
				continue
			}
			cycle := false
			for _, p := range path {
				cycle = cycle || bytes.Equal(p.raw, parent.raw)
			}
			if cycle {
				continue
			}
			if err := certificateSignature(last, parent); err != nil {
				reason = err
				continue
			}
			nextBelow := below
			if len(path) > 1 && !bytes.Equal(last.tbs.Subject.FullBytes, last.tbs.Issuer.FullBytes) {
				nextBelow++
			}
			// The parent's constraint counts non-self-issued CAs below it.
			if err := certificatePolicy(parent, at, true, nextBelow); err != nil {
				reason = err
				continue
			}
			result, err := search(append(append([]*certificate(nil), path...), parent), nextBelow)
			if err == nil {
				return result, nil
			}
			reason = err
		}
		return nil, reason
	}
	path, err := search([]*certificate{c}, 0)
	if err != nil {
		return nil, err
	}
	return describeChain(path)
}

func describeChain(path []*certificate) (*CertificateChain, error) {
	out := &CertificateChain{}
	for _, c := range path {
		info, err := certificateInfo(c)
		if err != nil {
			return nil, err
		}
		out.Certificates = append(out.Certificates, bytes.Clone(c.raw))
		out.Authorities = append(out.Authorities, info)
	}
	if appleDeveloper(path) {
		out.TeamID = out.Authorities[0].OrganizationalUnit
	}
	return out, nil
}

// The hashes are of Apple's public DER roots, obtained from Apple PKI. Caller
// trust anchors with Apple-like subjects or extensions cannot become Apple CAs.
func appleAnchor(path []*certificate) bool {
	if len(path) == 0 {
		return false
	}
	sum := sha256.Sum256(path[len(path)-1].raw)
	switch hex.EncodeToString(sum[:]) {
	case "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024", "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050", "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179":
		return true
	}
	return false
}

func appleDeveloper(path []*certificate) bool {
	if !appleAnchor(path) {
		return false
	}
	for _, suffix := range []string{"2", "12", "7", "4"} {
		if extension(path[0], "1.2.840.113635.100.6.1."+suffix) != nil {
			return true
		}
	}
	return len(path) > 1 && extension(path[0], "1.2.840.113635.100.6.1.13") != nil && extension(path[1], "1.2.840.113635.100.6.2.6") != nil
}

func checkTeamID(path []*certificate, team string) error {
	if appleDeveloper(path) {
		want, err := subjectAttribute(path[0], "2.5.4.11")
		if err != nil {
			return err
		}
		if team != "" && team != want {
			return invalid("Team ID does not match signing certificate")
		}
	}
	return nil
}

// linkedCertificates orders the supplied CMS/identity certificates using actual
// signatures. It is for display/leaf-pinned verification, not CA trust. Ambiguous
// issuers fail closed instead of allowing SET ordering to select an authority.
func linkedCertificates(leaf []byte, certs [][]byte) ([]*certificate, error) {
	c, err := parseCertificate(leaf)
	if err != nil {
		return nil, err
	}
	path := []*certificate{c}
	if len(certs) > 32 {
		return nil, malformed("certificate chain limit")
	}
	for len(path) <= 32 {
		last := path[len(path)-1]
		if bytes.Equal(last.tbs.Issuer.FullBytes, last.tbs.Subject.FullBytes) {
			return path, nil
		}
		var parent *certificate
		for _, raw := range certs {
			p, err := parseCertificate(raw)
			if err != nil {
				return nil, err
			}
			if certificateSignature(last, p) != nil {
				continue
			}
			if err := certificatePolicy(p, p.tbs.Validity.NotBefore, true, max(0, len(path)-1)); err != nil {
				return nil, err
			}
			if parent != nil && !bytes.Equal(parent.raw, p.raw) {
				return nil, unsupported("ambiguous certificate chain")
			}
			parent = p
		}
		if parent == nil {
			return path, nil
		}
		for _, p := range path {
			if bytes.Equal(p.raw, parent.raw) {
				return nil, invalid("certificate chain cycle")
			}
		}
		path = append(path, parent)
	}
	return nil, fmt.Errorf("%w: certificate chain length", ErrFormat)
}
