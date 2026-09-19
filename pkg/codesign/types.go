// Package codesign reads, signs and verifies Apple code signatures without
// invoking platform tools or using Apple security services.
package codesign

import (
	"crypto"
	"errors"
	"fmt"
	"time"
)

var (
	ErrFormat                = errors.New("unrecognized or malformed code")
	ErrUnsigned              = errors.New("code object is not signed at all")
	ErrInvalid               = errors.New("invalid signature")
	ErrSigned                = errors.New("is already signed")
	ErrUnsupported           = errors.New("unsupported operation")
	ErrUntrusted             = errors.New("signer certificate is not explicitly trusted")
	ErrRequirement           = errors.New("code failed to satisfy specified code requirement(s)")
	ErrDesignatedRequirement = fmt.Errorf("%w: does not satisfy its designated Requirement", ErrRequirement)
)

// Identity is an exportable signing key and its leaf-first DER certificate chain.
// Raw DER avoids importing a platform certificate verifier into the runtime.
type Identity struct {
	Signer       crypto.Signer
	Certificates [][]byte
}

// SignOptions controls the signed representation. A nil Identity requests ad-hoc signing.
type SignOptions struct {
	Identifier string
	Force      bool
	// DryRun constructs the signature and checks the input without writing path.
	DryRun                   bool
	Flags                    uint32
	PageSize                 uint32
	Entitlements             []byte
	ForceLibraryEntitlements bool
	Requirements             []byte
	InfoPlist                []byte
	Resources                []byte
	Identity                 *Identity
	RuntimeVersion           uint32
	// SigningTime is the CMS signing-time claim. Zero uses the current time.
	// It is not an RFC 3161 timestamp.
	SigningTime time.Time
}

// VerifyOptions selects an architecture and optional external special-slot data.
// Certificate-backed signatures are not reported valid until CMS verification succeeds.
type VerifyOptions struct {
	Architecture string
	InfoPlist    []byte
	Resources    []byte
	Requirement  string
	// TrustedCertificates pins complete DER leaf certificates. It does not
	// accept CA anchors or consult a system trust store. Certificate signatures
	// require a matching pin; ad-hoc signatures do not use this field.
	TrustedCertificates [][]byte
	// CurrentTime controls certificate validity checks. Zero uses time.Now.
	CurrentTime time.Time
}

// Blob retains the complete encoding, including its magic and length fields.
type Blob struct {
	Slot  uint32
	Magic uint32
	Data  []byte
}

// Directory is a decoded CodeDirectory. Raw is owned by the containing Signature.
type Directory struct {
	Version      uint32
	Flags        uint32
	Identifier   string
	TeamID       string
	HashType     uint8
	HashSize     uint8
	PageExponent uint8
	Platform     uint8
	CodeLimit    uint64
	CodeSlots    uint32
	SpecialSlots uint32
	HashOffset   uint32
	ExecBase     uint64
	ExecLimit    uint64
	ExecFlags    uint64
	Runtime      uint32
	CDHash       string
	FullHash     string
	Raw          []byte `json:"-"`
	certificate  []byte
}

type Signature struct {
	Length      uint32
	Blobs       []Blob
	Directories []Directory
}

// Architecture contains the observed signature of one Mach-O slice.
type Architecture struct {
	VersionPlatform uint32
	VersionMin      uint32
	VersionSDK      uint32
	Name            string
	CPU             uint32
	Subtype         uint32
	Offset          uint64
	Size            uint64
	SignatureOffset uint64
	SignatureSize   uint32
	Signature       *Signature
}

type Report struct {
	Path          string
	Format        string
	Architectures []Architecture
	Valid         bool
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, args...))
}
func unsupported(feature string) error { return fmt.Errorf("%w: %s", ErrUnsupported, feature) }
