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
	// Deep signs supported nested Mach-O files and APPL apps before sealing
	// their parent, from the deepest children outwards.
	// Existing child signatures, except linker signatures, are retained unless
	// Force is also set.
	Deep bool
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
	// Timestamp obtains and validates an RFC 3161 token for each Mach-O
	// architecture or for the single UDIF signature.
	// DryRun still calls the provider because it constructs complete signatures.
	Timestamp *TimestampOptions
	teamID    string
}

// VerifyOptions selects an architecture and optional external special-slot data.
// Certificate-backed signatures are not reported valid until CMS verification succeeds.
type VerifyOptions struct {
	// Deep checks nested code pages, resource envelopes and descendants.
	// Without it, immediate child signatures, signed non-resource metadata and
	// the parent's requirements are checked, matching Apple.
	Deep         bool
	Architecture string
	InfoPlist    []byte
	Resources    []byte
	Requirement  string
	// TrustedCertificates pins complete DER leaf certificates. It does not
	// accept CA anchors or consult a system trust store. A matching pin or
	// a valid path to TrustedRoots is required; ad-hoc signatures do not use it.
	TrustedCertificates [][]byte
	// TrustedRoots enables portable CA path validation in addition to leaf pins.
	// No system trust, revocation lookup or network issuer fetching is performed.
	TrustedRoots [][]byte
	// TimestampRoots separately anchors RFC 3161 TSA chains. A timestamp that
	// is present must validate; it is never silently ignored or treated as trust
	// merely because the code-signing certificate was pinned.
	TimestampRoots [][]byte
	// CurrentTime controls certificate validity checks. An authenticated,
	// explicitly trusted timestamp selects genTime instead and must not be in
	// the future relative to CurrentTime. Zero uses time.Now.
	CurrentTime   time.Time
	directoryOnly bool // internal shallow nested-code validation, never a public bypass
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
	chain        []*certificate
}

type Signature struct {
	Length      uint32
	Blobs       []Blob
	Directories []Directory
	// CertificateMetadata is descriptive; inspection never sets Report.Valid.
	CertificateMetadata *CertificateMetadata `json:",omitempty"`
}

// CertificateMetadata describes CMS data whose cryptographic binding has been
// checked, without asserting CA trust or a trusted signing timestamp.
type CertificateMetadata struct {
	Authorities []CertificateInfo
	SigningTime time.Time
	Timestamp   *TimestampInfo `json:",omitempty"`
}

// Architecture contains one observed signature. For Mach-O it represents a
// slice; for UDIF the architecture-independent image is named "dmg".
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
	Bundle        *BundleInfo `json:",omitempty"`
	Architectures []Architecture
	Valid         bool
	repSpecific   []byte
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, args...))
}
func unsupported(feature string) error { return fmt.Errorf("%w: %s", ErrUnsupported, feature) }
