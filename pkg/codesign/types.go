// Package codesign reads, signs and verifies Apple code signatures without
// invoking platform tools or using Apple security services.
package codesign

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
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

// PathOptions selects the physical version of a versioned framework. Empty or
// "Current" follows Versions/Current. Contents bundles and non-bundle inputs
// ignore BundleVersion; unversioned frameworks and direct version directories
// reject explicit selection. Selection applies only to the input bundle, never
// to its nested frameworks.
type PathOptions struct {
	BundleVersion string
}

// RemoveOptions selects a bundle version and explicitly supplied metadata.
// Generic files remove their signature attributes in place. AppleDouble inputs
// supplement native attributes and must implement MutableAppleDouble when a
// signature attribute is present. Bundle bindings follow VerifyOptions rules.
// Mach-O signatures remain embedded; their attached metadata is not removed.
type RemoveOptions struct {
	BundleVersion    string
	AppleDouble      appledouble.Value
	AppleDoubleFiles map[string]appledouble.Value
}

// SignOptions controls the signed representation. A nil Identity requests ad-hoc signing.
type SignOptions struct {
	// MacOSProfile selects versioned signing behavior on every host. Zero uses
	// the macOS 27 reference. This covers signature reservation, default signing
	// page size and resource preflight ordering, not complete OS compatibility.
	MacOSProfile osversion.MacOSProfile
	// BundleVersion has the same meaning as PathOptions.BundleVersion.
	BundleVersion string
	// PreserveAFSC requests recompression after replacing a compressed file.
	// Queue rejection can fail after the signed replacement has been committed.
	PreserveAFSC bool
	Identifier   string
	Force        bool
	// NoStrict disables signing preflight metadata rejection and code-object
	// stripping. Explicit stripping of included ordinary resources still runs.
	NoStrict bool
	// StripDisallowedXattrs removes nonempty ResourceFork and FinderInfo values
	// before signing preflight. Removals also occur during DryRun and are not
	// rolled back after subsequent failures. UDIF ignores this option.
	StripDisallowedXattrs bool
	// AppleDouble and AppleDoubleFiles explicitly supplement native metadata,
	// with the same binding rules as VerifyOptions. For stripping, a carrier
	// containing prohibited data must implement MutableAppleDouble. Carriers
	// are never automatically discovered or restored onto the host filesystem.
	AppleDouble      appledouble.Value
	AppleDoubleFiles map[string]appledouble.Value
	// OnReplace is called synchronously by Sign when Force selects an existing,
	// readable signature on the top-level input, before signature construction.
	// It is a notice of an attempted replacement, not a success notification, and
	// also applies to dry runs. Nested signatures and SignBytes do not call it.
	// The callback must not modify the input or signing options.
	OnReplace func()
	// Deep signs supported nested Mach-O files, apps, plug-ins and frameworks before sealing
	// their parent, from the deepest children outwards.
	// Existing child signatures, except linker signatures, are retained unless
	// Force is also set.
	Deep bool
	// DryRun checks a Mach-O or bundle without committing signature bytes. For
	// path-based ad-hoc DMG signing, native codesign instead writes components
	// without a CodeDirectory in place, leaving the image unsigned (also replacing
	// an existing signature with Force). Certificate DMG dry runs are unsupported.
	// SignBytes ignores this path-only option and returns a complete signature.
	DryRun                   bool
	Flags                    uint32
	PageSize                 uint32
	Entitlements             []byte
	ForceLibraryEntitlements bool
	// Requirements is an optional compiled set, copied and repacked by kind.
	// Certificate signing inserts a default designated requirement when kind 3
	// is absent, including in an explicitly empty set. Supplied expressions are
	// preserved, not evaluated during signing. Input and output sets are limited
	// to 1 MiB and 64 entries. Representation-specific defaults remain unsupported.
	Requirements   []byte
	InfoPlist      []byte
	Resources      []byte
	Identity       *Identity
	RuntimeVersion uint32
	// SigningTime is the CMS signing-time claim. Zero uses the current time.
	// It is not an RFC 3161 timestamp.
	SigningTime time.Time
	// Timestamp obtains and validates an RFC 3161 token for each Mach-O
	// architecture or for the single UDIF signature.
	// Mach-O/bundle dry runs still call the provider to construct signatures.
	// Certificate DMG path dry runs are rejected before calling the provider.
	Timestamp *TimestampOptions
	teamID    string
}

// MutableAppleDouble permits signing and removal to remove an attribute from an
// explicit AppleDouble input. Each removal must preserve unrelated values,
// update subsequent reads and report errors. The caller owns its lifetime.
type MutableAppleDouble interface {
	appledouble.Value
	RemoveAttribute(context.Context, string) error
}

// VerifyOptions selects an architecture and optional external special-slot data.
// Certificate-backed signatures are not reported valid until CMS verification succeeds.
type VerifyOptions struct {
	// IgnoreResources skips the resource-directory binding, resource traversal
	// and parent-sealed nested-code checks, including when Deep is set. Code
	// pages, CMS/trust, non-resource slots, requirements and enabled structural
	// policies are still checked. A successful report marks ResourcesIgnored.
	IgnoreResources bool
	// NoStrict disables the additional native layout, symlink and sideband policies.
	// Cryptographic verification and safe parsing remain required; resource seals
	// are still checked unless IgnoreResources is also set.
	NoStrict bool
	// StrictSymlinks requires sealed resource links to resolve to included
	// resources in this bundle or its verification parents. Absolute targets
	// must resolve inside /System or /Library on the verifying host. It does
	// not enable sideband-attribute checks or the complete --strict=all policy.
	StrictSymlinks bool
	// StrictSideband rejects nonempty ResourceFork and FinderInfo metadata on
	// Mach-O inputs and applicable bundle code/resources. UDIF verification ignores
	// sideband data, matching Apple's DiskImageRep override. NoStrict disables it.
	// VerifyBytes cannot observe Mach-O metadata and rejects this option for it.
	StrictSideband bool
	// AppleDouble explicitly supplements native metadata on a standalone input.
	// The caller owns the stable source and its lifetime. It requires enabled
	// StrictSideband; it is not restored and no neighboring sidecar is inferred.
	// UDIF's native strict override does not inspect this input.
	AppleDouble appledouble.Value
	// AppleDoubleFiles explicitly binds additional snapshots to filesystem
	// objects. Keys are paths relative to the resolved operand (a bundle root),
	// or absolute paths. Symbolic and hard links bind to the same held object.
	// Use "." for a bundle root. Duplicate bindings to one object are rejected.
	// Sources are caller-owned, stable, and only decoded if policy visits them.
	// Native metadata remains additive. No neighboring sidecars are inferred.
	AppleDoubleFiles map[string]appledouble.Value
	// BundleVersion selects the input framework; nested frameworks check every
	// physical version against the parent's sealed requirement.
	BundleVersion string
	// Deep checks nested code pages, resource envelopes and descendants.
	// Without it, immediate child signatures, signed non-resource metadata and
	// the parent's requirements are checked, matching Apple.
	Deep         bool
	Architecture string
	InfoPlist    []byte
	Resources    []byte
	// Requirement is a caller-supplied predicate checked against the selected
	// code. Nested objects instead satisfy their parent's sealed requirement.
	Requirement string
	// CheckDesignatedRequirement additionally evaluates the stored designated
	// requirement. Ordinary verification validates its structure and binding,
	// but does not require it to match the object itself. Set this to retain the
	// pre-verification-policy API behavior; explicit certificate trust is unchanged.
	CheckDesignatedRequirement bool
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
	CurrentTime    time.Time
	directoryOnly  bool   // internal shallow nested-code validation, never a public bypass
	resourceBase   string // absolute resource base for nested verification diagnostics
	linkScope      *verificationLinkScope
	sidebandFile   *os.File // same held object used to read the signature bytes
	sidebandPath   string   // resolved standalone path for native diagnostics
	sidebandObject *bundleSidebandObject
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
	view         *directoryView
}

type Signature struct {
	Length      uint32
	Blobs       []Blob
	Directories []Directory
	// CertificateMetadata is descriptive; inspection never sets Report.Valid.
	CertificateMetadata *CertificateMetadata `json:",omitempty"`
	view                *signatureView
}

// CertificateMetadata describes CMS data whose cryptographic binding has been
// checked, without asserting CA trust or a trusted signing timestamp.
type CertificateMetadata struct {
	Authorities []CertificateInfo
	// Certificates contains owned DER copies in the same leaf-first order as
	// Authorities. It is descriptive CMS data, not a trust result. JSON reports
	// omit certificate bytes; callers can explicitly export them when needed.
	Certificates [][]byte `json:"-"`
	SigningTime  time.Time
	Timestamp    *TimestampInfo `json:",omitempty"`
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
	// ResourcesIgnored means Valid only describes the selected non-resource
	// verification policy; it does not attest the bundle's resources or children.
	ResourcesIgnored     bool `json:",omitempty"`
	repSpecific          []byte
	verifiedArchitecture string
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, args...))
}
func unsupported(feature string) error { return fmt.Errorf("%w: %s", ErrUnsupported, feature) }
