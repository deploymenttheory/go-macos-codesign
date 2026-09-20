// Package cli contains command parsing and presentation only.
package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const usage = `Usage: macoscodesign -s identity [-fv*] [-o flags] [-r reqs] [-i ident] path ... # sign
       macoscodesign -v [-v*] [-R=<req string>|-R <req file path>] path ... # verify
       macoscodesign -d [options] path ... # display contents
       macoscodesign --remove-signature path ...
`

type options struct {
	entitlements                                                                         string
	forceLibrary                                                                         bool
	runtimeVersion                                                                       uint32
	operation                                                                            string
	identity, identifier, architecture, requirements, testRequirement, config, timestamp string
	keyFile, trustFile                                                                   string
	trustRootFile, passwordFile                                                          string
	timestampRootFile                                                                    string
	timestampTimeout                                                                     time.Duration
	force, continueOnError, dryrun, json                                                 bool
	deep                                                                                 bool
	verbose                                                                              int
	flags, pageSize                                                                      uint32
	paths                                                                                []string
}

type argumentError struct {
	error
	code int
}

// Run executes an isolated Cobra command. It is safe to call repeatedly in tests.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	code := 0
	cmd := &cobra.Command{Use: "macoscodesign", SilenceErrors: true, SilenceUsage: true, DisableFlagParsing: true,
		RunE: func(_ *cobra.Command, argv []string) error {
			if len(argv) == 1 && argv[0] == "--help" {
				fmt.Fprint(stdout, usage)
				fmt.Fprintln(stdout, "\nPortable extensions: --config FILE, --json, --help, --key FILE, --trust FILE, --trust-root FILE, --password-file FILE.\nCertificate signing: -s IDENTITY.pem, -s CERTIFICATE.pem --key KEY.pem, or -s IDENTITY.p12 --password-file FILE.\nVerification requires --trust CERTIFICATE.pem (exact leaf pin) or --trust-root CA.pem (portable chain policy).\nNative -h is hosting, not help.")
				fmt.Fprintln(stdout, "Timestamp signing: --timestamp (Apple TSA) or --timestamp=http://URL. Optional --timestamp-root CA.pem and --timestamp-timeout 15s.\nTimestamp verification requires --timestamp-root CA.pem or --timestamp-root apple (bundled Apple roots).")
				fmt.Fprintln(stdout, "Bundles: --deep signs or verifies nested Mach-O helpers/dylibs and Contents-based APPL .app children; framework/plugin layouts remain unsupported.")
				return nil
			}
			opts, err := parse(argv)
			if err != nil {
				code = 2
				var argument *argumentError
				if errors.As(err, &argument) {
					code = argument.code
				}
				return err
			}
			if err = configure(&opts); err != nil {
				code = 2
				return err
			}
			if opts.operation == "" || len(opts.paths) == 0 {
				code = 2
				fmt.Fprint(stderr, usage)
				return nil
			}
			code = execute(ctx, opts, stdout, stderr)
			return nil
		}}
	cmd.SetIn(stdin)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs(args)
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(stderr, "macoscodesign:", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func configure(o *options) error {
	v := viper.New()
	v.SetEnvPrefix("MACOSCODESIGN")
	_ = v.BindEnv("config")
	if o.config == "" {
		o.config = v.GetString("config")
	}
	if o.config == "" {
		return nil
	}
	v.SetConfigFile(o.config)
	if err := v.ReadInConfig(); err != nil {
		return err
	}
	// Only portable presentation extensions are configurable. Native operation
	// and signature defaults are always determined by the invocation.
	if !o.json {
		o.json = v.GetBool("json")
	}
	return nil
}

func parse(args []string) (options, error) {
	o := options{}
	setOperation := func(op string) error {
		if o.operation != "" && o.operation != op {
			return fmt.Errorf("conflicting operations")
		}
		o.operation = op
		return nil
	}
	value := func(i *int, attached string) (string, error) {
		if attached != "" {
			return strings.TrimPrefix(attached, "="), nil
		}
		*i++
		if *i >= len(args) {
			return "", fmt.Errorf("option requires an argument")
		}
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			o.paths = append(o.paths, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			o.paths = append(o.paths, a)
			continue
		}
		if strings.HasPrefix(a, "--") {
			name, attached, has := strings.Cut(a[2:], "=")
			var val string
			var err error
			switch name {
			case "sign", "identifier", "architecture", "requirements", "test-requirement", "options", "pagesize", "config", "entitlements", "runtime-version", "key", "trust", "trust-root", "password-file", "timestamp-root", "timestamp-timeout":
				if has {
					val = attached
				} else {
					val, err = value(&i, "")
				}
				if err != nil {
					return o, err
				}
				switch name {
				case "sign":
					err = setOperation("sign")
					o.identity = val
				case "identifier":
					o.identifier = val
				case "architecture":
					o.architecture = val
				case "requirements":
					o.requirements = val
				case "test-requirement":
					if has {
						o.testRequirement = val
					} else {
						o.testRequirement = "@" + val
					}
				case "options":
					o.flags, err = parseFlags(val)
				case "pagesize":
					var n uint64
					n, err = strconv.ParseUint(val, 0, 32)
					o.pageSize = uint32(n)
				case "config":
					o.config = val
				case "entitlements":
					o.entitlements = val
				case "runtime-version":
					o.runtimeVersion, err = parseVersion(val)
				case "key":
					o.keyFile = val
				case "trust":
					o.trustFile = val
				case "trust-root":
					o.trustRootFile = val
				case "timestamp-root":
					o.timestampRootFile = val
				case "timestamp-timeout":
					o.timestampTimeout, err = time.ParseDuration(val)
					if err == nil && o.timestampTimeout <= 0 {
						err = fmt.Errorf("timestamp timeout must be positive")
					}
				case "password-file":
					o.passwordFile = val
				}
			case "display":
				err = setOperation("display")
			case "verify":
				err = setOperation("verify")
			case "remove-signature":
				err = setOperation("remove")
			case "force":
				o.force = true
			case "continue":
				o.continueOnError = true
			case "dryrun":
				o.dryrun = true
			case "deep":
				o.deep = true
			case "json":
				o.json = true
			case "verbose":
				if has {
					o.verbose, err = strconv.Atoi(attached)
				} else {
					o.verbose++
				}
			case "timestamp":
				o.timestamp = attached
				if !has {
					o.timestamp = codesign.AppleTimestampURL
				}
				if o.timestamp != "none" {
					if _, err = codesign.NewHTTPTimestampExchange(o.timestamp, 0); err != nil {
						return o, &argumentError{error: err, code: 1}
					}
				}
			case "all-architectures":
			case "generate-entitlement-der":
			case "force-library-entitlements":
				o.forceLibrary = true
			default:
				return o, fmt.Errorf("%w: --%s", codesign.ErrUnsupported, name)
			}
			if err != nil {
				return o, err
			}
			continue
		}
		for j := 1; j < len(a); j++ {
			var err error
			switch a[j] {
			case 'f':
				o.force = true
			case 'v':
				o.verbose++
			case 'd':
				err = setOperation("display")
			case 'h':
				return o, fmt.Errorf("%w: live process hosting requires unavailable macOS state", codesign.ErrUnsupported)
			case 's', 'i', 'a', 'r', 'R', 'o', 'P':
				flag := a[j]
				attached := a[j+1:]
				var val string
				val, err = value(&i, attached)
				j = len(a)
				if err == nil {
					switch flag {
					case 's':
						err = setOperation("sign")
						o.identity = val
					case 'i':
						o.identifier = val
					case 'a':
						o.architecture = val
					case 'r':
						o.requirements = val
						if strings.HasPrefix(attached, "=") {
							o.requirements = "=" + val
						}
					case 'R':
						if strings.HasPrefix(attached, "=") {
							o.testRequirement = val
						} else {
							o.testRequirement = "@" + val
						}
					case 'o':
						o.flags, err = parseFlags(val)
					case 'P':
						var n uint64
						n, err = strconv.ParseUint(val, 0, 32)
						o.pageSize = uint32(n)
					}
				}
			default:
				err = fmt.Errorf("unrecognized option -%c", a[j])
			}
			if err != nil {
				return o, err
			}
		}
	}
	if o.operation == "" && o.verbose > 0 {
		o.operation = "verify"
		o.verbose--
	}
	return o, nil
}

func parseFlags(s string) (uint32, error) {
	if n, err := strconv.ParseUint(s, 0, 32); err == nil {
		return uint32(n), nil
	}
	var flags uint32
	for _, v := range strings.Split(s, ",") {
		switch v {
		case "none":
		case "adhoc":
			flags |= 2
		case "hard":
			flags |= 0x100
		case "kill":
			flags |= 0x200
		case "expires":
			flags |= 0x400
		case "restrict":
			flags |= 0x800
		case "enforcement":
			flags |= 0x1000
		case "library":
			flags |= 0x2000
		case "runtime":
			flags |= 0x10000
		case "linker-signed":
			flags |= 0x20000
		default:
			return 0, fmt.Errorf("unknown option flag %q", v)
		}
	}
	return flags, nil
}

func execute(ctx context.Context, o options, stdout, stderr io.Writer) int {
	signOpts := codesign.SignOptions{Identifier: o.identifier, Force: o.force, Deep: o.deep, DryRun: o.dryrun, Flags: o.flags, PageSize: o.pageSize, ForceLibraryEntitlements: o.forceLibrary, RuntimeVersion: o.runtimeVersion}
	if (o.keyFile != "" || o.passwordFile != "") && (o.operation != "sign" || o.identity == "-") || (o.trustFile != "" || o.trustRootFile != "") && o.operation != "verify" || o.passwordFile != "" && o.keyFile != "" {
		fmt.Fprintln(stderr, "macoscodesign: --key/--password-file require certificate signing and are mutually exclusive; --trust/--trust-root require verification")
		return 2
	}
	requestTimestamp := o.operation == "sign" && o.identity != "-" && o.timestamp != "" && o.timestamp != "none"
	if o.timestampRootFile != "" && o.operation != "verify" && !requestTimestamp || o.timestampTimeout != 0 && !requestTimestamp {
		fmt.Fprintln(stderr, "macoscodesign: --timestamp-root requires verification or timestamped certificate signing; --timestamp-timeout requires timestamped certificate signing")
		return 2
	}
	var trusted [][]byte
	if o.trustFile != "" {
		data, err := os.ReadFile(o.trustFile)
		if err == nil {
			trusted, err = codesign.ParseCertificatesPEM(data)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	var roots [][]byte
	if o.trustRootFile != "" {
		data, err := os.ReadFile(o.trustRootFile)
		if err == nil {
			roots, err = codesign.ParseCertificatesPEM(data)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	var timestampRoots [][]byte
	if o.timestampRootFile == "apple" || requestTimestamp && o.timestampRootFile == "" {
		timestampRoots = codesign.AppleTimestampRoots()
	} else if o.timestampRootFile != "" {
		data, err := os.ReadFile(o.timestampRootFile)
		if err == nil {
			timestampRoots, err = codesign.ParseCertificatesPEM(data)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if requestTimestamp {
		exchange, err := codesign.NewHTTPTimestampExchange(o.timestamp, o.timestampTimeout)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		signOpts.Timestamp = &codesign.TimestampOptions{TrustedRoots: timestampRoots, Provider: func(ctx context.Context, signature []byte) ([]byte, error) {
			return codesign.AcquireTimestamp(ctx, signature, exchange, timestampRoots, time.Time{})
		}}
	}
	if o.entitlements != "" && o.operation == "sign" {
		var err error
		signOpts.Entitlements, err = os.ReadFile(o.entitlements)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if bytes.HasPrefix(signOpts.Entitlements, []byte("bplist")) || !utf8.Valid(signOpts.Entitlements) {
			fmt.Fprintln(stderr, "Could not create string from entitlements data")
			return 1
		}
	}
	if o.operation == "sign" && o.identity != "-" {
		certs, err := os.ReadFile(o.identity)
		var key []byte
		if err == nil && o.keyFile != "" {
			key, err = os.ReadFile(o.keyFile)
		}
		if err == nil {
			if bytes.HasPrefix(bytes.TrimSpace(certs), []byte("-----BEGIN")) {
				if o.passwordFile != "" {
					err = fmt.Errorf("--password-file requires a PKCS#12 identity")
				} else {
					signOpts.Identity, err = codesign.LoadIdentityPEM(certs, key)
				}
			} else if o.keyFile != "" {
				err = fmt.Errorf("--key requires a PEM identity")
			} else {
				var password []byte
				if o.passwordFile != "" {
					password, err = os.ReadFile(o.passwordFile)
				}
				if err == nil {
					signOpts.Identity, err = codesign.LoadIdentityPKCS12(certs, strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r"))
				}
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "macoscodesign:", err)
			return 1
		}
	}
	if o.requirements != "" && o.operation != "sign" {
		fmt.Fprintln(stderr, "macoscodesign: unsupported operation: requirements extraction")
		return 1
	}
	if o.operation == "sign" && o.requirements != "" {
		text := o.requirements
		if !strings.HasPrefix(text, "=") {
			data, err := os.ReadFile(text)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			text = string(data)
		} else {
			text = strings.TrimPrefix(text, "=")
		}
		var err error
		signOpts.Requirements, err = codesign.RequirementsBytes([]byte(text))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if strings.HasPrefix(o.testRequirement, "@") {
		b, err := os.ReadFile(o.testRequirement[1:])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		o.testRequirement = string(b)
	}
	status := 0
	for _, path := range o.paths {
		var err error
		switch o.operation {
		case "sign":
			err = codesign.Sign(ctx, path, signOpts)
		case "remove":
			err = codesign.RemoveSignature(ctx, path)
		case "verify":
			var report *codesign.Report
			report, err = codesign.Verify(ctx, path, codesign.VerifyOptions{Deep: o.deep, Architecture: o.architecture, Requirement: o.testRequirement, TrustedCertificates: trusted, TrustedRoots: roots, TimestampRoots: timestampRoots})
			if o.json && report != nil {
				if e := json.NewEncoder(stdout).Encode(report); e != nil {
					err = e
				}
			}
			if err == nil && o.verbose > 0 {
				fmt.Fprintf(stderr, "%s: valid on disk\n%s: satisfies its Designated Requirement\n", path, path)
			}
		case "display":
			var report *codesign.Report
			report, err = codesign.Inspect(ctx, path)
			if err == nil {
				if o.entitlements != "" {
					err = extractEntitlements(stdout, report, o)
					break
				}
				if o.json {
					err = json.NewEncoder(stdout).Encode(report)
				} else {
					err = display(stderr, report, o)
				}
			}
		}
		if err != nil {
			fmt.Fprintf(stderr, "%s: %s\n", path, diagnostic(err))
			if errors.Is(err, codesign.ErrRequirement) && status == 0 {
				status = 3
			} else if !errors.Is(err, codesign.ErrRequirement) {
				status = 1
			}
			if o.operation != "verify" && !o.continueOnError {
				break
			}
		}
	}
	return status
}

func parseVersion(s string) (uint32, error) {
	parts := strings.Split(s, ".")
	if len(parts) > 3 || len(parts) == 0 {
		return 0, fmt.Errorf("invalid runtime version")
	}
	var v uint32
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || i > 0 && n > 255 {
			return 0, fmt.Errorf("invalid runtime version")
		}
		v |= uint32(n) << uint(16-i*8)
	}
	return v, nil
}

func extractEntitlements(w io.Writer, r *codesign.Report, o options) error {
	for _, a := range r.Architectures {
		if o.architecture != "" && o.architecture != a.Name {
			continue
		}
		if a.Signature == nil {
			return codesign.ErrUnsigned
		}
		for _, b := range a.Signature.Blobs {
			if b.Slot == codesign.SlotEntitlements {
				if o.entitlements == "-" || o.entitlements == ":-" {
					_, err := w.Write(b.Data[8:])
					return err
				}
				return os.WriteFile(o.entitlements, b.Data[8:], 0600)
			}
		}
		return nil
	}
	return fmt.Errorf("architecture not found")
}

func diagnostic(err error) string {
	switch {
	case errors.Is(err, codesign.ErrDesignatedRequirement):
		return "does not satisfy its designated Requirement"
	case errors.Is(err, codesign.ErrUnsigned):
		return codesign.ErrUnsigned.Error()
	case errors.Is(err, codesign.ErrSigned):
		return codesign.ErrSigned.Error()
	case errors.Is(err, codesign.ErrRequirement):
		return codesign.ErrRequirement.Error()
	default:
		return err.Error()
	}
}

func display(w io.Writer, r *codesign.Report, o options) error {
	var out bytes.Buffer
	if err := renderDisplay(&out, r, o); err != nil {
		return err
	}
	_, err := w.Write(out.Bytes())
	return err
}

func renderDisplay(w io.Writer, r *codesign.Report, o options) error {
	var selected *codesign.Architecture
	for i := range r.Architectures {
		a := &r.Architectures[i]
		if o.architecture != "" {
			if a.Name == o.architecture {
				selected = a
				break
			}
		} else if selected == nil || a.Name == "arm64" {
			selected = a
		}
	}
	if selected == nil {
		return fmt.Errorf("architecture %q not present", o.architecture)
	}
	if selected.Signature == nil {
		return codesign.ErrUnsigned
	}
	d := selected.Signature.Directories[0]
	executable := r.Path
	if r.Bundle != nil {
		executable = r.Bundle.Executable
	}
	path, err := filepath.Abs(executable)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Executable=%s\n", path)
	if o.verbose == 0 {
		return nil
	}
	names := make([]string, len(r.Architectures))
	for i, a := range r.Architectures {
		names[i] = a.Name
	}
	format := r.Format
	if r.Format != "disk image" {
		format += " (" + strings.Join(names, " ") + ")"
	}
	fmt.Fprintf(w, "Identifier=%s\nFormat=%s\nCodeDirectory v=%x size=%d flags=0x%x(%s) hashes=%d+%d location=embedded\n", d.Identifier, format, d.Version, len(d.Raw), d.Flags, flagNames(d.Flags), d.CodeSlots, d.SpecialSlots)
	if o.verbose >= 4 && selected.VersionPlatform != 0 {
		fmt.Fprintf(w, "VersionPlatform=%d\nVersionMin=%d\nVersionSDK=%d\n", selected.VersionPlatform, selected.VersionMin, selected.VersionSDK)
	}
	if o.verbose >= 3 {
		fmt.Fprintf(w, "Hash type=%s size=%d\nCandidateCDHash %s=%s\n", hashName(d.HashType), d.HashSize, hashName(d.HashType), d.CDHash)
	}
	if o.verbose >= 3 {
		fmt.Fprintf(w, "CandidateCDHashFull %s=%s\n", hashName(d.HashType), d.FullHash)
	}
	if o.verbose >= 3 {
		fmt.Fprintf(w, "Hash choices=%s\nCMSDigest=%s\nCMSDigestType=%d\n", hashName(d.HashType), d.FullHash, d.HashType)
	}
	if o.verbose >= 4 && d.ExecLimit > 0 {
		fmt.Fprintf(w, "Executable Segment base=%d\nExecutable Segment limit=%d\nExecutable Segment flags=0x%x\n", d.ExecBase, d.ExecLimit, d.ExecFlags)
	}
	if o.verbose >= 4 {
		if d.PageExponent == 0 {
			fmt.Fprintln(w, "Page size=none")
		} else {
			fmt.Fprintf(w, "Page size=%d\n", uint64(1)<<d.PageExponent)
		}
	}
	if o.verbose >= 3 {
		fmt.Fprintf(w, "CDHash=%s\n", d.CDHash)
	}
	if d.Flags&codesign.FlagAdhoc != 0 {
		fmt.Fprintln(w, "Signature=adhoc")
	} else {
		for _, b := range selected.Signature.Blobs {
			if b.Slot == codesign.SlotCMS {
				fmt.Fprintf(w, "Signature size=%d\n", len(b.Data)-8)
			}
		}
		metadata := selected.Signature.CertificateMetadata
		if metadata == nil {
			fmt.Fprintln(w, "Authority=(unavailable)")
		} else {
			for _, cert := range metadata.Authorities {
				fmt.Fprintf(w, "Authority=%s\n", cert.CommonName)
			}
			if metadata.Timestamp != nil {
				fmt.Fprintf(w, "Timestamp=%s\n", metadata.Timestamp.Time.UTC().Format("2 Jan 2006 at 15:04:05"))
			} else if !metadata.SigningTime.IsZero() {
				fmt.Fprintf(w, "Signed Time=%s\n", metadata.SigningTime.UTC().Format("2 Jan 2006 at 15:04:05"))
			}
		}
	}
	if r.Bundle == nil {
		fmt.Fprintln(w, "Info.plist=not bound")
	} else {
		fmt.Fprintf(w, "Info.plist entries=%d\n", r.Bundle.InfoEntries)
	}
	team := d.TeamID
	if team == "" {
		team = "not set"
	}
	fmt.Fprintf(w, "TeamIdentifier=%s\n", team)
	if d.Runtime != 0 {
		fmt.Fprintf(w, "Runtime Version=%d.%d.%d\n", d.Runtime>>16, d.Runtime>>8&255, d.Runtime&255)
	}
	if r.Bundle == nil || r.Bundle.ResourceVersion == 0 {
		fmt.Fprintln(w, "Sealed Resources=none")
	} else {
		fmt.Fprintf(w, "Sealed Resources version=%d rules=%d files=%d\n", r.Bundle.ResourceVersion, r.Bundle.ResourceRules, r.Bundle.ResourceFiles)
	}
	for _, b := range selected.Signature.Blobs {
		if b.Slot == codesign.SlotRequirements && len(b.Data) >= 12 {
			fmt.Fprintf(w, "Internal requirements count=%d size=%d\n", binary.BigEndian.Uint32(b.Data[8:]), len(b.Data))
		}
	}
	if o.verbose >= 2 {
		fmt.Fprintln(w, "Total signatures=1\nChosen signature=1")
	}
	return nil
}
func hashName(v uint8) string {
	switch v {
	case 1:
		return "sha1"
	case 2, 3:
		return "sha256"
	case 4:
		return "sha384"
	default:
		return "unknown"
	}
}
func flagNames(flags uint32) string {
	var out []string
	for _, v := range []struct {
		bit  uint32
		name string
	}{{2, "adhoc"}, {0x100, "hard"}, {0x200, "kill"}, {0x400, "expires"}, {0x800, "restrict"}, {0x1000, "enforcement"}, {0x2000, "library-validation"}, {0x10000, "runtime"}, {0x20000, "linker-signed"}} {
		if flags&v.bit != 0 {
			out = append(out, v.name)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ",")
}
