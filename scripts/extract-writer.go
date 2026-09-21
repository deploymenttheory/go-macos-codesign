//go:build ignore

// Research only: parse Apple's complete file-mapping, metadata and writer functions.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, err := os.ReadFile(path); must(err); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(input, name string, args ...string) []byte {
	c := exec.Command(name, args...)
	c.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, err := c.Output()
	if err != nil {
		panic(fmt.Sprintf("%v: %s", err, stderr.String()))
	}
	return b
}

type node struct {
	Kind, Name, Opcode, MangledName string
	Value                           any
	Inner                           []node
	ReferencedDecl                  *node
}

func walk(n node, f func(node)) {
	f(n)
	for _, c := range n.Inner {
		walk(c, f)
	}
}

func main() {
	const revision = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
	const copyRevision = "9f91eb6ced021952278816cdc76ad68da8631ccb"
	copySource := read(".research/apple/copyfile.c")
	copyHeader := read(".research/apple/copyfile_private.h")
	source := read(".research/apple/signerutils.cpp")
	unit := `#include <string>
#include <cstdio>
#include <set>
#include <map>
#include <cstdint>
#include <cstdlib>
#include <mach/machine.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <os/overflow.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/clonefile.h>
#include <copyfile.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <cstring>
#include <CoreFoundation/CoreFoundation.h>
#include <TargetConditionals.h>
namespace CodesignWriterResearch {
using std::string;
struct UnixError { static void check(int); static void throwMe(); };
struct UidGuard { UidGuard(int = 0); bool seteuid(uid_t); };
struct Copyfile { void set(unsigned int, void*); void operator()(const char*, const char*, copyfile_flags_t); };
struct FD { void open(const string&, int); operator int(); void read(void*, size_t, off_t); void write(const void*, size_t, off_t); };
struct Writer { void component(int, CFDataRef); bool getPreserveAFSC(); void setPreserveAFSC(bool); void remove(); void flush(); };
struct Universal { Universal(FD&); };
struct cmpInfo { unsigned int compressionType; unsigned long long compressedSize; };
int queryCompressionInfo(const char*, cmpInfo*);
using CompressionQueueContext = void*;
CompressionQueueContext CreateCompressionQueue(void*, void*, void*, void*, CFDictionaryRef);
bool CompressFile(CompressionQueueContext, const char*, void*);
void FinishCompressionAndCleanUp(CompressionQueueContext);
extern CFStringRef kAFSCCompressionTypes;
void secinfo(const char*, const char*, ...);
struct MacOSError { static void throwMe(int); };
constexpr int errSecCSInternalError = -67050, errSecCSNotSupported = -67051;
constexpr int errSecCSBadBundleFormat = -67049, errSecCSUnsealedAppRoot = -67048;
enum {cdResourceDirSlot=3, cdSlotCount=12, cdSignatureSlot=0x10000, writerLastResort=1};
struct CodeDirectory { using SpecialSlot=int; static const char* canonicalSlotName(int); };
struct ExecWriter { bool attribute(int); void component(int, CFDataRef); void remove(); void flush(); };
struct AutoFileDesc { AutoFileDesc(const string&, int, int); void writeAll(const UInt8*, CFIndex); void close(); };
struct DirScanner { DirScanner(const string&); bool initialized(); struct dirent* getNext(); bool isRegularFile(struct dirent*); void unlink(struct dirent*, int); };
string cfStringRelease(CFURLRef);
struct BundleDiskRep {
 string mMetaPath; bool mMetaExists; CFBundleRef mBundle;
 void createMeta(); string metaPath(const char*); CFURLRef copyCanonicalPath();
 struct Writer {
  BundleDiskRep* rep; ExecWriter* execWriter; std::set<string> mWrittenFiles;
  bool getPreserveAFSC(); void component(int, CFDataRef); void remove(); void remove(int); void flush(); void purgeMetaDirectory();
 };
};
#define BUNDLEDISKREP_DIRECTORY "_CodeSignature"
struct Architecture { Architecture(cpu_type_t, cpu_subtype_t); bool matches(const Architecture&) const; bool operator<(const Architecture&) const; };
namespace LowLevelMemoryUtilities { size_t alignUp(size_t, size_t); }
bool code_sign_deallocate(const char*, const char*, char*&);
bool code_sign_allocate(const char*, const char*, unsigned int (^)(cpu_type_t, cpu_subtype_t), char*&);
void secerror(const char*, ...);
uint32_t get32(bool, uint32_t);
bool assure_signature_space(void*, unsigned int, uint32_t, uint32_t&, char*&);
bool vm_alloc(void*&, vm_size_t, char*&);
bool vm_dealloc(void*&, vm_size_t, char*&);
bool writeFile(const char*, const void*, unsigned int, char*&);
void cleanupUnsigned(unsigned int**);
#define __os_free __attribute__((cleanup(cleanupUnsigned)))
struct MachOEditor {
  struct Arch { size_t blobSize; };
  std::map<Architecture, Arch*> architecture;
  MachOEditor(Writer*, Universal&, int, string); ~MachOEditor(); void allocate(); void commit();
  std::string sourcePath, tempPath; FD mFd;
  Writer* writer; Universal* mNewCode; bool mTempMayExist;
};
using SecCSFlags = unsigned int;
template<class T> struct RefPointer { RefPointer(T*); T* operator->(); };
struct DiskRep {
 using Writer = CodesignWriterResearch::Writer;
 Writer* writer(); Universal* mainExecutableImage(); string mainExecutablePath();
};
struct StaticCode { DiskRep* diskRep(); bool isSigned(); bool flag(unsigned int); void setValidationFlags(SecCSFlags); void resetValidity(); };
using SecStaticCode = StaticCode;
extern const SecCSFlags kSecCSSignPreserveSignature, kSecCSRemoveSignature, kSecCSEditSignature, kSecCSStripDisallowedXattrs;
extern const unsigned int kSecCodeSignatureLinkerSigned;
extern const int errSecCSInvalidObjectRef;
struct SecCodeSigner {
 SecCSFlags mOpFlags; bool valid(); void sign(SecStaticCode*, SecCSFlags);
 struct Signer {
 Signer(SecCodeSigner&, SecStaticCode*); void sign(SecCSFlags); void edit(SecCSFlags);
 struct State { bool mDetached, mPreserveAFSC, mNoMachO, mDryRun; } state;
 DiskRep* rep; StaticCode* code; int digestAlgorithms(); void remove(SecCSFlags);
 bool resourceDirectory; CFDataRef resourceDictData; void populate(DiskRep::Writer&);
}; };
enum MetadataConstants : unsigned long long {
 CloneACL = CLONE_ACL,
 FileSecMagic = KAUTH_FILESEC_MAGIC,
 NoACL = KAUTH_FILESEC_NOACL,
 FileSecSize = KAUTH_FILESEC_SIZE(0),
 AttrReferenceSize = sizeof(attrreference_t),
 CreationTimeAttribute = ATTR_CMN_CRTIME,
 TimeSpecSize = sizeof(struct timespec),
 MappingRead = PROT_READ,
 MappingPrivate = MAP_PRIVATE,
 MappingResilientCodesign = MAP_RESILIENT_CODESIGN
};
`
	hashes := map[string]string{}
	allocation := read(".research/apple/codesign_alloc.cpp")
	mapping := regexp.MustCompile(`(?ms)^static bool mapFile\(.*?^}`).Find(allocation)
	if len(mapping) == 0 {
		panic("missing complete allocation mapFile")
	}
	hashes["mapFile"] = hash(mapping)
	unit += "\nvoid log_error(char*&, const char*, ...);\n" + string(mapping) + "\n"
	allocator := regexp.MustCompile(`(?ms)^bool code_sign_allocate\(.*?^}`).Find(allocation)
	if len(allocator) == 0 {
		panic("missing complete code_sign_allocate")
	}
	hashes["code_sign_allocate"] = hash(allocator)
	unit += "\n" + string(allocator) + "\n"
	alignment := regexp.MustCompile(`(?m)^static const size_t csAlign = [0-9]+;`).Find(source)
	if len(alignment) == 0 {
		panic("missing allocation alignment")
	}
	hashes["csAlign"] = hash(alignment)
	unit += "\n" + string(alignment) + "\n"
	for _, name := range []string{"~MachOEditor", "allocate", "commit"} {
		excerpt := regexp.MustCompile(`(?ms)^(?:void )?MachOEditor::` + regexp.QuoteMeta(name) + `\(\).*?^}`).Find(source)
		if len(excerpt) == 0 {
			panic("missing complete method " + name)
		}
		hashes[name] = hash(excerpt)
		unit += "\n" + string(excerpt) + "\n"
	}
	controller := read(".research/apple/CodeSigner.cpp")
	controllerSign := regexp.MustCompile(`(?ms)^void SecCodeSigner::sign\(SecStaticCode \*code, SecCSFlags flags\).*?^}`).Find(controller)
	if len(controllerSign) == 0 {
		panic("missing complete signing controller")
	}
	hashes["signer_sign"] = hash(controllerSign)
	unit += "\n" + string(controllerSign) + "\n"
	signer := read(".research/apple/signer.cpp")
	remove := regexp.MustCompile(`(?ms)^void SecCodeSigner::Signer::remove\(SecCSFlags flags\).*?^}`).Find(signer)
	if len(remove) == 0 {
		panic("missing complete signer remove method")
	}
	hashes["signer_remove"] = hash(remove)
	unit += "\n" + string(remove) + "\n"
	populate := regexp.MustCompile(`(?ms)^void SecCodeSigner::Signer::populate\(DiskRep::Writer &writer\).*?^}`).Find(signer)
	if len(populate) == 0 {
		panic("missing complete signer global populate method")
	}
	hashes["signer_populate"] = hash(populate)
	unit += "\n" + string(populate) + "\n"
	bundle := read(".research/apple/bundlediskrep.cpp")
	for _, name := range []string{"createMeta", "metaPath", "component", "remove", "flush", "purgeMetaDirectory"} {
		prefix := "BundleDiskRep::Writer::"
		if name == "createMeta" || name == "metaPath" {
			prefix = "BundleDiskRep::"
		}
		excerpts := regexp.MustCompile(`(?ms)^(?:void|string) `+prefix+name+`\(.*?^}`).FindAll(bundle, -1)
		if len(excerpts) == 0 {
			panic("missing complete bundle method " + name)
		}
		for i, excerpt := range excerpts {
			hashes[fmt.Sprintf("bundle_%s_%d", name, i)] = hash(excerpt)
			unit += "\n" + string(excerpt) + "\n"
		}
	}
	// Parse the complete stat-copy implementation using SDK filesystem types.
	// Only the private state carrier and two helper interfaces are shims.
	statCopy := regexp.MustCompile(`(?ms)^static int copyfile_stat\(copyfile_state_t s\).*?^}`).Find(copySource)
	internalFlags := regexp.MustCompile(`(?ms)^enum cfInternalFlags \{.*?^};`).Find(copySource)
	suidMask := regexp.MustCompile(`(?m)^#define S_ISSUD[^\n]+`).Find(copySource)
	if len(statCopy) == 0 || len(internalFlags) == 0 || len(suidMask) == 0 {
		panic("missing copyfile stat source")
	}
	hashes["copyfile_stat"] = hash(statCopy)
	hashes["cfInternalFlags"] = hash(internalFlags)
	unit += "\n" + string(copyHeader) + "\n" + string(internalFlags) + "\n" + string(suidMask) + `
 struct DirectoryCopyState { struct stat sb; uint32_t internal_flags; copyfile_flags_t flags; int src_fd, dst_fd; };
 using copyfile_state_t = DirectoryCopyState*;
 int fd_volume_has_feature(int, uint32_t);
 int copyfile_set_bsdflags(copyfile_state_t, uint32_t, uint32_t);
 enum DirectoryConstants : unsigned long long {
  DirectorySupportedFlags = UF_NODUMP | UF_OPAQUE | UF_HIDDEN,
  DirectoryOmitFlags = COPYFILE_OMIT_FLAGS,
  DirectoryPreserveFlags = COPYFILE_PRESERVE_FLAGS,
  DirectoryCopyStat = COPYFILE_STAT,
  DirectoryCopySecurity = COPYFILE_SECURITY
 };
 ` + string(statCopy) + "\n}\n"
	sdk := strings.TrimSpace(string(run("", "xcrun", "--show-sdk-path")))
	targets := map[string]any{}
	for _, target := range []string{"arm64-apple-macos27", "x86_64-apple-macos27"} {
		var ast node
		must(json.Unmarshal(run(unit, "clang++", "-target", target, "-isysroot", sdk, "-std=c++17", "-fblocks", "-x", "c++", "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=CodesignWriterResearch", "-"), &ast))
		methods, constants := map[string]any{}, map[string]string{}
		walk(ast, func(n node) {
			if n.Kind == "EnumConstantDecl" && (n.Name == "CloneACL" || n.Name == "FileSecMagic" || n.Name == "NoACL" || n.Name == "FileSecSize" || n.Name == "AttrReferenceSize" || n.Name == "CreationTimeAttribute" || n.Name == "TimeSpecSize" || strings.HasPrefix(n.Name, "Directory") || strings.HasPrefix(n.Name, "Mapping")) {
				walk(n, func(c node) {
					if c.Kind == "ConstantExpr" {
						constants[n.Name] = fmt.Sprint(c.Value)
					}
				})
			}
			if (n.Kind != "CXXMethodDecl" && n.Kind != "CXXDestructorDecl" && n.Kind != "FunctionDecl") || hashes[n.Name] == "" && hashes["bundle_"+n.Name+"_0"] == "" && hashes["signer_"+n.Name] == "" {
				return
			}
			kinds, references := map[string]int{}, map[string]int{}
			walk(n, func(c node) {
				kinds[c.Kind]++
				if c.Kind == "DeclRefExpr" && c.ReferencedDecl != nil {
					references[c.ReferencedDecl.Name]++
				}
				if c.Kind == "MemberExpr" {
					references[c.Name]++
				}
			})
			if kinds["CompoundStmt"] > 0 {
				name := n.Name
				if strings.Contains(n.MangledName, "SecCodeSigner") {
					name = "signer_" + name
				} else if hashes[name] == "" {
					name = fmt.Sprintf("bundle_%s_%d", name, kinds["ParmVarDecl"])
				}
				methods[name] = map[string]any{"ast_kinds": kinds, "references": references}
			}
		})
		if len(methods) != 16 || len(constants) != 15 {
			panic(fmt.Sprintf("incomplete AST: %d methods, %d constants", len(methods), len(constants)))
		}
		targets[target] = map[string]any{"methods": methods, "metadata_constants": constants}
	}
	headers := map[string]string{}
	for _, path := range []string{"sys/clonefile.h", "sys/attr.h", "sys/acl.h", "sys/kauth.h", "copyfile.h", "sys/stat.h", "sys/mount.h", "sys/mman.h", "mach/machine.h", "mach-o/fat.h", "mach-o/loader.h", "mach/mach.h", "os/overflow.h"} {
		headers[path] = hash(read(filepath.Join(sdk, "usr/include", path)))
	}
	record := map[string]any{
		"schema": 1, "compiler": strings.Split(string(run("", "clang++", "--version")), "\n")[0], "sdk": filepath.Base(sdk),
		"scope": "Thirteen complete verbatim writer/controller methods plus copyfile_stat, allocation mapFile and code_sign_allocate: SecCodeSigner::sign, SecCodeSigner::Signer::remove and global populate, MachOEditor allocate/commit/destructor and BundleDiskRep createMeta, metaPath, component, both remove overloads, flush and purgeMetaDirectory. Real SDK declarations supply filesystem types, ACL/copy flags, ATTR_CMN_CRTIME, timespec size and mapping flags. The complete allocation mapFile uses a read-only private source mapping. The complete code_sign_allocate body maps input before creating output; private __os_free uses a declaration-only cleanup attribute shim, while allocation, signature-space and endian helpers are declarations. Native APFS observations distinguish mapped-read access-time updates from ordinary reads; 294 comparisons cover signing, re-signing, read-only executables, outer removal and signed/outer-unsigned dry runs. Source hard links share read-access updates; rewritten executables receive a later access time, while outer removal leaves descendant access times unchanged. The shared APFS primitive maps one byte without accessing mapped memory; it does not require metadata-write permission. Private state, helpers, compression and error interfaces are declaration-only shims; private slot/error values describe control flow, not wire formats. Both targets include TARGET_OS_OSX compression branches. MachOEditor copies source metadata, refreshes access/modification times with a byte read/write, and renames the staged file. copyfile_stat copies modification/access times without explicitly copying creation time. Native APFS comparisons establish that a rewritten bundle executable receives a new creation time capped by an earlier source modification time; 210 cases cover seven layouts, three architectures, past/future times and five operations, including nested code and external hard links. Other evidence covers in-place envelopes, directory stat copying, stale-file purge, 278 APFS ASCII order cases, 104 envelope-directory cases and 20 POSIX permission cases. Removal follows directory order, and signing-envelope directory errors occur before the affected executable commit but after earlier children. Symlinked signing envelopes retain early rejection for containment. Standalone mapping and replacement access are covered by 216 native comparisons across three architectures, four operand forms, past/future timestamps and nine operations. Another 168 bundle display/verification comparisons preserve executable stat metadata; 80 DMG comparisons preserve access times. Twenty DMG dry-run cases explicitly record native in-place byte/modification-time changes while Go preserves both. The allocation and global-populate bodies record temporary allocation cleanup and dry-run envelope suppression. Pinned signMachO source calls allocate even for dry runs; pinned buildResources dispatches nested work through LimitedAsync and waits for its group. Those two call sites are source-reviewed, not part of this AST extraction. The readable/searchable executable-directory profile compares modes 0755/0555 independently of executable modes 0755/0551, including first/last sibling allocation failures, outer failures, shallow signing, dry runs and removal. Go retains independent sibling commits and the failed bundle envelope, skips ancestors, and discards dry-run allocations without restoring metadata. Ordinary bundle planning reads leave access untouched; eligible replacement preparation records source access before allocation. The 624 executable-directory cases require matching access effects for dispatched work, including blocked ancestors and shallow descendants. Native exception-aware dispatch can leave independent siblings entirely unstarted; complete before/after member manifests explicitly distinguish that scheduling outcome from Go sibling completion. Pinned dispatch.cpp is source-reviewed, not part of this AST extraction. Another 252 native cases cover preserved signed children and already-signed rejection across seven layouts, three architectures and past/future times. The complete signing controller resets validity only after signing or removal returns successfully; the pinned resetValidity and checkForSystemSignature call sites are source-reviewed separately. Controller state, flags and validation helpers are declaration-only shims. Native cleanup failures retain copied source access on the replacement. Go refreshes the committed executable only after its cleanup succeeds, with root-relative identity checks. A 504-case native corpus covers seven layouts, three architectures, past/future access, stale directories/symlinks, unsigned/signed/read-only signing, signed/unsigned removal and dry runs. Thirty-six failure-boundary cases retain envelope/cleanup source-read and unsigned-child dry-run differences; their replacement access now agrees. Explicit ACL copying/inheritance, DMG dry-run writes, envelope/resource access times, other filesystems, broader permissions, raw diagnostics and compression remain open.",
		"sources": map[string]any{
			"CodeSigner.cpp":     map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/CodeSigner.cpp", "sha256": hash(controller)},
			"StaticCode.cpp":     map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/StaticCode.cpp", "sha256": hash(read(".research/apple/StaticCode.cpp"))},
			"dispatch.cpp":       map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_utilities/lib/dispatch.cpp", "sha256": hash(read(".research/apple/dispatch.cpp"))},
			"codesign_alloc.cpp": map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/codesign_alloc.cpp", "sha256": hash(allocation)},
			"signer.cpp":         map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/signer.cpp", "sha256": hash(signer)},
			"copyfile.c":         map[string]string{"url": "https://github.com/apple-oss-distributions/copyfile/blob/" + copyRevision + "/copyfile.c", "sha256": hash(copySource)},
			"copyfile_private.h": map[string]string{"url": "https://github.com/apple-oss-distributions/copyfile/blob/" + copyRevision + "/copyfile_private.h", "sha256": hash(copyHeader)},
			"signerutils.cpp":    map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/signerutils.cpp", "sha256": hash(source)},
			"bundlediskrep.cpp":  map[string]string{"url": "https://github.com/apple-oss-distributions/Security/blob/" + revision + "/OSX/libsecurity_codesigning/lib/bundlediskrep.cpp", "sha256": hash(bundle)},
		},
		"sdk_headers": headers, "excerpt_sha256": hashes, "translation_unit_sha256": hash([]byte(unit)), "targets": targets,
	}
	b, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile("spec/apple-writer.json", append(b, '\n'), 0644))
	fmt.Println("Wrote spec/apple-writer.json: thirteen writer/controller methods, copyfile_stat, mapFile and code_sign_allocate on two targets")
}
