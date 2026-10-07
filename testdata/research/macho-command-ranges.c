/* Research fixture generator, never linked into the portable implementation.
 * Real SDK structures define the recipe. A zero-padded LC_ID_DYLIB grows the
 * command range while __TEXT and __LINKEDIT retain valid file/VM boundaries.
 * This is a signing-layout fixture, not a claim that the dylib is loadable code.
 */
#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

enum CommandRangeLayout {
    CR_HEADER_SIZE = sizeof(struct mach_header_64),
    CR_HEADER_NCMDS = offsetof(struct mach_header_64, ncmds),
    CR_HEADER_SIZEOFCMDS = offsetof(struct mach_header_64, sizeofcmds),
    CR_SEGMENT_SIZE = sizeof(struct segment_command_64),
    CR_SEGMENT_VMADDR = offsetof(struct segment_command_64, vmaddr),
    CR_SEGMENT_VMSIZE = offsetof(struct segment_command_64, vmsize),
    CR_SEGMENT_FILEOFF = offsetof(struct segment_command_64, fileoff),
    CR_SEGMENT_FILESIZE = offsetof(struct segment_command_64, filesize),
    CR_SEGMENT_MAXPROT = offsetof(struct segment_command_64, maxprot),
    CR_SEGMENT_INITPROT = offsetof(struct segment_command_64, initprot),
    CR_DYLIB_SIZE = sizeof(struct dylib_command),
    CR_DYLIB_NAME = offsetof(struct dylib_command, dylib.name),
    CR_UUID_SIZE = sizeof(struct uuid_command),
    CR_UUID_BYTES = offsetof(struct uuid_command, uuid),
    CR_RPATH_SIZE = sizeof(struct rpath_command),
    CR_RPATH_PATH = offsetof(struct rpath_command, path),
    CR_MAGIC = MH_MAGIC_64,
    CR_FILETYPE = MH_DYLIB,
    CR_SEGMENT = LC_SEGMENT_64,
    CR_DYLIB = LC_ID_DYLIB,
    CR_UUID = LC_UUID,
    CR_RPATH = LC_RPATH,
    CR_SECTION_SIZE = sizeof(struct section_64),
    CR_SECTION_ADDR = offsetof(struct section_64, addr),
    CR_SECTION_LENGTH = offsetof(struct section_64, size),
    CR_SECTION_OFFSET = offsetof(struct section_64, offset),
    CR_SECTION_FLAGS = offsetof(struct section_64, flags),
    CR_BUILD_SIZE = sizeof(struct build_version_command),
    CR_BUILD_PLATFORM = offsetof(struct build_version_command, platform),
    CR_BUILD_MINOS = offsetof(struct build_version_command, minos),
    CR_BUILD_SDK = offsetof(struct build_version_command, sdk)
};

static void write_at(int fd, const void *bytes, size_t size, uint64_t at) {
    if (pwrite(fd, bytes, size, (off_t)at) != (ssize_t)size) { perror("pwrite"); exit(1); }
}
static struct segment_command_64 segment(const char *name, uint64_t vm, uint64_t off, uint64_t size, int prot) {
    struct segment_command_64 s = {0};
    s.cmd = LC_SEGMENT_64; s.cmdsize = sizeof(s); strcpy(s.segname, name);
    s.vmaddr = vm; s.vmsize = (size + 16383) & ~UINT64_C(16383);
    s.fileoff = off; s.filesize = size; s.maxprot = prot; s.initprot = prot;
    return s;
}
int main(int argc, char **argv) {
    if (argc != 7) { fprintf(stderr, "path dylib-command-size rpath-count cpu text-section platform\n"); return 2; }
    uint64_t n = strtoull(argv[2], NULL, 10), count = strtoull(argv[3], NULL, 10);
    uint64_t extra = atoi(argv[5]) ? sizeof(struct section_64) : 0;
    uint64_t commands = 168 + extra + n + count * 24 + (atoi(argv[6]) ? 24 : 0), command_end = 32 + commands;
    if (n < 40 || n % 8 || commands > UINT32_MAX) return 2;
    uint64_t text_end = (command_end + 32 + 16383) & ~UINT64_C(16383);
    struct mach_header_64 h = {0};
    h.magic = MH_MAGIC_64; h.cputype = (cpu_type_t)strtoul(argv[4], NULL, 10);
    h.filetype = MH_DYLIB; h.ncmds = (uint32_t)(4 + count + (atoi(argv[6]) ? 1 : 0)); h.sizeofcmds = (uint32_t)commands;
    struct segment_command_64 text = segment("__TEXT", UINT64_C(0x100000000), 0, text_end, 5);
    text.cmdsize += (uint32_t)extra; text.nsects = extra ? 1 : 0;
    struct segment_command_64 link = segment("__LINKEDIT", UINT64_C(0x100000000) + text_end, text_end, 64, 1);
    struct dylib_command dylib = {0}; dylib.cmd = LC_ID_DYLIB; dylib.cmdsize = (uint32_t)n; dylib.dylib.name.offset = sizeof(dylib);
    struct uuid_command uuid = {0}; uuid.cmd = LC_UUID; uuid.cmdsize = sizeof(uuid); memcpy(uuid.uuid, "0123456789abcdef", 16);
    int fd = open(argv[1], O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) { perror("open"); return 1; }
    if (ftruncate(fd, (off_t)(text_end + 64))) { perror("ftruncate"); return 1; }
    write_at(fd, &h, sizeof(h), 0); write_at(fd, &text, sizeof(text), 32);
    write_at(fd, &dylib, sizeof(dylib), 104 + extra); write_at(fd, "libsample.dylib", 15, 128 + extra);
    write_at(fd, &link, sizeof(link), 104 + extra + n); write_at(fd, &uuid, sizeof(uuid), 176 + extra + n);
    for (uint64_t i = 0; i < count; i++) {
        unsigned char bytes[24] = {0}; struct rpath_command r = {LC_RPATH, 24, {12}};
        memcpy(bytes, &r, sizeof(r)); memcpy(bytes + 12, "/usr/lib", 9);
        write_at(fd, bytes, sizeof(bytes), 200 + extra + n + i * 24);
    }
    if (atoi(argv[6])) {
        struct build_version_command build = {LC_BUILD_VERSION, sizeof(build), (uint32_t)atoi(argv[6]), 11 << 16, 27 << 16, 0};
        write_at(fd, &build, sizeof(build), 200 + extra + n + count * 24);
    }
    if (extra) {
        struct section_64 section = {0}; strcpy(section.sectname, "__text"); strcpy(section.segname, "__TEXT");
        section.addr = UINT64_C(0x100000000) + text_end - 16; section.size = 4; section.offset = (uint32_t)(text_end - 16);
        section.align = 2; section.flags = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
        uint32_t instruction = h.cputype == CPU_TYPE_ARM64 ? UINT32_C(0xd65f03c0) : UINT32_C(0x909090c3);
        write_at(fd, &section, sizeof(section), 104); write_at(fd, &instruction, sizeof(instruction), text_end - 16);
    }
    if (close(fd)) { perror("close"); return 1; }
    return 0;
}
