/* Independent native input producer; never linked into production. */
#include <copyfile.h>
#include <sys/xattr.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int assign(const char *path, const char *name, const void *value, size_t size) {
    if (setxattr(path, name, value, size, 0, XATTR_NOFOLLOW) == 0) return 0;
    fprintf(stderr, "setxattr %s errno=%d: %s\n", name, errno, strerror(errno));
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: seed input output kind\n"); return 2; }
    if (!strncmp(argv[3], "generic-", 8)) {
        const char *state = argv[3] + 8;
        if (strcmp(state, "clean") && strcmp(state, "populated") && strcmp(state, "empty")) return 2;
        unsigned char finder[32] = {'T', 'E', 'X', 'T'};
        if (assign(argv[1], "com.apple.FinderInfo", finder, sizeof(finder)) ||
            assign(argv[1], "com.apple.ResourceFork", "unrelated resource fork", 23) ||
            assign(argv[1], "user.codesign-control", "keep", 4) ||
            assign(argv[1], "com.apple.cs", "near prefix", 11) ||
            assign(argv[1], "com.apple.csign", "not a signature", 15)) return 1;
        const char *slots[] = {"CodeDirectory", "CodeRequirements", "CodeResources", "CodeTopDirectory",
            "CodeEntitlements", "CodeRepSpecific", "CodeEntitlementDER", "LaunchConstraintSelf",
            "LaunchConstraintParent", "LaunchConstraintResponsible", "LibraryConstraint",
            "CodeSignature", "CodeRequirements-1", "Unknown"};
        if (strcmp(state, "clean")) {
            for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
                char name[128];
                snprintf(name, sizeof(name), "com.apple.cs.%s", slots[i]);
                if (assign(argv[1], name, slots[i], !strcmp(state, "empty") ? 0 : strlen(slots[i]))) return 1;
            }
        }
    } else if (!strcmp(argv[3], "discovery")) {
        if (assign(argv[1], "com.apple.cs.CodeDirectory", "attached signature", 18) ||
            assign(argv[1], "user.codesign-control", "unchanged", 9)) return 1;
    } else if ((!strcmp(argv[3], "strip") || !strcmp(argv[3], "remove")) &&
        assign(argv[1], "com.example.retained", "retained", 8)) return 1;
    if (!strcmp(argv[3], "strip")) {
        unsigned char finder[32] = {0};
        memcpy(finder, "TEST", 4);
        if (assign(argv[1], "com.apple.FinderInfo", finder, sizeof(finder)) ||
            assign(argv[1], "com.apple.ResourceFork", "fork", 4)) return 1;
    } else if (!strcmp(argv[3], "remove")) {
        if (assign(argv[1], "com.apple.cs.CodeDirectory", "signature", 9)) return 1;
    } else if (!strcmp(argv[3], "fork") || !strcmp(argv[3], "finder") || !strcmp(argv[3], "both")) {
        if (strcmp(argv[3], "finder") && assign(argv[1], "com.apple.ResourceFork", "resource fork", 13)) return 1;
        if (strcmp(argv[3], "fork")) {
            unsigned char finder[32] = {0};
            memcpy(finder, "TEXTttxt", 8);
            if (assign(argv[1], "com.apple.FinderInfo", finder, sizeof(finder))) return 1;
        }
    } else if (!strcmp(argv[3], "ordinary")) {
        if (assign(argv[1], "user.codesign-control", "keep", 4)) return 1;
    } else if (!strcmp(argv[3], "clean")) {
        /* No requested metadata; retain anything the native host creates. */
    } else if (strncmp(argv[3], "generic-", 8) && strcmp(argv[3], "discovery")) {
        fprintf(stderr, "unknown seed kind\n"); return 2;
    }
    if (copyfile(argv[1], argv[2], NULL, COPYFILE_PACK | COPYFILE_ALL)) {
        fprintf(stderr, "copyfile pack errno=%d: %s\n", errno, strerror(errno));
        return 1;
    }
    return 0;
}
