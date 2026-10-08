/* Research only: the same FTS options used by Apple's ResourceBuilder.
 * This probe observes SDK traversal and xattr calls; it is not a codesign
 * implementation and is never linked into production Go code. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fts.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void quoted(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: resource-order bundle\n"); return 2; }
    char *paths[] = {argv[1], NULL};
    FTS *tree = fts_open(paths, FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR, NULL);
    if (!tree) { perror("fts_open"); return 1; }
    const size_t root_length = strlen(argv[1]);
    FTSENT *entry;
    errno = 0;
    while ((entry = fts_read(tree)) != NULL) {
        int finder_error = 0, resource_error = 0;
        ssize_t finder_size = -1, resource_size = -1;
        if (entry->fts_info == FTS_F) {
            finder_size = getxattr(entry->fts_path, XATTR_FINDERINFO_NAME, NULL, 0, 0, XATTR_NOFOLLOW);
            if (finder_size < 0) finder_error = errno;
            resource_size = getxattr(entry->fts_path, XATTR_RESOURCEFORK_NAME, NULL, 0, 0, XATTR_NOFOLLOW);
            if (resource_size < 0) resource_error = errno;
        }
        const char *relative = entry->fts_path + root_length;
        if (*relative == '/') relative++;
        printf("{\"path\":"); quoted(relative);
        printf(",\"info\":%d,\"errno\":%d,\"finder_size\":%zd,\"finder_errno\":%d,\"resource_size\":%zd,\"resource_errno\":%d}\n",
               entry->fts_info, entry->fts_errno, finder_size, finder_error, resource_size, resource_error);
        errno = 0;
    }
    int failure = errno;
    if (fts_close(tree) != 0 && !failure) failure = errno;
    if (failure) { fprintf(stderr, "fts traversal errno=%d\n", failure); return 1; }
    return 0;
}
