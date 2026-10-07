// Research only: observe compression-hidden attributes using public SDK headers.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static void die(const char *what) { perror(what); exit(2); }
static int observe_volume(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) die("volume open");
    struct statfs volume;
    if (fstatfs(fd, &volume)) die("fstatfs");
    if (close(fd)) die("volume close");
    printf("{\"filesystem\":\"%s\",\"flags\":%u,\"cprotect_mask\":%u}\n",
        volume.f_fstypename, volume.f_flags, (unsigned)MNT_CPROTECT);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (strcmp(argv[1], "--volume") == 0) return observe_volume(argv[2]);
    struct stat st;
    if (stat(argv[1], &st)) die("stat");
    const char *names[] = {"com.apple.decmpfs", "com.apple.ResourceFork"};
    const char *suffix[] = {"attr", "fork"};
    for (int i = 0; i < 2; i++) {
        ssize_t n = getxattr(argv[1], names[i], NULL, 0, 0, XATTR_SHOWCOMPRESSION);
        if (n < 0) { if (errno == ENOATTR) continue; die("attribute size"); }
        if (n > (128 << 20)) return 2;
        void *data = malloc(n ? (size_t)n : 1);
        if (!data) die("malloc");
        if (getxattr(argv[1], names[i], data, n, 0, XATTR_SHOWCOMPRESSION) != n) die("attribute read");
        char path[4096];
        if (snprintf(path, sizeof(path), "%s.%s", argv[2], suffix[i]) >= (int)sizeof(path)) return 2;
        FILE *f = fopen(path, "wb"); if (!f) die("open output");
        if (fwrite(data, 1, n, f) != (size_t)n || fclose(f)) die("write output");
        free(data);
    }
    printf("{\"flags\":%u,\"size\":%lld}\n", st.st_flags, (long long)st.st_size);
    return 0;
}
