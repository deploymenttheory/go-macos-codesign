/* Research only. CommonCrypto is an independent digest oracle, not a signer. */
#include <CommonCrypto/CommonDigest.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    const uint64_t offsets[] = {0, UINT64_C(4294967295), UINT64_C(4294967297)};
    const size_t lengths[] = {0, 1, 63, 64, 65, 4095, 4096, 4097, 65535, 65536, 65537, 131072, 131089};
    puts("[");
    int first = 1;
    for (unsigned kind = 1; kind <= 4; kind++) {
        for (size_t o = 0; o < sizeof(offsets)/sizeof(offsets[0]); o++) {
            for (size_t l = 0; l < sizeof(lengths)/sizeof(lengths[0]); l++) {
                CC_SHA1_CTX s1; CC_SHA256_CTX s256; CC_SHA512_CTX s384;
                if (kind == 1) CC_SHA1_Init(&s1);
                else if (kind == 4) CC_SHA384_Init(&s384);
                else CC_SHA256_Init(&s256);
                unsigned char buffer[4093], digest[CC_SHA384_DIGEST_LENGTH];
                for (size_t done = 0; done < lengths[l];) {
                    size_t n = lengths[l] - done;
                    if (n > sizeof(buffer)) n = sizeof(buffer);
                    for (size_t i = 0; i < n; i++) {
                        uint64_t x = offsets[o] + done + i;
                        buffer[i] = (unsigned char)((x ^ (x >> 17) ^ (x >> 32)) * 29 + 7);
                    }
                    if (kind == 1) CC_SHA1_Update(&s1, buffer, (CC_LONG)n);
                    else if (kind == 4) CC_SHA384_Update(&s384, buffer, (CC_LONG)n);
                    else CC_SHA256_Update(&s256, buffer, (CC_LONG)n);
                    done += n;
                }
                if (kind == 1) CC_SHA1_Final(digest, &s1);
                else if (kind == 4) CC_SHA384_Final(digest, &s384);
                else CC_SHA256_Final(digest, &s256);
                size_t n = kind == 4 ? 48 : kind == 2 ? 32 : 20;
                printf("%s{\"kind\":%u,\"offset\":%llu,\"length\":%zu,\"digest\":\"", first ? "" : ",\n", kind, (unsigned long long)offsets[o], lengths[l]);
                for (size_t i = 0; i < n; i++) printf("%02x", digest[i]);
                printf("\"}"); first = 0;
            }
        }
    }
    puts("\n]");
    return ferror(stdout) ? 1 : 0;
}
