/* Native evidence only. Never linked into the portable implementation. */
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

int metadata_probe(const char *path) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
        (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (url == NULL) return 2;
    SecStaticCodeRef code = NULL;
    OSStatus create = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (create != errSecSuccess) return 3;
    CFDictionaryRef info = NULL;
    OSStatus inspect = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    OSStatus verify = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL);
    printf("{\"create\":%d,\"inspect\":%d,\"verify\":%d,\"cdhash\":\"",
        (int)create, (int)inspect, (int)verify);
    if (info != NULL) {
        CFDataRef hash = CFDictionaryGetValue(info, kSecCodeInfoUnique);
        if (hash != NULL && CFGetTypeID(hash) == CFDataGetTypeID()) {
            const UInt8 *bytes = CFDataGetBytePtr(hash);
            for (CFIndex i = 0; i < CFDataGetLength(hash); i++) printf("%02x", bytes[i]);
        }
        CFRelease(info);
    }
    puts("\"}");
    CFRelease(code);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    return metadata_probe(argv[1]);
}
