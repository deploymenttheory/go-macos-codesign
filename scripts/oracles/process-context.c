/* Research-only SDK oracle. This inspects only its own process and holds it alive
 * for the parent's independent native codesign calls. No production linkage. */
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CodeSigning.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    SecCodeRef self = NULL, host = NULL;
    SecStaticCodeRef disk = NULL;
    int32_t status = 0;
    CFDictionaryRef information = NULL;
    OSStatus copied = SecCodeCopySelf(kSecCSDefaultFlags, &self);
    OSStatus hosted = copied ? copied : SecCodeCopyHost(self, kSecCSDefaultFlags, &host);
    OSStatus static_code = copied ? copied : SecCodeCopyStaticCode(self, kSecCSDefaultFlags, &disk);
    OSStatus status_code = copied ? copied : SecCodeCopySigningInformation((SecStaticCodeRef)self, kSecCSDynamicInformation, &information);
    if (status_code == 0) {
        CFNumberRef value = CFDictionaryGetValue(information, kSecCodeInfoStatus);
        if (!value || CFGetTypeID(value) != CFNumberGetTypeID() ||
            !CFNumberGetValue(value, kCFNumberSInt32Type, &status)) return 2;
    }
    OSStatus validity = copied ? copied : SecCodeCheckValidity(self, kSecCSDefaultFlags, NULL);
    printf("{\"pid\":%d,\"self\":%d,\"host\":%d,\"static\":%d,\"status_result\":%d,\"status\":%u,\"validity\":%d}\n",
           getpid(), (int)copied, (int)hosted, (int)static_code, (int)status_code, (unsigned)status, (int)validity);
    fflush(stdout);
    char token;
    (void)read(STDIN_FILENO, &token, 1);
    if (information) CFRelease(information);
    if (disk) CFRelease(disk);
    if (host) CFRelease(host);
    if (self) CFRelease(self);
    return 0;
}
