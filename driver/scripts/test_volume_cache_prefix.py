#!/usr/bin/env python3
"""Extract the current resident prefix code and run portable semantic vectors."""
from pathlib import Path
import hashlib
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'driver/SafeUpload.Minifilter/Policy.c'
OUT = ROOT / 'output/mvp-continuation'
OUT.mkdir(parents=True, exist_ok=True)


def extract(name):
    text = SOURCE.read_text()
    match = re.search(r'(?m)^__declspec\(noinline\) static BOOLEAN ' + re.escape(name) + r'\(', text)
    if not match:
        raise SystemExit('function absent: ' + name)
    start = text.rfind('\n', 0, match.start()) + 1
    brace = text.index('{', match.end())
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == '{':
            depth += 1
        elif text[index] == '}':
            depth -= 1
            if depth == 0:
                return text[start:index + 1] + '\n', text.count('\n', 0, start) + 1
    raise SystemExit('unbalanced function: ' + name)


helper, helper_line = extract('SafeUploadVolumeCachePathUnderPrefix')
classifier, classifier_line = extract('SafeUploadPolicyVolumeCacheMatchesLocked')
body = helper[helper.index('{') + 1:helper.rindex('}')]
body = re.sub(r'/\*.*?\*/|//[^\n]*', '', body, flags=re.S)
calls = [token for token in re.findall(r'\b([A-Za-z_]\w*)\s*\(', body)
         if token not in ('if', 'for', 'sizeof', 'return')]
if calls:
    raise SystemExit('helper has external/unknown calls: ' + repr(calls))

prefix = r'''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t BOOLEAN;
typedef uint16_t USHORT;
typedef uint32_t ULONG;
typedef uint16_t WCHAR;
typedef struct { USHORT Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef struct { USHORT Length; WCHAR Text[260]; } SAFEUPLOAD_VOLUME_SCOPE_PREFIX;
typedef struct { ULONG PrefixCount, Flags; BOOLEAN Overflow, ScopeApplyActive;
                 SAFEUPLOAD_VOLUME_SCOPE_PREFIX Prefixes[112]; } SAFEUPLOAD_VOLUME_SCOPE_CACHE;
typedef SAFEUPLOAD_VOLUME_SCOPE_CACHE *PSAFEUPLOAD_VOLUME_SCOPE_CACHE;
typedef enum { SafeUploadVolumeUnknown, SafeUploadVolumeFixed, SafeUploadVolumeRemovable,
               SafeUploadVolumeNetwork } SAFEUPLOAD_VOLUME_KIND;
#define TRUE 1
#define FALSE 0
#define DISPATCH_LEVEL 2
#define _IRQL_requires_max_(x)
#define _In_opt_
#define _In_
#define __declspec(x)
#define FlagOn(v, m) ((v) & (m))
#define SAFEUPLOAD_VOLUME_SCOPE_FLAG_REMOVABLE 1u
#define SAFEUPLOAD_VOLUME_SCOPE_FLAG_NETWORK 2u
_Static_assert(sizeof(WCHAR) == 2, "Windows WCHAR width required");
'''

tests = r'''
static unsigned checks = 0, failures = 0;
static UNICODE_STRING ascii(const char *s, WCHAR *buffer) {
    size_t n = strlen(s);
    if (n > 260) { fputs("bad fixture length\n", stderr); failures++; n = 260; }
    for (size_t i = 0; i < n; i++) buffer[i] = (unsigned char)s[i];
    return (UNICODE_STRING){(USHORT)(n * 2), (USHORT)(n * 2), buffer};
}
static void check(const char *name, BOOLEAN got, BOOLEAN expected) {
    checks++;
    if (got != expected) { fprintf(stderr, "FAIL %s: got %u expected %u\n", name, got, expected); failures++; }
}
static void pair(const char *name, const char *prefix, const char *path, BOOLEAN expected) {
    WCHAR pbuf[260] = {0}, xbuf[260] = {0};
    UNICODE_STRING p = ascii(prefix, pbuf), x = ascii(path, xbuf);
    check(name, SafeUploadVolumeCachePathUnderPrefix(&p, &x), expected);
}
int main(void) {
    WCHAR pbuf[260] = {0}, xbuf[260] = {0};
    char maxRoot[261], shorter[260];
    memset(maxRoot, 'A', 260); maxRoot[260] = '\0';
    memset(shorter, 'A', 259); shorter[259] = '\0';
    pair("260-unit exact bound", maxRoot, maxRoot, TRUE);
    pair("260-unit prefix longer than path", maxRoot, shorter, FALSE);
    UNICODE_STRING p = ascii("\\Device\\HarddiskVolume3", pbuf);
    UNICODE_STRING x = ascii("\\Device\\HarddiskVolume3", xbuf);
    pair("exact canonical root", "\\Device\\HarddiskVolume3", "\\Device\\HarddiskVolume3", TRUE);
    pair("mixed case canonical root", "\\dEvIcE\\hArDdIsKvOlUmE3", "\\Device\\HarddiskVolume3", TRUE);
    pair("longer prefix", "\\Device\\HarddiskVolume3\\scope", "\\Device\\HarddiskVolume3", FALSE);
    pair("root 3 versus root 30", "\\Device\\HarddiskVolume3", "\\Device\\HarddiskVolume30", FALSE);
    pair("boundary slash", "\\Device\\HarddiskVolume3", "\\Device\\HarddiskVolume3\\scope", TRUE);
    pair("trailing prefix slash", "\\Device\\HarddiskVolume3\\", "\\Device\\HarddiskVolume3\\scope", TRUE);
    pair("trailing prefix slash versus bare root", "\\Device\\HarddiskVolume3\\", "\\Device\\HarddiskVolume3", FALSE);
    pair("ASCII mismatch", "\\Device\\HarddiskVolume3", "\\Device\\HarddiskVolume4", FALSE);
    pair("ASCII different component", "\\Device\\HarddiskVolume3", "\\Device\\HarddiskVolume3x\\scope", FALSE);
    pbuf[2] = 0x00e9;
    check("nonASCII prefix compared unit conservatively matches", SafeUploadVolumeCachePathUnderPrefix(&p, &x), TRUE);
    pbuf[2] = 'e'; xbuf[2] = 0x00e9;
    check("nonASCII path compared unit conservatively matches", SafeUploadVolumeCachePathUnderPrefix(&p, &x), TRUE);
    xbuf[2] = 'e';
    check("null prefix", SafeUploadVolumeCachePathUnderPrefix(NULL, &x), TRUE);
    check("null path", SafeUploadVolumeCachePathUnderPrefix(&p, NULL), TRUE);
    p.Buffer = NULL;
    check("null prefix buffer", SafeUploadVolumeCachePathUnderPrefix(&p, &x), TRUE);
    p.Buffer = pbuf; x.Buffer = NULL;
    check("null path buffer", SafeUploadVolumeCachePathUnderPrefix(&p, &x), TRUE);
    x.Buffer = xbuf; p.Length = 0;
    check("empty prefix", SafeUploadVolumeCachePathUnderPrefix(&p, &x), TRUE);
    p.Length = 1;
    check("odd prefix byte length", SafeUploadVolumeCachePathUnderPrefix(&p, &x), TRUE);
    p.Length = 2; x.Length = 1;
    check("odd path byte length", SafeUploadVolumeCachePathUnderPrefix(&p, &x), TRUE);
    p = ascii("\\Device\\HarddiskVolume3", pbuf); x.Length = 0;
    check("empty path helper alone", SafeUploadVolumeCachePathUnderPrefix(&p, &x), FALSE);
    SAFEUPLOAD_VOLUME_SCOPE_CACHE cache = {0};
    cache.PrefixCount = 1;
    cache.Prefixes[0].Length = p.Length;
    memcpy(cache.Prefixes[0].Text, p.Buffer, p.Length);
    check("empty path classifier fallback", SafeUploadPolicyVolumeCacheMatchesLocked(&cache, SafeUploadVolumeFixed, &x), TRUE);
    check("null path classifier fallback", SafeUploadPolicyVolumeCacheMatchesLocked(&cache, SafeUploadVolumeFixed, NULL), TRUE);
    check("normal matching classifier", SafeUploadPolicyVolumeCacheMatchesLocked(&cache, SafeUploadVolumeFixed, &p), TRUE);
    printf("checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
'''

test_source = OUT / 'volume-cache-prefix-check.c'
test_source.write_text(prefix + '\n/* Extracted verbatim from Policy.c. */\n' + helper + '\n' + classifier + '\n' + tests)
print('Policy.c helper line', helper_line, 'sha256', hashlib.sha256(helper.encode()).hexdigest())
print('Policy.c classifier line', classifier_line, 'sha256', hashlib.sha256(classifier.encode()).hexdigest())
print('helper external calls', calls)
for compiler in ('gcc', 'clang'):
    executable = OUT / ('volume-cache-prefix-check-' + compiler)
    command = [compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic',
               str(test_source), '-o', str(executable)]
    print('COMMAND', ' '.join(command), flush=True)
    subprocess.run(command, check=True)
    subprocess.run([str(executable)], check=True)
