#!/usr/bin/env python3
"""Host C shims of the production T9 grant validator; no WDK/IRQL/VM qualification."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
source = (ROOT / "driver/SafeUpload.Minifilter/StageStream.c").read_text()
# MSVC needs the alloc_text declaration before the definition; skip its
# forward declaration rather than accidentally compiling the intervening code.
functions = list(re.finditer(r"static BOOLEAN StageSpaceGrantValid\([^;{}]*\)\s*\{", source))
assert len(functions) == 1, "Expected exactly one production grant validator definition"
start = functions[0].start()
body_start = functions[0].end() - 1
pragma = source.index("#pragma alloc_text(PAGE, StageSpaceGrantValid)")
assert pragma < start, "MSVC alloc_text must precede the function definition"
depth, end = 1, body_start + 1
while depth:
    depth += (source[end] == "{") - (source[end] == "}")
    end += 1
body = source[start:end].replace("_In_ ", "")
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
typedef int BOOLEAN;
typedef struct { uint64_t x, y; } GUID;
typedef struct { uint64_t volume, low, high; } SAFEUPLOAD_STAGE_IDENTITY_V19;
typedef struct { uint64_t Magic; int64_t Capacity; SAFEUPLOAD_STAGE_IDENTITY_V19 Identity; GUID TransferId; uint64_t Reserved; } STAGE_SPACE_GRANT;
#define PAGED_CODE() ((void)0)
#define STAGE_LEGACY_CAPACITY (16LL*1024*1024)
#define MAXLONGLONG INT64_MAX
#define RtlEqualMemory(a,b,n) (memcmp(a,b,n)==0)
/* BODY */
int main(void) {
  SAFEUPLOAD_STAGE_IDENTITY_V19 identity={4,5,6}; GUID id={1,2};
  STAGE_SPACE_GRANT grant={0x3150535553464153ULL, (int64_t)3*1024*1024*1024, {4,5,6}, {1,2}, 0};
  assert(sizeof(grant)==64);
  assert(StageSpaceGrantValid(&grant,&identity,&id));
  grant.Capacity=STAGE_LEGACY_CAPACITY;
  assert(StageSpaceGrantValid(&grant,&identity,&id));
  grant.Capacity--;
  assert(!StageSpaceGrantValid(&grant,&identity,&id));
  grant.Capacity=INT64_MAX;
  assert(!StageSpaceGrantValid(&grant,&identity,&id));
  grant.Capacity=-1;
  assert(!StageSpaceGrantValid(&grant,&identity,&id));
  grant.Capacity=STAGE_LEGACY_CAPACITY+65536;
  for (unsigned byte=0;byte<64;byte++) {
    STAGE_SPACE_GRANT bad=grant;
    ((unsigned char *)&bad)[byte]^=1;
    if (byte>=8 && byte<16) continue; /* capacity changes may describe a valid different reservation */
    assert(!StageSpaceGrantValid(&bad,&identity,&id));
  }
  grant.Capacity=INT64_MAX-131071;
  assert(StageSpaceGrantValid(&grant,&identity,&id));
  return 0;
}
'''
compilers = list(dict.fromkeys(filter(None, (shutil.which("cc"), shutil.which("clang")))))
if len(compilers) < 2:
    raise SystemExit("Both cc and clang are required")
for compiler in compilers:
    directory = Path(tempfile.mkdtemp(prefix="large-grant-", dir=os.environ.get("TMPDIR", ROOT / ".scratch")))
    program = directory / "fixture.c"
    program.write_text(fixture.replace("/* BODY */", body))
    build = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", str(program), "-o", str(directory / "fixture")], capture_output=True, text=True)
    (directory / "build.txt").write_text(build.stdout + build.stderr)
    if build.returncode:
        raise SystemExit(f"FAIL {directory}: {build.stderr}")
    run = subprocess.run([str(directory / "fixture")], capture_output=True, text=True)
    (directory / "run.txt").write_text(run.stdout + run.stderr)
    if run.returncode:
        raise SystemExit(f"FAIL {directory}: {run.stderr}")
    # Mutation must fail the identical controls.
    program.write_text(fixture.replace("/* BODY */", body.replace("Grant->Reserved == 0", "1")))
    mutation = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(program), "-o", str(directory / "mutated")], capture_output=True, text=True)
    if mutation.returncode:
        raise SystemExit(mutation.stderr)
    run = subprocess.run([str(directory / "mutated")], capture_output=True, text=True)
    if run.returncode == 0:
        raise SystemExit("Mutation escaped the controls")
    print(f"GrantValidator={Path(compiler).name}: PASS; exact identity/GUID, >2GiB, boundaries, overflow, alignment, padding, negative mutation")
