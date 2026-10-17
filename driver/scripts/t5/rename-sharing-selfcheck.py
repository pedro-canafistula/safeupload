#!/usr/bin/env python3
"""Compile the production rename-sharing predicate against handle scenarios.

Host control only: no NTFS, Filter Manager, PREfast or loaded-driver claim.
TMPDIR chooses all generated sources/binaries; the default is .scratch here.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "driver/SafeUpload.Minifilter/StageStream.c"


def function(source, name):
    match = re.search(r"(?m)^static (?:BOOLEAN|NTSTATUS) " + name + r"\([^;]*?\)\s*\{", source)
    if match is None:
        raise AssertionError("Missing production function: " + name)
    end = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


SHIM = r"""
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
/* A rejected negative control must not leave a core dump. */
#undef assert
#define assert(c) ((c) ? (void)0 : exit(97))
typedef int BOOLEAN;
typedef uint32_t ULONG;
typedef struct { ULONG OpenCount, SharedDelete; } SHARE_ACCESS;
typedef struct { BOOLEAN DeleteAccess, SharedDelete; } FILE_OBJECT, *PFILE_OBJECT;
#define FALSE 0
#define PAGED_CODE() ((void)0)
/* PRODUCTION */
typedef struct { SHARE_ACCESS ShareAccess; int Resource; } STREAM;
typedef struct { PFILE_OBJECT TargetFileObject; } IOPB;
typedef struct { IOPB *Iopb; } DATA;
#define STATUS_SUCCESS 0
#define STATUS_SHARING_VIOLATION -1
static void StageAcquire(int *resource) { assert(!*resource); ++*resource; }
static void StageRelease(int *resource) { assert(*resource == 1); --*resource; }
static BOOLEAN check(SHARE_ACCESS *ledger, PFILE_OBJECT actor)
{
    STREAM storage = {*ledger, 0}, *Stream = &storage;
    IOPB iopb = {actor};
    DATA data = {&iopb}, *Data = &data;
    int status;
    /* PRODUCTION_CALL */
    assert(storage.Resource == 0);
    assert(storage.ShareAccess.OpenCount == ledger->OpenCount);
    assert(storage.ShareAccess.SharedDelete == ledger->SharedDelete);
    return status == STATUS_SUCCESS;
}
int main(void)
{
    /* One FILE_OBJECT is the renaming open. Duplicated handles do not add
     * another open to IoUpdateShareAccess. Other counted opens must each
     * permit deletion. Enumerate their individual grants independently. */
    for (unsigned actorShares = 0; actorShares < 2; ++actorShares) {
        for (unsigned others = 0; others <= 8; ++others) {
            for (unsigned mask = 0; mask < (1U << others); ++mask) {
                FILE_OBJECT actor = {1, (BOOLEAN)actorShares};
                SHARE_ACCESS ledger = {1, actorShares};
                BOOLEAN expected = 1;
                for (unsigned n = 0; n < others; ++n) {
                    ++ledger.OpenCount;
                    if (mask & (1U << n)) ++ledger.SharedDelete;
                    else expected = 0;
                }
                SHARE_ACCESS before = ledger;
                assert(check(&ledger, &actor) == expected);
                assert(ledger.OpenCount == before.OpenCount && ledger.SharedDelete == before.SharedDelete);
                /* Same open, another duplicated handle: same answer. */
                assert(check(&ledger, &actor) == expected);
                actor.DeleteAccess = 0;
                assert(!check(&ledger, &actor));
            }
        }
    }
    FILE_OBJECT actor = {1, 0};
    SHARE_ACCESS invalid = {0, 0};
    assert(!check(&invalid, &actor));
    invalid.OpenCount = 1; invalid.SharedDelete = 2;
    assert(!check(&invalid, &actor));
    SHARE_ACCESS large = {UINT32_MAX, UINT32_MAX - 1};
    assert(check(&large, &actor));
    large.SharedDelete = UINT32_MAX;
    actor.SharedDelete = 1;
    assert(check(&large, &actor));
    return 0;
}
"""


class RenameSharing(unittest.TestCase):
    def test_production_is_wired_under_the_existing_resource(self):
        source = SOURCE.read_text()
        rename = function(source, "StageRename")
        call = "StageRenameShareAllowed(&Stream->ShareAccess, Data->Iopb->TargetFileObject)"
        at = rename.index(call)
        acquired = rename.rfind("StageAcquire(&Stream->Resource);", 0, at)
        self.assertGreaterEqual(acquired, 0)
        self.assertLess(acquired, at)
        self.assertLess(at, rename.index("StageRelease(&Stream->Resource);", at))
        self.assertIn("#pragma alloc_text(PAGE, StageRenameShareAllowed)", source)
        self.assertIn("_IRQL_requires_max_(APC_LEVEL)\nstatic BOOLEAN StageRenameShareAllowed", source)
        self.assertIn("PAGED_CODE();", function(source, "StageRenameShareAllowed"))
        self.assertIn("if (!Data->Iopb->TargetFileObject->DeleteAccess) return STATUS_ACCESS_DENIED;", rename)

    def test_actual_c_body_and_original_defect(self):
        source = SOURCE.read_text()
        actual = function(source, "StageRenameShareAllowed")
        rename = function(source, "StageRename")
        at = rename.index("StageRenameShareAllowed(")
        start = rename.rindex("StageAcquire(&Stream->Resource);", 0, at)
        end = rename.index("StageRelease(&Stream->Resource);", at) + len("StageRelease(&Stream->Resource);")
        caller = rename[start:end]
        original = actual[:actual.index("    PAGED_CODE();")] + """
    return FileObject->DeleteAccess && ShareAccess->OpenCount == ShareAccess->SharedDelete;
}
"""
        scratch = Path(os.environ.get("TMPDIR", ROOT / ".scratch"))
        scratch.mkdir(parents=True, exist_ok=True)
        compilers = [c for c in ("cc", "clang") if shutil.which(c)]
        self.assertTrue(compilers, "a host C compiler is required")
        with tempfile.TemporaryDirectory(prefix="rename-sharing-", dir=scratch) as directory:
            for compiler in compilers:
                for label, body in (("actual", actual), ("original-defect", original)):
                    with self.subTest(compiler=compiler, label=label):
                        path = Path(directory) / (compiler + "-" + label)
                        path.with_suffix(".c").write_text(SHIM.replace("/* PRODUCTION */", body)
                                                         .replace("/* PRODUCTION_CALL */", caller))
                        subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                        str(path.with_suffix(".c")), "-o", str(path)], check=True)
                        result = subprocess.run([str(path)], check=False)
                        self.assertEqual(result.returncode, 0 if label == "actual" else 97)


if __name__ == "__main__":
    unittest.main()
