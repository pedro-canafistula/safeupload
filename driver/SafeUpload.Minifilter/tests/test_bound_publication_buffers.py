#!/usr/bin/env python3
"""Compile actual V26 control/security bodies against injectable host boundaries.

Checks fixed wire sizes, output canaries, initialized replies and failure cleanup.
This is not WDK/PREfast, Windows SEH or native/loaded-driver qualification.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SOURCE = (HERE.parent / "StageBoundPublication.c").read_text()


def function(name):
    match = re.search(r"(?m)^(?:static )?(?:NTSTATUS|VOID|BOOLEAN) " + name + r"\([^;]*?\)\s*\{", SOURCE)
    if match is None:
        raise AssertionError("Missing production function: " + name)
    end = SOURCE.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (SOURCE[end] == "{") - (SOURCE[end] == "}")
        end += 1
    # Only the approved MSVC ProbeForWrite annotation is omitted for host C.
    return SOURCE[match.start():end].replace("#pragma warning(suppress: 6001)\n", "") + "\n"


def main():
    wire = (HERE.parent / "StageBoundPublication.h").read_text()
    wire = wire[wire.index("#define SAFEUPLOAD_CONTROL_BOUND_PUBLICATION"):wire.index("\n#endif")]
    scratch = SOURCE[SOURCE.index("typedef union _BP_INPUT"):SOURCE.index("static KSPIN_LOCK BpLock")]
    helpers = "\n".join(function(n) for n in ["BpEqual", "BpZero", "BpReply"])
    bodies = "\n".join(function(n) for n in ["SafeUploadBoundPublicationControl", "BpCaptureSecurity"])
    fixture = (HERE / "bound_publication_buffers_fixture.c").read_text()
    fixture = fixture.replace("/* PRODUCTION_WIRE */", wire + scratch)
    fixture = fixture.replace("/* PRODUCTION_HELPERS */", helpers).replace("/* PRODUCTION_BODIES */", bodies)
    with tempfile.TemporaryDirectory(prefix="safeupload-bound-buffers-") as directory:
        source = Path(directory) / "controls.c"
        binary = Path(directory) / "controls"
        source.write_text(fixture)
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == "__main__":
    main()
