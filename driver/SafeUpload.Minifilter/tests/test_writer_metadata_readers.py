#!/usr/bin/env python3
"""Portable controls using the actual kernel control/admission/teardown bodies.

Run on a host with a C11 compiler and pthreads. This is a mocked component
control, not WDK/PREfast, Windows SEH or loaded-driver qualification.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
SOURCE = (HERE.parent / "StagePublic.c").read_text()


def function(name):
    match = re.search(r"(?m)^(?:static )?(?:NTSTATUS|VOID|BOOLEAN) " + name + r"\([^;]*?\)\s*\{", SOURCE)
    if match is None:
        raise AssertionError("Missing production function: " + name)
    brace = SOURCE.index("{", match.start())
    depth = 1
    end = brace + 1
    while depth:
        depth += (SOURCE[end] == "{") - (SOURCE[end] == "}")
        end += 1
    # MSVC-only, approved probe annotation has no host-compiler equivalent.
    body = SOURCE[match.start():end].replace("#pragma warning(suppress: 6001)\n", "")
    return body + "\n"


def main():
    wire = (HERE.parent / "StageWriterMetadata.h").read_text()
    wire = wire[wire.index("#define SAFEUPLOAD_WRITER_METADATA_VERSION"):wire.index("typedef struct _SAFEUPLOAD_WRITER_METADATA_FACTS")]
    wire += "\n#pragma pack(pop)\n"
    protocol = (HERE.parent / "Protocol.h").read_text()
    constants = "\n".join(re.findall(r"(?m)^#define (?:SAFEUPLOAD_PROTOCOL_VERSION|SAFEUPLOAD_CONTROL_WRITER_METADATA) .*", protocol))
    constants += "\n" + re.search(r"(?m)^#define STAGE_WRITER_MAX_METADATA_READERS .*", SOURCE)[0] + "\n"
    bodies = "\n".join(function(name) for name in [
        "StageWriterMetadataBeginRead", "StageWriterMetadataEndRead",
        "SafeUploadStagePublicTryCloseAdmission", "SafeUploadStagePublicReopenAdmission",
        "SafeUploadStagePublicCloseAdmission",
        "SafeUploadStagePublicCloseAllBackends", "SafeUploadStageWriterMetadataControl"])
    fixture = (HERE / "writer_metadata_readers_fixture.c").read_text()
    fixture = fixture.replace("/* PRODUCTION_WIRE */", constants + wire).replace("/* PRODUCTION_BODIES */", bodies)
    with tempfile.TemporaryDirectory(prefix="safeupload-metadata-readers-") as directory:
        source = Path(directory) / "controls.c"
        binary = Path(directory) / "controls"
        source.write_text(fixture)
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
                        str(source), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == "__main__":
    main()
