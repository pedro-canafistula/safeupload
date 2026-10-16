#!/usr/bin/env python3
"""Local synthetic T9 probe. No VM, policy-default changes, or qualification claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import zipfile

zipfile.ZIP64_LIMIT = (1 << 32) - 1  # Use valid ZIP32 extents through 2 GiB; do not emit ZIP64.

ROOT = Path(__file__).resolve().parents[3]

def fill(output, length):
    pattern = b"alfa beta gamma delta epsilon safe document line\n"
    chunk = (pattern * (65536 // len(pattern) + 1))[:65536]
    while length:
        piece = chunk[:min(length, len(chunk))]
        output.write(piece)
        length -= len(piece)

def corpus(root, mib, extension):
    path = root / f"synthetic-{mib}MiB{extension}"
    length = mib * 1024 * 1024
    if extension == ".txt":
        with path.open("wb") as output:
            fill(output, length)
    else:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
            if extension == ".docx":
                archive.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
                archive.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
                with archive.open("word/document.xml", "w", force_zip64=False) as output:
                    output.write(b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>')
                    fill(output, length)
                    output.write(b'</w:t></w:r></w:p></w:body></w:document>')
            else:
                with archive.open("document.txt", "w", force_zip64=False) as output:
                    fill(output, length)
    return path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--scratch", type=Path, default=ROOT / ".scratch/t9/measure")
    parser.add_argument("--sizes", type=int, nargs="+", default=[64, 512, 2048])
    args = parser.parse_args()
    args.scratch.mkdir(parents=True, exist_ok=True)
    results = []
    for size in args.sizes:
        for extension in [".txt", ".docx", ".zip"]:
            path = corpus(args.scratch, size, extension)
            environment = os.environ | {"DOTNET_GCHeapHardLimit": "10000000"}
            began = time.monotonic()
            run = subprocess.run([args.dotnet, args.probe, str(path.resolve())], text=True,
                                 capture_output=True, timeout=660, env=environment)
            stem = path.with_suffix(path.suffix + ".probe")
            stem.with_suffix(stem.suffix + ".stdout.txt").write_text(run.stdout)
            stem.with_suffix(stem.suffix + ".stderr.txt").write_text(run.stderr)
            try:
                result = json.loads(run.stdout)
            except (json.JSONDecodeError, ValueError):
                result = {"file": path.name, "failure": "probe_failed", "seconds": time.monotonic() - began}
            result.update(exitCode=run.returncode, decodedPayloadMiB=size)
            results.append(result)
            (args.scratch / "results.json").write_text(json.dumps(results, indent=2) + "\n")
            print(json.dumps(result), flush=True)
    return 0 if all(row["exitCode"] == 0 for row in results) else 1

if __name__ == "__main__":
    raise SystemExit(main())
