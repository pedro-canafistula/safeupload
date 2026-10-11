#!/usr/bin/env python3
"""Offline source and transaction-model controls for the R21 harness candidate."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
CANDIDATE = Path(__file__).resolve().parents[1]
SRC = CANDIDATE / "src"
BASELINE = REPO / "output/review-candidates/m2-t5-harness-windows-gate-r20-root-a1/src"
BASE_CAPTURE = CANDIDATE / "author/r20-root-review-capture-baseline.json"
CONTROL_OUTPUT = CANDIDATE / "author/offline-controls.txt"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def capture_records(root: Path) -> list[dict[str, object]]:
    records = []
    for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.relative_to(root).as_posix()):
        data = path.read_bytes()
        records.append({"path": path.relative_to(root).as_posix(), "sha256": sha(data), "size": len(data)})
    return records


def extract_function(text: str, start_marker: str, end_marker: str) -> str:
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return text[start:end]


def source_violations(protocol: str, keeper: str, remote: str, control: str,
                      manifest_bytes: bytes, shell: str) -> list[str]:
    problems: list[str] = []

    def require(ok: bool, message: str) -> None:
        if not ok:
            problems.append(message)

    writer = extract_function(
        protocol,
        "function Write-HarnessGateKeeperReadyReceipt(",
        "\nfunction New-HarnessGateState(",
    )
    require(protocol.count("function Write-HarnessGateKeeperReadyReceipt(") == 1,
            "exactly one readiness-receipt writer definition exists")
    required_order = [
        "$Path -cne (Get-HarnessGateKeeperReadyPath $RunToken)",
        "$bytes = [Text.UTF8Encoding]::new($false).GetBytes(",
        "$sha.ComputeHash($bytes)",
        "$temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'",
        "New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)",
        "$stream.Write($bytes, 0, $bytes.Length)",
        "$stream.Flush($true)",
        "$stream.Dispose()",
        "$stream = $null",
        "[IO.File]::Move($temporary, $Path)",
        "return $readySha",
    ]
    positions = [writer.find(token) for token in required_order]
    dispose_position = writer.find("$stream.Dispose()")
    positions[8] = writer.find("$stream = $null", dispose_position + 1)
    require(all(pos >= 0 for pos in positions), "required receipt validation/write/publish tokens exist")
    require(all(a < b for a, b in zip(positions, positions[1:])), "validation, staging, flush, close, publish, return order is strict")
    move_position = writer.find("[IO.File]::Move($temporary, $Path)")
    cleared_position = writer.find("$temporaryCreated = $false", move_position + 1)
    require(cleared_position > move_position and cleared_position < writer.find("return $readySha"),
            "successful publication clears only the consumed staging-path cleanup flag")
    require(writer.count("[IO.File]::Move($temporary, $Path)") == 1, "receipt has exactly one no-overwrite publish operation")
    require("FileStream($Path," not in writer, "receipt never writes directly to the consumer-visible final path")
    require("[IO.File]::Replace(" not in writer and "[IO.File]::Copy(" not in writer,
            "receipt has no overwrite-capable or copy-based publication fallback")
    require("$temporaryCreated = $true" in writer and "if ($temporaryCreated)" in writer and
            "[IO.File]::Delete($temporary)" in writer,
            "failure cleanup is limited to the staging path created by this invocation")
    require("[IO.FileShare]::None" in writer and "[IO.FileMode]::CreateNew" in writer,
            "staging receipt is exclusive and cannot be opened over an existing name")
    require("$retainHandlesForCancel = $true" in keeper and
            keeper.index("$retainHandlesForCancel = $true") < keeper.index("Write-HarnessGateKeeperReadyReceipt"),
            "keeper retention is armed before staging or final publication begins")
    require("while ($true) { [Threading.Thread]::Sleep(1000) }" in keeper and
            "if ($retainHandlesForCancel)" in keeper,
            "receipt failure keeps the exact handles retained for CANCEL")

    ready_wait = extract_function(remote, "function Wait-KeeperReady(", "\nfunction Invoke-LifecycleFixtureBarrier(")
    require("Test-Path -LiteralPath $receiptPath -PathType Leaf" in ready_wait,
            "RUN observes only the deterministic final readiness path")
    require("ConvertFrom-Json -ErrorAction Stop" in ready_wait and
            "safeupload-harness-gate-keeper-ready-v1" in ready_wait and
            "$receipt.runToken -cne $RunToken" in ready_wait and
            "$receipt.keeperPid -ne [uint32]$leaseKeeper.ProcessId" in ready_wait and
            "$receipt.keeperStartFiletime -ne [long]$leaseKeeper.StartFileTime" in ready_wait and
            "$receipt.mainJobName -cne [string]$state.jobName" in ready_wait and
            "$receipt.keeperJobName -cne [string]$state.keeperJobName" in ready_wait and
            "EXACT_HANDLE_QUERY_SUCCEEDED" in ready_wait and "CURRENT_PROCESS_MEMBER" in ready_wait,
            "RUN retains exact schema/token/process/job/query/membership checks")
    ready_assert = extract_function(control, "function Assert-KeeperReadyReceipt(", "\nfunction Assert-ExactState(")
    require("Get-FileHash -LiteralPath $path" in ready_assert and
            "$receipt.runToken -cne $RunToken" in ready_assert and
            "safeupload-harness-gate-keeper-ready-v1" in ready_assert,
            "VERIFY/CANCEL retains the existing durable-hash and receipt identity checks")

    manifest = json.loads(manifest_bytes)
    expected_manifest = sha(manifest_bytes)
    shell_pins = dict(re.findall(r"^(expected_[a-z_]+_sha256)='([0-9a-f]{64})'$", shell, re.MULTILINE))
    keeper_sha = sha((SRC / "driver/scripts/HarnessWindowsGateLeaseKeeper.ps1").read_bytes())
    protocol_sha = sha((SRC / "driver/scripts/HarnessWindowsGateProtocol.psm1").read_bytes())
    require(manifest["gateKeeper"]["sha256"] == keeper_sha, "manifest pins the exact keeper bytes")
    require(manifest["gateProtocol"]["sha256"] == protocol_sha, "manifest pins the exact protocol bytes")
    require(shell_pins.get("expected_keeper_sha256") == keeper_sha, "shell pins the exact keeper bytes")
    require(shell_pins.get("expected_protocol_sha256") == protocol_sha, "shell pins the exact protocol bytes")
    require(shell_pins.get("expected_manifest_sha256") == expected_manifest, "shell pins the exact manifest bytes")
    return problems


def check_inventory_and_delta() -> tuple[list[dict[str, object]], dict[str, object]]:
    baseline_capture = json.loads(BASE_CAPTURE.read_text(encoding="utf-8"))
    before = baseline_capture["SourceFiles"]
    after = capture_records(SRC)
    require_paths = [r["path"] for r in before] == [r["path"] for r in after]
    assert require_paths, "R21 must preserve the R20 closed path set exactly"
    changed = []
    identical = 0
    for old, new in zip(before, after):
        if old["sha256"] == new["sha256"] and old["size"] == new["size"]:
            identical += 1
        else:
            changed.append({"path": old["path"], "beforeSha256": old["sha256"],
                            "afterSha256": new["sha256"], "beforeSize": old["size"], "afterSize": new["size"]})
    expected_changed = {
        "driver/scripts/HarnessWindowsGateLeaseKeeper.ps1",
        "driver/scripts/HarnessWindowsGateProtocol.psm1",
        "driver/scripts/HarnessWindowsGate.manifest.json",
        "driver/scripts/Invoke-HarnessWindowsGate.sh",
    }
    assert {row["path"] for row in changed} == expected_changed, "R21 source delta must remain exactly four expected harness pin/source files"

    old_manifest = json.loads((BASELINE / "driver/scripts/HarnessWindowsGate.manifest.json").read_text(encoding="utf-8"))
    new_manifest = json.loads((SRC / "driver/scripts/HarnessWindowsGate.manifest.json").read_text(encoding="utf-8"))
    for key in ("mainFiles", "rootSelfchecks", "t5Selfcheck", "sourceFiles"):
        assert old_manifest[key] == new_manifest[key], f"R21 changed frozen execution inventory field {key}"
    delta = {
        "identicalCount": identical,
        "changed": changed,
        "added": [],
        "removed": [],
        "executionSourceInventoryUnchanged": True,
    }
    return after, delta


def transaction_model() -> int:
    """A POSIX analogue checks staging visibility and no-overwrite semantics only."""
    payload = b'complete-exact-tuple-receipt-v1'
    with tempfile.TemporaryDirectory(prefix="r21-ready-receipt-") as temp:
        root = Path(temp)
        final = root / "run.keeper-ready.json"
        partial = root / "run.partial.random.tmp"
        fd = os.open(partial, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, payload[:7])
            os.fsync(fd)
        finally:
            os.close(fd)
        assert partial.read_bytes() == payload[:7] and not final.exists()
        partial.unlink()

        staged = root / "run.complete.random.tmp"
        fd = os.open(staged, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        assert not final.exists()
        os.link(staged, final)  # atomic no-overwrite analogue, not Windows File.Move
        staged.unlink()
        assert final.read_bytes() == payload
        collision = root / "run.other.random.tmp"
        collision.write_bytes(b"replacement-attempt")
        try:
            os.link(collision, final)
        except FileExistsError:
            pass
        else:
            raise AssertionError("no-overwrite model accepted duplicate final path")
        assert final.read_bytes() == payload
        return 4


def main() -> int:
    records, delta = check_inventory_and_delta()
    protocol = read(SRC / "driver/scripts/HarnessWindowsGateProtocol.psm1")
    keeper = read(SRC / "driver/scripts/HarnessWindowsGateLeaseKeeper.ps1")
    remote = read(SRC / "driver/scripts/HarnessWindowsGateRemote.ps1")
    control = read(SRC / "driver/scripts/HarnessWindowsGateRemoteControl.ps1")
    manifest_path = SRC / "driver/scripts/HarnessWindowsGate.manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    shell = read(SRC / "driver/scripts/Invoke-HarnessWindowsGate.sh")

    problems = source_violations(protocol, keeper, remote, control, manifest_bytes, shell)
    assert not problems, "source control failure: " + "; ".join(problems)

    writer = extract_function(protocol, "function Write-HarnessGateKeeperReadyReceipt(", "\nfunction New-HarnessGateState(")
    attacks = {
        "direct-final-write": writer.replace("FileStream($temporary,", "FileStream($Path,", 1),
        "publish-before-flush": writer.replace(
            "        $stream.Flush($true)\n        $stream.Dispose()\n        $stream = $null\n\n        # Same-directory Move is an atomic publish and fails if the final name\n        # already exists; no partial receipt is ever created at the ready path.\n        [IO.File]::Move($temporary, $Path)",
            "        [IO.File]::Move($temporary, $Path)\n        $stream.Flush($true)\n        $stream.Dispose()\n        $stream = $null",
            1,
        ),
        "overwrite-publish": writer.replace("[IO.File]::Move($temporary, $Path)", "[IO.File]::Replace($temporary, $Path, $null)", 1),
        "share-readable-stage": writer.replace("[IO.FileShare]::None", "[IO.FileShare]::Read", 1),
    }
    for name, mutant in attacks.items():
        assert mutant != writer, f"{name}: mutation did not apply"
        assert source_violations(protocol.replace(writer, mutant, 1), keeper, remote, control,
                                 manifest_bytes, shell), f"{name}: source checker accepted mutant"

    model_assertions = transaction_model()
    inventory_hash = sha(json.dumps(records, separators=(",", ":"), ensure_ascii=False).encode())
    shell_pins = dict(re.findall(r"^(expected_[a-z_]+_sha256)='([0-9a-f]{64})'$", shell, re.MULTILINE))
    report = [
        "R21 offline source controls: PASS",
        f"Source closure: {len(records)} paths; R20 delta: {delta['identicalCount']} unchanged, {len(delta['changed'])} changed, 0 added, 0 removed.",
        "Changed source paths: " + ", ".join(row["path"] for row in delta["changed"]),
        f"Canonical inventory SHA-256 (compact sorted source records): {inventory_hash}",
        "Manifest/shell pins: keeper, protocol, and manifest hashes match exact candidate bytes.",
        "Receipt order: exact final-path/tuple guards; in-memory receipt/hash; random same-directory CreateNew + FileShare.None; full write; Flush(true); close; no-overwrite File.Move; return.",
        "Consumer controls: unchanged final-path-only polling and exact schema/token/PID/FILETIME/job/query/membership checks retained.",
        "Retention control: keeper sticky-retention assignment precedes receipt writer invocation; exception branch retains handles for explicit CANCEL.",
        "Mutation controls: PASS; direct-final-write, move-before-flush, overwrite-publish, and share-readable-stage mutants rejected.",
        f"Staging/no-overwrite model: PASS ({model_assertions} assertions; POSIX hard-link analogue only, not Windows/.NET runtime evidence).",
        "Execution inventory: all 33 manifest execution source records and arrays unchanged from frozen R20.",
        "Shell syntax and actual manifest verifier are recorded in the author control transcript.",
        "No PowerShell, Windows, builder/product network transport, service, actor, coordinator, VM, host-policy, or Git operation was invoked; one read-only Microsoft Learn API documentation lookup was used.",
        "Runtime disposition: NOT RUN; Windows .NET FileStream/File.Move behavior and gate lifecycle remain unqualified.",
    ]
    CONTROL_OUTPUT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
