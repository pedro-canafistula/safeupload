#!/usr/bin/env python3
"""Synthetic controls based on the committed Inspector formatter's literal JSON."""
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SAMPLE = HERE.parent / "evidence/2026-10-05/rv4-w-inspector-selftest-stdout-b.txt"
spec = importlib.util.spec_from_file_location("validator", HERE / "Validate-StagedWTrace.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def fixture():
    begin, end = [json.loads(line) for line in SAMPLE.read_text(encoding="utf-16").splitlines()]
    for row, sequence in ((begin, 1), (end, 2)):
        row.update(sequence=sequence, pid=123, instance="0x0000000000001111",
                   targetFileObject="0x0000000000002222",
                   sectionObjectPointer="0x0000000000003333", major=4, minor=0,
                   irpFlags="0x00000001", registryUnknownReasons="0x00000000")
    begin.update(ioStatus="0x00000103", ioInformation=0, completionFlags="0x00000000")
    end.update(ioStatus="0x00000000", ioInformation=4096,
               completionFlags="0x00000001")
    summary = dict(summary=True, totalEvents=2, pagingWrites=0, nonPagingWrites=0,
                   sectionAcquires=0, sectionReleases=0, instanceSetups=0,
                   lostEntries=0, cursor=3, snapshotSequence=2)
    expected = dict(file_id="000102030405060708090A0B0C0D0E0F",
                    serial=0x0102030405060708, pid=123, offset=8192, length=4096,
                    irp_flags=1, alignment=4096, pairs=1, instance=0x1111,
                    targetFileObject=0x2222, sectionObjectPointer=0x3333,
                    callbackData=None)
    return [begin, end, summary], expected


def run(rows, expected, raw=None, encoding="utf-8"):
    with tempfile.TemporaryDirectory(prefix="safeupload-wtrace-selftest-") as temp:
        path = Path(temp) / "trace.jsonl"
        path.write_text(raw if raw is not None else
                        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
                        encoding=encoding)
        return validator.validate(path, expected)


def negative(name, mutate):
    rows, expected = fixture()
    raw = mutate(rows, expected)
    try:
        run(rows, expected, raw)
    except validator.Invalid:
        print(name + "=REJECTED")
    else:
        raise AssertionError(name + " was accepted")


def main():
    rows, expected = fixture()
    result = run(rows, expected)
    assert result["upperLedger"] == "PAIRED_W01_SUCCESS_STATUS"
    assert result["pairedTickets"] == [9007199254740993]
    assert result["W01"] == result["W02"] == result["Phase4"] == "NOT_QUALIFIED"
    print("actual-formatter-shape-exact-u64=PAIRED_UPPER_ONLY")
    assert run(rows, expected, encoding="utf-16")["upperLedger"] == "PAIRED_W01_SUCCESS_STATUS"
    print("utf16-bom-capture=PAIRED_UPPER_ONLY")
    with tempfile.TemporaryDirectory(prefix="safeupload-wtrace-cli-") as temp:
        path = Path(temp) / "trace.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        child = subprocess.run([sys.executable, str(HERE / "Validate-StagedWTrace.py"),
                                str(path), "--file-id", expected["file_id"],
                                "--volume-serial", "0x0102030405060708", "--pid", "123",
                                "--offset", "8192", "--length", "4096",
                                "--alignment", "4096", "--irp-flags", "0x00000001",
                                "--instance", "0x0000000000001111",
                                "--target-file-object", "0x0000000000002222",
                                "--section-object-pointer", "0x0000000000003333"],
                               text=True, capture_output=True, timeout=5)
        assert child.returncode == 0 and not child.stderr
        cli_result = json.loads(child.stdout)
        assert cli_result["upperLedger"] == "PAIRED_W01_SUCCESS_STATUS"
        assert all(cli_result[name] == "NOT_QUALIFIED" for name in ("W01", "W02", "Phase4"))
        print("cli-qualification-fields=NOT_QUALIFIED")
    negative("duplicate-key", lambda r, e: '{"sequence":1,"sequence":1}\n')
    negative("float", lambda r, e: (r[0].__setitem__("ticketSequence", 1.5), None)[1])
    negative("loss", lambda r, e: (r[2].__setitem__("lostEntries", 1), None)[1])
    negative("sequence-gap", lambda r, e: (r[1].__setitem__("sequence", 3), None)[1])
    negative("incomplete-window", lambda r, e: (r[2].__setitem__("cursor", 2), None)[1])
    negative("duplicate-ticket", lambda r, e: (r[1].__setitem__("event", "w_begin"), None)[1])
    negative("unmatched-ticket", lambda r, e: (r[1].__setitem__("ticketSequence", 99), None)[1])
    negative("wrong-file-id", lambda r, e: (r[1].__setitem__("fileId", "FF" * 16), None)[1])
    negative("wrong-serial", lambda r, e: (r[1].__setitem__("volumeSerial", "0x0000000000000001"), None)[1])
    negative("wrong-request", lambda r, e: (r[1].__setitem__("targetFileObject", "0x0000000000003333"), None)[1])
    negative("wrong-operation", lambda r, e: (r[1].__setitem__("major", 9), None)[1])
    negative("wrong-range", lambda r, e: (r[1].__setitem__("writeLength", 2048), None)[1])
    negative("wrong-post-flags", lambda r, e: (r[1].__setitem__("completionFlags", "0x00000005"), None)[1])
    negative("missing-exact-snapshot", lambda r, e: (r[1].__setitem__("registrySnapshotFlags", "0x00000005"), None)[1])
    negative("unknown-reason", lambda r, e: (r[1].__setitem__("registryUnknownReasons", "0x00000010"), None)[1])
    negative("zero-sop", lambda r, e: (r[0].__setitem__("sectionObjectPointer", "0x0000000000000000"), None)[1])
    negative("changed-sop", lambda r, e: (r[1].__setitem__("sectionObjectPointer", "0x0000000000004444"), None)[1])
    negative("cached-write", lambda r, e: (r[0].__setitem__("irpFlags", "0x00000000"),
                                           r[1].__setitem__("irpFlags", "0x00000000"),
                                           e.__setitem__("irp_flags", 0), None)[3])
    negative("paging-write", lambda r, e: (r[0].__setitem__("irpFlags", "0x00000003"),
                                           r[1].__setitem__("irpFlags", "0x00000003"),
                                           e.__setitem__("irp_flags", 3), None)[3])
    negative("unaligned-offset", lambda r, e: (r[0].__setitem__("writeOffset", 8193),
                                               r[1].__setitem__("writeOffset", 8193),
                                               e.__setitem__("offset", 8193), None)[3])
    negative("unaligned-length", lambda r, e: (r[0].__setitem__("writeLength", 4095),
                                               r[1].__setitem__("writeLength", 4095),
                                               e.__setitem__("length", 4095), None)[3])
    negative("failure-status", lambda r, e: (r[1].__setitem__("ioStatus", "0xC0000120"), None)[1])
    negative("short-success", lambda r, e: (r[1].__setitem__("ioInformation", 2048), None)[1])
    negative("overlong-success", lambda r, e: (r[1].__setitem__("ioInformation", 8192), None)[1])
    negative("begin-information", lambda r, e: (r[0].__setitem__("ioInformation", 4096), None)[1])
    negative("alignment-one-pin", lambda r, e: (e.__setitem__("alignment", 1), None)[1])
    negative("multiple-pair-pin", lambda r, e: (e.__setitem__("pairs", 2), None)[1])
    negative("offset-overflow", lambda r, e: (e.__setitem__("offset", validator.U64), None)[1])
    negative("bool-ticket", lambda r, e: (r[0].__setitem__("ticketSequence", True), None)[1])
    negative("foreign-w-ticket", lambda r, e: (
        r.insert(2, dict(r[0], sequence=3, ticketSequence=9007199254740994,
                         fileId="FF" * 16)),
        r[3].__setitem__("snapshotSequence", 3), r[3].__setitem__("totalEvents", 3),
        r[3].__setitem__("cursor", 4), None)[4])
    negative("recursive-json", lambda r, e: ("[" * 1300 + "]" * 1300 + "\n"))
    with tempfile.TemporaryDirectory(prefix="safeupload-wtrace-size-") as temp:
        big = Path(temp) / "big.jsonl"
        big.write_bytes(b"x" * (validator.MAX_BYTES + 1))
        try:
            validator.validate(big, fixture()[1])
        except validator.Invalid:
            print("bounded-input=REJECTED")
        else:
            raise AssertionError("oversized input accepted")
    print("ValidatorSelfTest=PASS;WindowsVmQualification=False")


if __name__ == "__main__":
    main()
