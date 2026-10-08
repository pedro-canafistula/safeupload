#!/usr/bin/env python3
"""Validate a complete Inspector --admission-trace upper W01 write window.

This never qualifies W01/W02: lower-filter, raw-volume and runtime evidence
must be checked independently. Input is bounded JSONL from the actual Inspector.
"""
import argparse
import json
import re
import sys
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
MAX_LINE = 4096
RING_ENTRIES = 16384  # Protocol.h, SAFEUPLOAD_ADMISSION_TRACE_RING_ENTRIES
U64 = (1 << 64) - 1
IRP_NOCACHE = 0x00000001
IRP_PAGING_IO = 0x00000002
HEX64 = re.compile(r"0x[0-9A-Fa-f]{16}\Z")
HEX32 = re.compile(r"0x[0-9A-Fa-f]{8}\Z")
FILE_ID = re.compile(r"[0-9A-Fa-f]{32}\Z")


class Invalid(ValueError):
    pass


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate JSON key: " + key)
        result[key] = value
    return result


def no_float(value):
    raise Invalid("non-integer JSON number: " + value[:24])


def bounded_integer(value):
    if len(value) > 21:
        raise Invalid("JSON integer exceeds unsigned 64-bit width")
    return int(value)


def uint(value, name, maximum=U64):
    if type(value) is not int or not 0 <= value <= maximum:
        raise Invalid(name + " must be an exact unsigned integer")
    return value


def hex_value(value, name, pattern):
    if type(value) is not str or not pattern.fullmatch(value):
        raise Invalid(name + " has wrong hex encoding")
    return int(value, 16)


def parse_file_id(value):
    if type(value) is not str or not FILE_ID.fullmatch(value):
        raise Invalid("fileId must encode all 16 bytes")
    if int(value, 16) == 0:
        raise Invalid("fileId is unbound/zero")
    return value.upper()


def load_lines(path):
    with path.open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    if not raw or len(raw) > MAX_BYTES:
        raise Invalid("dump size outside 1..8 MiB")
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    try:
        lines = raw.decode(encoding).splitlines()
    except UnicodeDecodeError as exc:
        raise Invalid("invalid UTF-8/UTF-16 dump") from exc
    if len(lines) > RING_ENTRIES + 1:
        raise Invalid("too many dump lines")
    for number, line in enumerate(lines, 1):
        if len(line.encode("utf-8")) > MAX_LINE or "\x00" in line:
            raise Invalid("dump line exceeds 4096 bytes or contains NUL")
        try:
            obj = json.loads(line, object_pairs_hook=no_duplicate_keys,
                             parse_int=bounded_integer, parse_float=no_float,
                             parse_constant=no_float)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise Invalid("invalid JSON at line %d: %s" % (number, exc)) from exc
        if type(obj) is not dict:
            raise Invalid("line %d is not a JSON object" % number)
        yield obj


def require_fields(obj, names, location):
    missing = set(names) - set(obj)
    if missing:
        raise Invalid(location + " missing " + ",".join(sorted(missing)))


W_FIELDS = (
    "sequence", "event", "ticketSequence", "callbackData", "instance",
    "targetFileObject", "sectionObjectPointer", "pid", "major", "minor",
    "irpFlags", "volumeSerial",
    "fileId", "writeOffset", "writeLength", "operationCode", "completionFlags",
    "registrySnapshotFlags", "registryUnknownReasons", "ioStatus", "H", "W",
    "registryState", "activationGeneration", "policyGeneration", "ioInformation",
)
SUMMARY_FIELDS = ("summary", "totalEvents", "pagingWrites", "nonPagingWrites",
                  "sectionAcquires", "sectionReleases", "instanceSetups",
                  "lostEntries", "cursor", "snapshotSequence")


def validate(path, expected):
    alignment = uint(expected["alignment"], "alignment", 65536)
    offset = uint(expected["offset"], "offset")
    length = uint(expected["length"], "length", (1 << 32) - 1)
    flags_pin = uint(expected["irp_flags"], "irp_flags", (1 << 32) - 1)
    pair_count = uint(expected["pairs"], "pairs", RING_ENTRIES)
    if length == 0 or offset + length > U64:
        raise Invalid("empty/overflow write range")
    if pair_count != 1:
        raise Invalid("W01 requires exactly one W ticket")
    if alignment < 512 or alignment & (alignment - 1):
        raise Invalid("alignment must be a power of two in 512..65536")
    if offset % alignment or length % alignment:
        raise Invalid("write offset/length are not aligned")
    if not flags_pin & IRP_NOCACHE or flags_pin & IRP_PAGING_IO:
        raise Invalid("expected IRP flags are cached or paging I/O")
    rows = list(load_lines(path))
    if len(rows) < 3:
        raise Invalid("need W begin/end and final summary")
    summary = rows[-1]
    require_fields(summary, SUMMARY_FIELDS, "summary")
    if summary["summary"] is not True or any("summary" in row for row in rows[:-1]):
        raise Invalid("exactly one final summary required")
    for name in SUMMARY_FIELDS[1:]:
        uint(summary[name], name)
    records = rows[:-1]
    snapshot = summary["snapshotSequence"]
    if not 1 <= snapshot <= RING_ENTRIES or summary["cursor"] != snapshot + 1:
        raise Invalid("summary does not prove a complete bounded snapshot")
    if summary["lostEntries"] != 0:
        raise Invalid("trace reported lost/overwritten entries")
    if summary["totalEvents"] != snapshot or len(records) != snapshot:
        raise Invalid("clear-to-snapshot event count is incomplete")
    pairs = {}
    ended = set()
    for index, row in enumerate(records, 1):
        seq = uint(row.get("sequence"), "sequence")
        if seq != index:
            raise Invalid("noncontiguous event sequence at record %d" % index)
        event = row.get("event")
        if type(event) is not str:
            raise Invalid("event name missing")
        if event not in ("w_begin", "w_end"):
            continue
        require_fields(row, W_FIELDS, event)
        ticket = uint(row["ticketSequence"], "ticketSequence")
        if ticket == 0:
            raise Invalid("zero W ticket")
        if parse_file_id(row["fileId"]) != expected["file_id"]:
            raise Invalid("wrong exact FileId128")
        if hex_value(row["volumeSerial"], "volumeSerial", HEX64) != expected["serial"]:
            raise Invalid("wrong exact volume serial")
        for name in ("instance", "targetFileObject", "sectionObjectPointer", "callbackData"):
            value = hex_value(row[name], name, HEX64)
            if value == 0 or (expected[name] is not None and value != expected[name]):
                raise Invalid("wrong or zero request identity: " + name)
        if uint(row["pid"], "pid", (1 << 32) - 1) != expected["pid"]:
            raise Invalid("wrong request PID")
        if uint(row["major"], "major", 255) != 4 or uint(row["minor"], "minor", 255) != 0:
            raise Invalid("wrong operation (expected IRP_MJ_WRITE/minor 0)")
        flags = hex_value(row["irpFlags"], "irpFlags", HEX32)
        if not flags & IRP_NOCACHE or flags & IRP_PAGING_IO or flags != expected["irp_flags"]:
            raise Invalid("wrong request IRP flags")
        if uint(row["operationCode"], "operationCode", (1 << 32) - 1) != 0:
            raise Invalid("non-write operation code")
        if (uint(row["writeOffset"], "writeOffset") != expected["offset"] or
                uint(row["writeLength"], "writeLength", (1 << 32) - 1) != expected["length"]):
            raise Invalid("wrong write range")
        for name in ("H", "W", "registryState", "activationGeneration",
                     "policyGeneration"):
            uint(row[name], name, (1 << 32) - 1)
        information = uint(row["ioInformation"], "ioInformation")
        if hex_value(row["registryUnknownReasons"], "registryUnknownReasons", HEX32) != 0:
            raise Invalid("registry identity/state unknown")
        snapshot_flags = hex_value(row["registrySnapshotFlags"], "registrySnapshotFlags", HEX32)
        completion = hex_value(row["completionFlags"], "completionFlags", HEX32)
        status = hex_value(row["ioStatus"], "ioStatus", HEX32)
        if event == "w_begin":
            if ticket in pairs or ticket in ended:
                raise Invalid("double W_BEGIN ticket")
            if (snapshot_flags != 3 or completion != 0 or status != 0x103 or
                    information != 0 or row["W"] == 0):
                raise Invalid("bad W_BEGIN snapshot/completion/pending state")
            pairs[ticket] = row
        else:
            if ticket in ended or ticket not in pairs:
                raise Invalid("unmatched or double W_END ticket")
            if snapshot_flags != 7 or completion != 1:
                raise Invalid("bad W_END post-retire/lower-completion flags")
            if status != 0 or information != expected["length"]:
                raise Invalid("W_END was not a full STATUS_SUCCESS write")
            begin = pairs.pop(ticket)
            for name in ("callbackData", "instance", "targetFileObject", "sectionObjectPointer", "pid",
                         "major", "minor", "irpFlags", "volumeSerial", "fileId",
                         "writeOffset", "writeLength", "operationCode"):
                if begin[name] != row[name]:
                    raise Invalid("W pair request identity changed: " + name)
            ended.add(ticket)
    if pairs:
        raise Invalid("unmatched W_BEGIN ticket")
    if len(ended) != expected["pairs"]:
        raise Invalid("wrong W pair count")
    return {"upperLedger": "PAIRED_W01_SUCCESS_STATUS", "pairedTickets": sorted(ended),
            "snapshotSequence": snapshot, "eventCount": len(records),
            "W01": "NOT_QUALIFIED", "W02": "NOT_QUALIFIED",
            "Phase4": "NOT_QUALIFIED",
            "scope": "upper W01 ticket/status only; lower/raw/runtime evidence required"}


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path)
    parser.add_argument("--file-id", required=True, help="32 hex digits, FileId128 bytes")
    parser.add_argument("--volume-serial", required=True, help="0x plus 16 hex digits")
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--offset", required=True, type=int)
    parser.add_argument("--length", required=True, type=int)
    parser.add_argument("--irp-flags", required=True, help="exact flags with IRP_NOCACHE set, IRP_PAGING_IO clear")
    parser.add_argument("--alignment", required=True, type=int, help="externally pinned sector alignment, 512..65536 power of two")
    parser.add_argument("--instance", help="optional externally pinned 0x+16 hex")
    parser.add_argument("--target-file-object", help="optional externally pinned 0x+16 hex")
    parser.add_argument("--section-object-pointer", help="optional externally pinned upper stream pointer")
    parser.add_argument("--callback-data", help="optional upper callback pointer pin only")
    parser.add_argument("--pairs", type=int, default=1)
    args = parser.parse_args()
    try:
        expected = {"file_id": parse_file_id(args.file_id),
                    "serial": hex_value(args.volume_serial, "volumeSerial", HEX64),
                    "pid": uint(args.pid, "pid", (1 << 32) - 1),
                    "offset": uint(args.offset, "offset"),
                    "length": uint(args.length, "length", (1 << 32) - 1),
                    "irp_flags": hex_value(args.irp_flags, "irpFlags", HEX32),
                    "alignment": uint(args.alignment, "alignment", 65536),
                    "pairs": uint(args.pairs, "pairs", RING_ENTRIES),
                    "instance": None, "targetFileObject": None,
                    "sectionObjectPointer": None, "callbackData": None}
        if expected["length"] == 0 or expected["pairs"] == 0 or expected["offset"] + expected["length"] > U64:
            raise Invalid("empty/overflow write range or pair count")
        for name, value in (("instance", args.instance), ("targetFileObject", args.target_file_object),
                            ("sectionObjectPointer", args.section_object_pointer),
                            ("callbackData", args.callback_data)):
            if value is not None:
                expected[name] = hex_value(value, name, HEX64)
        result = validate(args.dump, expected)
        code = 0
    except (Invalid, OSError) as exc:
        result = {"upperLedger": "INCONCLUSIVE", "reason": str(exc),
                  "W01": "NOT_QUALIFIED", "W02": "NOT_QUALIFIED",
                  "Phase4": "NOT_QUALIFIED"}
        code = 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(cli())
