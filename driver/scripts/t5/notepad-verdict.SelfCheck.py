#!/usr/bin/env python3
"""Exercise the actual T5 host verdict helpers without starting a VM."""
import ast
import copy
import hashlib
import pathlib
import re

launcher = pathlib.Path(__file__).resolve().parents[1] / "Invoke-StageNotepad.sh"
blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", launcher.read_text(), re.S)
parsed = [ast.parse(block) for block in blocks]
required = {"valid_raw_sample", "native_steps_match", "forced_order_matches", "approved_public_hash_map", "writer_registry_verdict", "staging_empty_verdict",
            "transient_observation_error", "raw_samples_accepted", "workflow_observed_bytes_match", "journal_settled_verdict"}
constants = {"T5_TRANSIENT_PHASES", "T5_TRANSIENT_ERRORS"}
functions = [node for tree in parsed for node in tree.body
             if (isinstance(node, ast.FunctionDef) and node.name in required) or
             (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets))]
assert {node.name for node in functions if isinstance(node, ast.FunctionDef)} == required, "Actual verdict helpers missing"
assert sum(isinstance(node, ast.Assign) for node in functions) == len(constants), "Transient error constants missing"
import json
required_cases = json.loads((launcher.parent / 't5/notepad-cases.json').read_text())
leaves = {leaf.lower() for c in required_cases for leaf in [c['Leaf'], *c.get('AuxiliaryLeaves', [])]}
scope = r"c:\protected\t5"
environment = {"re": re, "json": json, "hashlib": hashlib, "required_cases": required_cases, "expected_leaves": leaves, "scope_path": scope,
               "ro": {"BootId": "control-boot"},
               "baseline_parent": [{"FileId": "parent-full-id", "Reference": "parent-reference"}]}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(launcher), "exec"), environment)
environment["approved_public_hashes"] = environment["approved_public_hash_map"]()
checks = 0


def check(value, message):
    global checks
    checks += 1
    if not value:
        raise AssertionError(message)


def sample(sequence, leaf, public_empty):
    images, readers, native, entries = [], [], [], []
    empty_sha = hashlib.sha256(b"").hexdigest().upper()
    for current in sorted(leaves):
        path = scope + "\\" + current
        exists = public_empty and current == leaf
        image = {"Path": path, "Absent": not exists, "FileId": None, "Reference": None,
                 "LogicalArtifact": None, "Length": None, "Sha256": None, "FileNames": []}
        reader = {"Path": path, "Status": "ABSENT"}
        if exists:
            identity = "0123456789ABCDEF0123456789ABCDEF"
            name = {"Name": current, "Namespace": 1, "Reference": "file-reference", "Parent": "parent-reference"}
            image.update(FileId=identity, Reference="file-reference", Length=0, Sha256=empty_sha,
                         LogicalArtifact={"Path": r"C:\T5\raw\empty.bin", "Length": 0, "Sha256": empty_sha}, FileNames=[name])
            reader.update(Status="OK", Length=0, Sha256=empty_sha)
            entries.append(copy.deepcopy(name))
            for unbuffered in (False, True):
                native.append({"Path": path, "Unbuffered": unbuffered, "Status": "OK", "Length": 0,
                               "Sha256": empty_sha, "BeforeFileId": identity, "AfterFileId": identity})
        images.append(image)
        readers.append(reader)
    return {"Sequence": sequence, "ModuleSequence": sequence, "Status": "OK", "RawComplete": True,
            "IndependentReadersAgree": True, "NativeReaderCoverageComplete": True, "DirectoryComplete": True,
            "Phase": "ControlProbeAfterTestCreateCloseBeforeDeleteOrSave", "TargetAbsent": not public_empty,
            "ForbiddenBytesObserved": False, "CurrentImages": images, "PublicReaders": readers, "ObserverReaders": native,
            "ParentFileId": "parent-full-id", "ParentReference": "parent-reference", "DirectoryEntries": entries,
            "Start": {"BootId": "control-boot", "Qpc": sequence * 100, "QpcFrequency": 1000},
            "End": {"BootId": "control-boot", "Qpc": sequence * 100 + 20, "QpcFrequency": 1000}}


def case(after_publication):
    op = "probe-delete-after-publication" if after_publication else "probe-delete-before-seal"
    order = "DeleteAfterObservedPublication" if after_publication else "DeleteBeforeSeal"
    leaf = "probe-after-publication.txt" if after_publication else "probe-delete.txt"
    observations = [sample(1, leaf, after_publication), sample(2, leaf, after_publication)]
    path = scope + "\\" + leaf
    steps = ("test-create=0 test-close=0 test-delete=0" if after_publication
             else "test-create=0 test-delete=0 test-close=0") + " save-create=0 save-write=0 save-close=0"
    entry = {"IsV20": True, "DestinationPath": path, "State": "5" if after_publication else "0",
             "SealedOnce": after_publication, "SealedLength": 0 if after_publication else None,
             "Sha256Hex": hashlib.sha256(b"").hexdigest().upper() if after_publication else None,
             "DriverInstanceId": "94bedc1e-c804-4d65-b643-fa10eb398b25", "TransferId": "644729ee-b29a-47a7-97cf-94356762762b",
             "StageIdentity": {"VolumeSerialNumber": 2**64 - 1, "FileIdHigh": 2**64 - 1, "FileIdLow": 17}}
    target = next(image for image in observations[-1]["CurrentImages"] if image["Path"] == path)
    ready = {"N": 1, "Op": op, "ProbeCreated": True, "WritableProbeHandleHeld": not after_publication, "ForcedOrder": order}
    if after_publication:
        ready["RequiredObservation"] = "PublicEmptyFile"
    return {"Op": op, "Path": path, "Ack": {"N": 1, "ForcedOrder": order, "Steps": steps},
            "NativeStepsChecked": True, "NativeStepsOk": True,
            "ForcedOrderProof": {"Verified": True, "Op": op, "ActorReady": ready, "RawSequences": [1, 2],
                                 "FinalRawSequence": 2, "Target": copy.deepcopy(target), "Journal": [entry],
                                 "CapturedBeforeGoQpc": 250}}, observations


valid_raw = environment["valid_raw_sample"]
valid_order = environment["forced_order_matches"]
valid_steps = environment["native_steps_match"]
before, before_samples = case(False)
after, after_samples = case(True)
check(all(valid_raw(s) for s in before_samples + after_samples), "Complete control observations must validate")
check(valid_order(before, before_samples) and valid_steps(before), "Held-writer native order must validate")
check(valid_order(after, after_samples) and valid_steps(after), "Observed zero-byte publication native order must validate")

bad = copy.deepcopy(before)
bad["ForcedOrderProof"]["ActorReady"]["WritableProbeHandleHeld"] = False
check(not valid_order(bad, before_samples), "Before-seal order must retain the writer")
bad = copy.deepcopy(before)
bad["ForcedOrderProof"]["Journal"][0]["SealedOnce"] = True
check(not valid_order(bad, before_samples), "Already sealed is not delete-before-seal")
bad = copy.deepcopy(before)
bad["Ack"]["Steps"] = after["Ack"]["Steps"]
check(not valid_order(bad, before_samples), "Close-before-delete cannot claim held-writer deletion")
bad = copy.deepcopy(after)
bad["ForcedOrderProof"]["RawSequences"] = [1, 3]
check(not valid_order(bad, after_samples), "Unobserved raw sequence cannot authorize the gate")
bad = copy.deepcopy(after)
bad["ForcedOrderProof"]["CapturedBeforeGoQpc"] = 210
check(not valid_order(bad, after_samples), "Observation after actor release cannot prove the order")
bad = copy.deepcopy(after)
bad["ForcedOrderProof"]["Journal"][0]["State"] = "4"
check(not valid_order(bad, after_samples), "Publishing is not a completed publication receipt")
bad = copy.deepcopy(after)
bad["ForcedOrderProof"]["Journal"][0]["SealedLength"] = None
check(not valid_order(bad, after_samples), "Unmeasured length is not inspected empty content")
bad_samples = copy.deepcopy(after_samples)
bad_samples[-1]["ObserverReaders"][-1]["AfterFileId"] = "different-full-id"
check(not valid_order(after, bad_samples), "Changed native file identity invalidates the raw gate")
bad_samples = copy.deepcopy(after_samples)
bad_samples[-1]["DirectoryEntries"] = []
check(not valid_order(after, bad_samples), "Incomplete raw parent index invalidates the gate")
bad_samples = copy.deepcopy(after_samples)
bad_samples[-1]["ForbiddenBytesObserved"] = True
check(not valid_order(after, bad_samples), "Forbidden bytes invalidate the raw observation gate")
bad = copy.deepcopy(after)
bad["Ack"]["Steps"] = bad["Ack"]["Steps"].replace("test-delete=0", "test-delete=5")
check(not valid_steps(bad), "A failed DeleteFileW is never a native control pass")

# Owner 2026-10-21: an ActorRunning sample may straddle a publication; the raw image must match the before or the after read,
# and a change between them must be approved bytes. Other phases stay strict.
def straddle(after_status, after_bytes, phase="ActorRunning", before_present=False):
    leaf = "probe-after-publication.txt"
    s = sample(3, leaf, False)
    s["Phase"] = phase
    s["PublicReadersBefore"] = copy.deepcopy(s["PublicReaders"])
    path = scope + "\\" + leaf
    for reader in s["PublicReaders"] + (s["PublicReadersBefore"] if before_present else []):
        if reader["Path"] == path:
            reader.update(Status=after_status, Length=len(after_bytes), Sha256=hashlib.sha256(after_bytes).hexdigest().upper())
    return s
check(valid_raw(straddle("OK", b"")), "A raw-absent capture before an approved empty publication must validate")
check(valid_raw(straddle("OK", b"T5 ProbeDeleteAfterPublication clean text")), "A straddled publication of the case's clean text must validate")
check(not valid_raw(straddle("OK", b"T5 notepad CPF: 529.982.247-25")), "A straddle onto unapproved bytes must fail")
check(not valid_raw(straddle("OK", b"", phase="AfterActorOutcomeSettlement")), "Bracketed reads outside ActorRunning must fail")
check(not valid_raw(straddle("OK", b"", before_present=True)), "A raw image matching neither public read must fail")
# D7 rev 5 (m2t5ord9): the row records the driver's writer registry and requires it to stay Known; missing evidence is never PASS.
registry = environment["writer_registry_verdict"]
def writer_state(**changes):
    state = {"registryUnknownReasons": 0, "registryInstanceUnknown": 0, "writerSopUnknownCount": 0, "cleanupUnmatched": 0,
             "untrackedCreates": 0, "writerGlobalFirstUnknown": {"reason": 0, "site": 0},
             "writerEntryFirstUnknown": {"reason": 0, "site": 0}, "writerSopFirstUnknown": {"reason": 0, "site": 0}}
    state.update(changes)
    return "AFTER_DONE=False\nWRITER_STATE=" + json.dumps(state, separators=(",", ":")) + "\nAFTER_DONE=True\n"
check(registry(writer_state())[0] == "PASS", "A Known registry must pass")
check(registry(writer_state(registryUnknownReasons=64))[0] == "FAIL", "A sticky Unknown mask must fail")
check(registry(writer_state(registryInstanceUnknown=1))[0] == "FAIL", "An Unknown instance must fail")
check(registry(writer_state(writerSopUnknownCount=1))[0] == "FAIL", "An Unknown section pointer must fail")
check(registry(writer_state(writerGlobalFirstUnknown={"reason": 6, "site": 3141}))[0] == "FAIL", "A recorded first-Unknown origin must fail")
check(registry(writer_state(writerEntryFirstUnknown={"reason": 2, "site": 9}))[0] == "FAIL", "An entry-level Unknown origin must fail")
failed = registry(writer_state(registryUnknownReasons=64, writerGlobalFirstUnknown={"reason": 6, "site": 3141}))[1]
check("globalFirst={\"reason\": 6, \"site\": 3141}" in failed and "unknownReasons=64" in failed, "The failure line carries the reasons and origins")
check(registry("AFTER_DONE=True\n")[0] == "INCONCLUSIVE", "Missing diagnostics are INCONCLUSIVE, never PASS")
check(registry("WRITER_STATE_ERROR=pipe closed\n")[0] == "INCONCLUSIVE" and "pipe closed" in registry("WRITER_STATE_ERROR=pipe closed\n")[1],
      "A diagnostics error is INCONCLUSIVE and reported")
check(registry("WRITER_STATE={\"registryUnknownReasons\":0}\n")[0] == "INCONCLUSIVE", "A partial state is INCONCLUSIVE")
check(registry("WRITER_STATE={\"registryUnknownReasons\":\"0\",\"registryInstanceUnknown\":0,\"writerSopUnknownCount\":0,"
               "\"writerGlobalFirstUnknown\":{\"reason\":0},\"writerEntryFirstUnknown\":{\"reason\":0},\"writerSopFirstUnknown\":{\"reason\":0}}\n")[0] == "INCONCLUSIVE",
      "A non-numeric field is INCONCLUSIVE")
# m2t5ord10: the coordinator cannot see the private staging namespace; the launcher's post-run listing is the leftover proof.
staging = environment["staging_empty_verdict"]
empty_listing = "DIR=C:\\ProgramData\\SafeUpload\\staging-journal\nC:\\ProgramData\\SafeUpload\\staging-journal\\completed|1|2026\nDIR=C:\\ProgramData\\SafeUpload\\staging\n"
check(staging(empty_listing)[0] == "PASS", "An empty staging directory passes; journal files are not stage files")
leftover = empty_listing + "C:\\ProgramData\\SafeUpload\\staging\\e8bc.txt|0|2026\n"
check(staging(leftover)[0] == "FAIL" and "e8bc.txt" in staging(leftover)[1], "A remaining stage file fails and is named")
check(staging("")[0] == "INCONCLUSIVE" and staging("DIR=C:\\ProgramData\\SafeUpload\\staging-journal\n")[0] == "INCONCLUSIVE", "A missing staging listing is INCONCLUSIVE, never PASS")
# Owner 2026-10-22: an ERROR sample from an observation race stops counting only when the very next sample of the same phase is valid.
accepted = environment["raw_samples_accepted"]
RACE = "System.Management.Automation.RuntimeException: Raw image, buffered read, and both fresh native readers do not agree (including absence)."
def error_sample(sequence, phase="ActorRunning", error=RACE, **changes):
    value = {"Sequence": sequence, "ModuleSequence": sequence, "Phase": phase, "Status": "ERROR", "Error": error,
             "ForbiddenBytesObserved": False, "CurrentImages": [], "PublicReaders": []}
    value.update(changes)
    return value
def ok_sample(sequence, phase="ActorRunning"):
    value = sample(sequence, "probe-delete.txt", False)
    value["Phase"] = phase
    return value
check(accepted([ok_sample(1), ok_sample(2)]) == (True, 0), "All-valid samples are accepted with no supersession")
check(accepted([error_sample(1), ok_sample(2)]) == (True, 1), "A race error followed by a valid sample of the same phase is superseded")
check(accepted([ok_sample(1), error_sample(2), ok_sample(3)]) == (True, 1), "A race error between valid samples is superseded")
check(accepted([ok_sample(1), error_sample(2)])[0] is False, "A trailing race error with no successor fails")
check(accepted([error_sample(1), error_sample(2), ok_sample(3)])[0] is False, "Two consecutive race errors fail: only the next sample may supersede")
check(accepted([error_sample(1, "WorkflowSettlement"), ok_sample(2, "WorkflowSettlement")]) == (True, 1), "WorkflowSettlement race errors are superseded too")
check(accepted([error_sample(1), ok_sample(2, "WorkflowSettlement")]) == (True, 1), "The successor may be in the next phase of the same case (owner 2026-10-22)")
check(accepted([error_sample(1), ok_sample(2, "ControlProbeAfterTestCreateCloseBeforeDeleteOrSave")]) == (True, 1), "A control-gate successor supersedes too")
check(accepted([error_sample(1), ok_sample(3)])[0] is False, "The successor must be the very next sequence")
check(accepted([error_sample(1, "AfterActorOutcomeSettlement"), ok_sample(2, "AfterActorOutcomeSettlement")])[0] is False, "The final outcome bracket never qualifies")
check(accepted([error_sample(1, "AfterActorAcknowledgementSettlement"), ok_sample(2, "AfterActorOutcomeSettlement")]) == (True, 1), "The acknowledgement settlement phase qualifies (the agent's late publication lands there)")
check(accepted([error_sample(1, "ControlProbeAfterTestCreateCloseBeforeDeleteOrSave"), ok_sample(2, "ControlProbeAfterTestCreateCloseBeforeDeleteOrSave")])[0] is False, "The control-gate phase never qualifies")
denied = 'System.Management.Automation.RuntimeException: Raw sample status=ERROR; {"Chain":[{"Type":"System.UnauthorizedAccessException","Message":"Access is denied","Stack":"   at Microsoft.PowerShell.Commands.FileSystemProvider.ItemExists(String path, ErrorRecord\\u0026 error)"}]}'
check(accepted([error_sample(1, error=denied), ok_sample(2)]) == (True, 1), "A Test-Path access-denied race on a name being deleted qualifies")
check(accepted([error_sample(1, error='Exception calling "Capture" with "2" argument(s): "Requested record=269245; Wrong record number/sequence or not in use"'), ok_sample(2)]) == (True, 1), "A stale MFT record qualifies")
check(accepted([error_sample(1, error="Raw parent index does not identify the requested name/file reference."), ok_sample(2)]) == (True, 1), "A parent index that has not caught up qualifies")
check(accepted([error_sample(1, error="Raw sample parent FileId/reference differs from the independently captured baseline parent."), ok_sample(2)])[0] is False, "A baseline parent identity mismatch stays fatal")
check(accepted([error_sample(1, error="One or more raw target images or artifacts are missing/incomplete."), ok_sample(2)])[0] is False, "An artifact error stays fatal")
check(accepted([error_sample(1, ForbiddenBytesObserved=True), ok_sample(2)])[0] is False, "A sample with forbidden bytes never qualifies")
check(accepted([error_sample(1, error="CPF or unexpected nonempty fixture bytes were observed in a raw public image."), ok_sample(2)])[0] is False, "Only the known observation-race messages qualify")
check(accepted([error_sample(1, error="Raw sample parent FileId/reference differs from the independently captured baseline parent."), ok_sample(2)])[0] is False, "A parent mismatch is not a race")
lookup = 'Exception calling \\"OpenAttributes\\" with \\"1\\" argument(s): \\"The system cannot find the file specified; Win32=2'
check(accepted([error_sample(1, error=lookup), ok_sample(2)]) == (True, 1), "A name that vanished before the attributes open is a race (serialized quotes)")
check(accepted([error_sample(1, error="Missing lookup but present raw index entry."), ok_sample(2)]) == (True, 1), "A lookup/index disagreement is a race")
check(accepted([error_sample(1, error="Target metadata probe failed, yet the named lookup succeeded."), ok_sample(2)]) == (True, 1), "A name that appeared between the probes is a race")
check(accepted([error_sample(1, error='Exception calling "Capture" with "2" argument(s): "Requested record=272309; Bad signature"'), ok_sample(2)])[0] is False,
      "A lagging MFT record is retried inside the sample, not superseded by the verdict")
invalid_ok = ok_sample(2)
invalid_ok["IndependentReadersAgree"] = False
check(accepted([error_sample(1), invalid_ok])[0] is False, "A successor that is itself invalid does not supersede")
check(accepted([])[0] is False, "No samples are never accepted")
# D8: no unfinished journal entry may remain after the run.
settled = environment["journal_settled_verdict"]
journal_dir = "C:\\ProgramData\\SafeUpload\\staging-journal"
clean_listing = f"DIR={journal_dir}\n{journal_dir}\\completed|1|2026\n{journal_dir}\\driver-epoch.state|192|2026\n{journal_dir}\\completed\\00000001.pack|9|2026\nDIR=C:\\ProgramData\\SafeUpload\\staging\n"
check(settled(clean_listing)[0] == "PASS", "Archived packs and the epoch state are not unfinished entries")
stuck_listing = clean_listing.replace("DIR=C:\\ProgramData\\SafeUpload\\staging\n", f"{journal_dir}\\e8bc5d9dce0211f1a0a580fd768e5436.json|2853|2026\nDIR=C:\\ProgramData\\SafeUpload\\staging\n")
check(settled(stuck_listing)[0] == "FAIL" and "e8bc5d9d" in settled(stuck_listing)[1], "A hot journal entry fails and is named")
check(settled("")[0] == "INCONCLUSIVE" and settled("DIR=C:\\ProgramData\\SafeUpload\\staging\n")[0] == "INCONCLUSIVE", "A missing journal listing is INCONCLUSIVE")
print(f"T5HostVerdictSelfCheck=PASS;Assertions={checks};ProductQualified=False")
