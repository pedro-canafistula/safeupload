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
required = {"valid_raw_sample", "native_steps_match", "forced_order_matches"}
functions = [node for tree in parsed for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name in required]
assert {node.name for node in functions} == required, "Actual verdict helpers missing"
import json
leaves = {leaf.lower() for c in json.loads((launcher.parent / 't5/notepad-cases.json').read_text())
          for leaf in [c['Leaf'], *c.get('AuxiliaryLeaves', [])]}
scope = r"c:\protected\t5"
environment = {"re": re, "expected_leaves": leaves, "scope_path": scope,
               "ro": {"BootId": "control-boot"},
               "baseline_parent": [{"FileId": "parent-full-id", "Reference": "parent-reference"}]}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(launcher), "exec"), environment)
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
print(f"T5HostVerdictSelfCheck=PASS;Assertions={checks};ProductQualified=False")
