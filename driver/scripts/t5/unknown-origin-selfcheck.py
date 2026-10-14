#!/usr/bin/env python3
"""Source-only writer Unknown attribution controls; no compiler, network or VM.

Run: python3 driver/scripts/t5/unknown-origin-selfcheck.py
Checks every current loss mutation, caller/deferred origin forwarding, sticky
CAS diagnostics, the census fallback and the complete append-only C/C# layout.
Mutation controls operate on in-memory source copies, never repository files.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
WRITERS = ROOT / 'driver/SafeUpload.Minifilter/StageWriters.c'
HEADER = ROOT / 'driver/SafeUpload.Minifilter/Protocol.h'
MIRROR = ROOT / 'agente/SafeUpload.Agent.Minifilter/DriverDiagnostics.cs'
PROXY = ROOT / 'agente/SafeUpload.Agent.Minifilter/StagedProofProxy.cs'

# Independent baseline, including all pre-existing offsets (Reserved2 is untouched).
LAYOUT = '''
StructSize:0:4 SectionInFlightNow:4:4 PostCreateRuns:8:8 WriteObjectsCounted:16:8
WriteObjectsReleased:24:8 UntrackedCreates:32:8 CleanupUnmatched:40:8 DirectoryCreatesSkipped:48:8
SectionInFlightInserted:56:8 SectionInFlightReleased:64:8 RetiredSectionOverflow:72:8
SectionInFlightStuck:80:8 SectionInFlightRemovedOnFailure:88:8 SectionInFlightMaxDepth:96:4
CleanupDirectoriesSkipped:100:4 PagingCreatesSkipped:104:8 VolumeCreatesSkipped:112:8
StageStreams:120:4 StageFileObjects:124:4 LastUnloadVeto:128:4 LastUnloadStatus:132:4
WritersDroppedAtTeardown:136:8 WritersDroppedWhileMounted:144:8 InstanceTeardownsDismount:152:8
InstanceTeardownsOther:160:8 TxfRefused:168:8 RegistryCapacityFailures:176:8
RegistryAllocationFailures:184:8 RegistryIdentityFailures:192:8 RegistryTransactionFailures:200:8
RegistryRenameFailures:208:8 RegistryDroppedAtDismount:216:8 RegistryDroppedWhileMounted:224:8
RegistryEntries:232:4 RegistryReservations:236:4 RegistryOverflow:240:4 RegistryUnknownReasons:244:4
RegistryInstanceUnknown:248:4 RegistryCapacity:252:4 TransactionAssociations:256:4 Reserved2:260:4
RegistryPruned:264:8 RegistryReclaimPasses:272:8 RegistryNameTierEntries:280:4
RegistryCompactTierEntries:284:4 WriterGlobalFirstUnknown:288:4 WriterEntryFirstUnknown:292:4
WriterSopFirstUnknown:296:4 WriterSopUnknownCount:300:4
'''
EXPECTED = [(name, int(offset), int(size)) for name, offset, size in
            (item.split(':') for item in LAYOUT.split())]


def code(source):
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source, flags=re.S)


def body(text, name):
    for match in re.finditer(r'\b' + re.escape(name) + r'\s*\(', text):
        i = text.index('(', match.start()) + 1
        level = 1
        while level:
            level += {'(': 1, ')': -1}.get(text[i], 0)
            i += 1
        while text[i].isspace():
            i += 1
        if text[i] != '{':
            continue
        start = i
        level = 1
        i += 1
        while level:
            level += {'{': 1, '}': -1}.get(text[i], 0)
            i += 1
        return text[start:i]
    raise AssertionError('Missing production body: ' + name)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def validate_origins(source):
    text = code(source)
    require(len(source.splitlines()) < 65536, 'packed site would truncate')
    require(re.search(r'PSTAGE_REGISTRY_ENTRY PoolNext;\s*volatile LONG FirstUnknown;', text),
            'retain origin in entry tail padding')
    require('FIELD_OFFSET(STAGE_REGISTRY_ENTRY, PoolNext) + sizeof(PSTAGE_REGISTRY_ENTRY) + 15' in text,
            'entry allocation size guard')
    record = body(text, 'StageRegistryRecordOrigin')
    require(re.search(r'\(OriginSite & 0xFFFFUL\) << 16', record), 'site packing')
    require('((ULONG)Reason & 0xFFFFUL)' in record, 'reason packing')
    require('InterlockedCompareExchange(FirstUnknown, packed, 0)' in record, 'first CAS must be sticky')
    counted = body(text, 'StageRegistryRecordCountedEntryOrigin')
    eligible = body(text, 'StageRegistryRecordEligibleEntryOrigin')
    require('if (Entry->Retired || !Entry->Listed) return;' in eligible, 'live/listed census predicate')
    for flag in ('ActivationEnforced', 'AliasProbePending', 'RenameInFlight'):
        require(f'InterlockedCompareExchange(&Entry->{flag}, 0, 0) == 0' in eligible, 'census predicate ' + flag)
    require('LONG packed = InterlockedCompareExchange(&Entry->FirstUnknown, 0, 0);' in counted, 'retained origin')
    require('InterlockedCompareExchange(&WriterEntryFirstUnknown, packed, 0)' in counted, 'counted entry first CAS')
    require('StageRegistryRecordCountedEntryOrigin(Entry);' in eligible, 'eligible publication')
    for name in ('StageRegistryRecordOrigin', 'StageRegistryRecordCountedEntryOrigin',
                 'StageRegistryRecordEligibleEntryOrigin'):
        resident = body(text, name)
        require(not re.search(r'Lock|PAGED_CODE|Allocate|Reference\(', resident), 'origin helper must not acquire resources')
        require(not re.search(r'#pragma alloc_text\(PAGE,\s*' + name, text), 'origin helper must be resident')
    for name in ('WriterGlobalFirstUnknown', 'WriterEntryFirstUnknown', 'WriterSopFirstUnknown'):
        require(f'static volatile LONG {name};' in text, 'zero initialized boot diagnostic')
        require(not re.search(r'(?<![.>])\b' + name + r'\s*=(?!=)', text), 'no direct reset/write')
        require(not re.search(r'Interlocked(?:Exchange|And|Or)\(&' + name, text), 'no diagnostic reset/write')

    # Inventory every global-state write; a future bypass must fail this control.
    writes = list(re.finditer(r'InterlockedExchange\(&WriterGlobalUnknown, 1\);', text))
    require(len(writes) == 2, 'unexpected global escalation path')
    for write in writes:
        require(re.search(r'StageRegistryRecordOrigin\(&WriterGlobalFirstUnknown, Reason, OriginSite\);\s*$',
                          text[:write.start()]), 'global escalation without original site')
    require(len(re.findall(r'Interlocked\w+\(&WriterGlobalUnknown,', text)) ==
            len(writes) + len(re.findall(r'InterlockedCompareExchange\(&WriterGlobalUnknown, 0, 0\)', text)),
            'unaccounted global write')
    require(not re.search(r'\bWriterGlobalUnknown\s*=(?!=)', text), 'direct global write')

    for macro in ('StageRegistryMarkUnknown', 'StageRegistryMarkEntryUnknown',
                  'StageRegistrySetEntryUnknownLocked', 'StageRegistryPublishGlobalUnknown',
                  'StageRegistryMarkSopUnknown'):
        definition = re.search(r'#define ' + macro + r'\([^\n]+\)(?:[^\n]*\\\n)+[^\n]*', text)
        require(definition and macro + 'At(' in definition[0] and '(ULONG)__LINE__' in definition[0],
                'caller origin macro ' + macro)
    entry = body(text, 'StageRegistryMarkEntryUnknownAt')
    require('StageRegistryPublishGlobalUnknownAt(Reason, OriginSite);' in entry, 'queue failure origin')
    worker = body(text, 'StageRegistryUnknownWorker')
    require('StageRegistryPublishGlobalUnknownAt(deferred->Reason, deferred->OriginSite);' in worker,
            'deferred escalation origin')

    # Every entry reason mutation has its own origin, including direct shell and
    # alias classification writes that bypass MarkEntryUnknownAt.
    mutations = list(re.finditer(r'InterlockedOr\(&(\w+(?:->Shell)?)->UnknownReasons, ([^;]+)\);', text))
    mutations = [m for m in mutations if m[1] not in ('context', 'instanceContext')]
    require(all(m[1] == 'Entry' for m in mutations), 'new direct entry reason write')
    require(len(mutations) == 4, 'unexpected entry reason mutation')
    for mutation in mutations:
        reason = re.escape(mutation[2])
        require(re.search(r'StageRegistryRecordOrigin\(&Entry->FirstUnknown,\s*' + reason +
                          r', (?:OriginSite|\(ULONG\)__LINE__)\);\s*$', text[:mutation.start()]),
                'entry reason mutation without origin')
    require(re.search(r'StageRegistryRecordOrigin\(&reservation->Shell->FirstUnknown,\s*'
                      r'SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY, \(ULONG\)__LINE__\);\s*'
                      r'reservation->Shell->UnknownReasons = SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;', text),
            'direct shell origin')
    require(all(lhs in ('reservation->Shell', 'Output', 'Result') for lhs in
                re.findall(r'(\w+(?:->\w+)?)->UnknownReasons\s*=(?!=)', text)),
            'unaccounted direct entry reason write')
    for setter in ('StageRegistrySetEntryUnknownLockedAt', 'StageRegistryMarkEntryUnknownAt',
                   'StageRegistryResolveAliasProbeVersioned', 'StageRegistryResolveAliasProbeForGeneration'):
        require('StageRegistryRecordEligibleEntryOrigin(Entry);' in body(text, setter), 'counted origin ' + setter)
    for mutation in re.finditer(r'InterlockedExchange\(\(volatile LONG \*\)\s*&Entry->State,\s*SAFEUPLOAD_REGISTRY_STATE_UNKNOWN\);', text):
        require(re.match(r'\s*StageRegistryRecordEligibleEntryOrigin\(Entry\);', text[mutation.end():]),
                'each entry Unknown state publication must record eligibility')
    census = body(text, 'SafeUploadStageWritersAdmissionCoverage')
    require(re.search(r'\+\+unknownEntries;\s*StageRegistryRecordCountedEntryOrigin\(entry\);', census),
            'later scope inclusion must retain original event')

    sop = body(text, 'StageRegistryMarkSopUnknownAt')
    require(re.search(r'StageRegistryRecordOrigin\(&WriterSopFirstUnknown, '
                      r'SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY, OriginSite\);\s*slot->Unknown = TRUE;', sop),
            'SOP marker creation origin')
    require(len(re.findall(r'->Unknown\s*=\s*TRUE', text)) == 1, 'unexpected SOP marker creation')
    require(sop.count('StageRegistryRecordOrigin(&WriterSopFirstUnknown,') == 3, 'SOP update origins')
    for reason in ('IDENTITY', 'CAPACITY'):
        require(re.search(r'StageRegistryRecordOrigin\(&WriterSopFirstUnknown, '
                          r'SAFEUPLOAD_REGISTRY_UNKNOWN_' + reason + r', OriginSite\);\s*'
                          r'slot->UnknownReasons \|= SAFEUPLOAD_REGISTRY_UNKNOWN_' + reason + r';', sop),
                'SOP update reason ' + reason)
    require('StageRegistryMarkEntryUnknownAt(existing, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY, OriginSite);' in sop,
            'SOP identity collision entry origin')
    require('StageRegistryMarkUnknownAt(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY, FALSE, OriginSite);' in sop,
            'SOP identity collision instance origin')
    status = body(text, 'SafeUploadStageWritersGetStatus')
    for name, _, _ in EXPECTED[-4:-1]:
        require(f'snapshot.{name} = (UINT32)InterlockedCompareExchange(&{name}, 0, 0);' in status, 'snapshot ' + name)
    require('snapshot.WriterSopUnknownCount = StageRegistryUnknownSopCount();' in status, 'current SOP count')
    require('snapshot.StructSize = sizeof(snapshot);' in status, 'snapshot size')


def validate_layout(header, mirror, proxy):
    h, m = code(header), code(mirror)
    c_struct = re.search(r'typedef struct _SAFEUPLOAD_WRITER_STATE_STATUS \{(.*?)\}', h, re.S)[1]
    cs_struct = re.search(r'public struct SafeUploadWriterStateStatus\s*\{(.*?)\}', m, re.S)[1]
    for text, pattern in ((c_struct, r'UINT(32|64)\s+(\w+)\s*;'),
                          (cs_struct, r'public (uint|ulong)\s+(\w+)\s*;')):
        fields = [(name, 4 if kind in ('32', 'uint') else 8) for kind, name in re.findall(pattern, text)]
        require(fields == [(name, size) for name, _, size in EXPECTED], 'wire field order/types')
        offset = 0
        for (name, size), (_, expected, _) in zip(fields, EXPECTED):
            offset = (offset + size - 1) // size * size
            require(offset == expected, 'wire offset ' + name)
            offset += size
        require(offset == 304, 'wire StructSize')
    # Tail stays inside the existing feature guard, as do all previous extension fields.
    tail = c_struct[c_struct.index('#if defined(SAFEUPLOAD_STAGING_PROTOTYPE)'):]
    require(tail.index('WriterGlobalFirstUnknown') < tail.index('#endif'), 'feature-only append')
    require('Pack = 8' in mirror, 'mirror packing')
    require('WriterStateStatusSize = 304;' in m, 'agent size constant')
    require('sizeof( SAFEUPLOAD_WRITER_STATE_STATUS ) == 304' in h, 'C size assertion')
    for name, offset, _ in EXPECTED[-4:] + [EXPECTED[40]]:
        require(re.search(r'FIELD_OFFSET\( SAFEUPLOAD_WRITER_STATE_STATUS, ' + name + r' \) == ' + str(offset), h),
                'C offset assertion ' + name)
        require(f'CheckWriterOffset(nameof(SafeUploadWriterStateStatus.{name}), {offset});' in m,
                'runtime mirror offset ' + name)
    require('status.StructSize != sizeof(SafeUploadWriterStateStatus)' in m, 'response size rejection')
    require('12 => DiagnosticsContract.WriterStateStatusSize' in code(proxy), 'proof proxy size')


class UnknownOrigins(unittest.TestCase):
    def setUp(self):
        self.source = WRITERS.read_text()
        self.header, self.mirror, self.proxy = HEADER.read_text(), MIRROR.read_text(), PROXY.read_text()

    def test_all_origin_paths(self):
        validate_origins(self.source)

    def test_complete_wire_layout(self):
        validate_layout(self.header, self.mirror, self.proxy)

    def test_removing_each_origin_record_is_detected(self):
        calls = list(re.finditer(r'StageRegistryRecordOrigin\(&[^;]+\);', code(self.source)))
        self.assertGreaterEqual(len(calls), 10)
        for call in calls:
            with self.subTest(site=self.source[:call.start()].count('\n') + 1):
                mutated = self.source[:call.start()] + self.source[call.end():]
                with self.assertRaises(AssertionError):
                    validate_origins(mutated)

    def test_census_deferred_snapshot_and_cas_mutations_are_detected(self):
        for old, new in (
            ('StageRegistryRecordCountedEntryOrigin(entry);', ''),
            ('StageRegistryRecordCountedEntryOrigin(Entry);', ''),
            ('StageRegistryPublishGlobalUnknownAt(deferred->Reason, deferred->OriginSite);',
             'StageRegistryPublishGlobalUnknown(deferred->Reason);'),
            ('StageRegistryPublishGlobalUnknownAt(Reason, OriginSite);', 'StageRegistryPublishGlobalUnknown(Reason);'),
            ('InterlockedCompareExchange(FirstUnknown, packed, 0)', 'InterlockedExchange(FirstUnknown, packed)'),
            ('snapshot.WriterSopUnknownCount = StageRegistryUnknownSopCount();', ''),
            ('if (Entry->Retired || !Entry->Listed) return;', ''),
            ('(OriginSite & 0xFFFFUL) << 16', '(OriginSite & 0xFFFFUL) << 8'),
        ):
            with self.subTest(mutation=old):
                self.assertIn(old, self.source)
                with self.assertRaises(AssertionError):
                    validate_origins(self.source.replace(old, new, 1))

    def test_new_uninstrumented_loss_paths_are_detected(self):
        for statement in (
            'InterlockedExchange(&WriterGlobalUnknown, 1);',
            'InterlockedOr(&entry->UnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP);',
            'slot->Unknown = TRUE;',
        ):
            with self.subTest(statement=statement):
                with self.assertRaises(AssertionError):
                    validate_origins(self.source + '\nstatic VOID Bypass(VOID) { ' + statement + ' }\n')

    def test_layout_mutations_are_detected(self):
        for target, old, new in (
            ('header', 'UINT32 WriterGlobalFirstUnknown;', 'UINT64 WriterGlobalFirstUnknown;'),
            ('header', 'UINT32 Reserved2;', 'UINT32 Repurposed;'),
            ('header', '== 304', '== 288'),
            ('mirror', 'WriterStateStatusSize = 304', 'WriterStateStatusSize = 288'),
            ('mirror', 'public uint WriterEntryFirstUnknown;', 'public ulong WriterEntryFirstUnknown;'),
            ('mirror', 'WriterGlobalFirstUnknown;\n', 'WriterSopFirstUnknown;\n'),
            ('proxy', '12 => DiagnosticsContract.WriterStateStatusSize', '12 => 288'),
        ):
            values = dict(header=self.header, mirror=self.mirror, proxy=self.proxy)
            with self.subTest(target=target, mutation=old):
                self.assertIn(old, values[target])
                values[target] = values[target].replace(old, new, 1)
                with self.assertRaises(AssertionError):
                    validate_layout(**values)


if __name__ == '__main__':
    unittest.main()
