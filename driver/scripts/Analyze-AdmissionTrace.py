#!/usr/bin/env python3
"""Reproduce the section-pointer analysis from raw admission-trace JSON lines.
Usage: Analyze-AdmissionTrace.py <probe-trace.jsonl> [<write-trace.jsonl>]
The probe trace holds the explicit_probe entries (in probe order); the write trace (default: the same
file) holds the unowned paging writes. For each probe prints its SOP and MmDoes result, and every paging
write whose SectionObjectPointer equals that probe's SOP (a different file object is the point)."""
import json, sys

def load(path):
    rows = [json.loads(l) for l in open(path, encoding='utf-8') if l.strip().startswith('{')]
    return [r for r in rows if 'event' in r], [r for r in rows if r.get('summary')][-1]

probe_path = sys.argv[1]
write_path = sys.argv[2] if len(sys.argv) > 2 else probe_path
probe_entries, probe_summary = load(probe_path)
write_entries, write_summary = load(write_path)
print('probe trace :', probe_path, 'lost=%d total=%d' % (probe_summary['lostEntries'], probe_summary['totalEvents']))
print('write trace :', write_path, 'lost=%d total=%d' % (write_summary['lostEntries'], write_summary['totalEvents']))
probes = [e for e in probe_entries if e['event'] == 'explicit_probe']
paging = [e for e in write_entries if e['event'] == 'paging_write']
print('explicit probes: %d, paging writes (all pids): %d' % (len(probes), len(paging)))
for index, p in enumerate(probes):
    matches = [e for e in paging if e['sectionObjectPointer'] == p['sectionObjectPointer']]
    print('probe #%d seq=%d probeFO=%s SOP=%s mmDoes=%s status=%s stage=%s' % (
        index + 1, p['sequence'], p['targetFileObject'], p['sectionObjectPointer'], p['mmDoes'], p['probeStatus'], p['probeStage']))
    if not matches:
        print('    paging writes with this SOP: none')
    for e in matches:
        print('    paging write seq=%d pid=%d writerFO=%s irpFlags=%s sameFileObjectAsProbe=%s' % (
            e['sequence'], e['pid'], e['targetFileObject'], e['irpFlags'], e['targetFileObject'] == p['targetFileObject']))
