#!/usr/bin/env python3
"""Read matrix TRX Times and report four feature leg wall times and tests over 60 s.

Offline and read-only. Missing/malformed legs are reported with a nonzero exit;
failed tests remain in the duration report. Merged TRX files are not counted twice.
TRX Times come from the guest wall clock, which can jump (~4 h after boot): a leg whose wall time exceeds
its summed test time by more than JUMP_SLACK is flagged; use the host-side elapsed time for that leg.
"""
import argparse
import datetime as dt
from pathlib import Path
import re
import xml.etree.ElementTree as ET

NS = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
PROFILES = ('feature-debug', 'feature-release')
JUMP_SLACK = 600.0


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() is None:
        raise ValueError('TRX time lacks a timezone')
    return parsed


def seconds(value):
    # TRX uses .NET TimeSpan: [days.]hh:mm:ss[.fffffff].
    match = re.fullmatch(r'(?:(\d+)\.)?(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?', value)
    if not match:
        raise ValueError('Invalid TRX duration: ' + value)
    days, hours, minutes, secs, fraction = match.groups()
    if int(hours) > 23 or int(minutes) > 59 or int(secs) > 59:
        raise ValueError('Invalid TRX duration: ' + value)
    return int(days or 0) * 86400 + int(hours) * 3600 + int(minutes) * 60 + int(secs) + float('0.' + (fraction or '0'))


def report(out):
    legs, slow, errors = [], [], []
    for profile in PROFILES:
        for account in ('user', 'system'):
            leg = profile + '/' + account
            path = out / (profile + '-results') / ('agent-tests-' + account + '.trx')
            try:
                root = ET.parse(path).getroot()
                times = root.find('t:Times', NS)
                if times is None:
                    raise ValueError('Missing TRX Times')
                start, finish = timestamp(times.attrib['start']), timestamp(times.attrib['finish'])
                elapsed = (finish - start).total_seconds()
                if elapsed < 0:
                    raise ValueError('TRX finish precedes start')
                summed = 0.0
                for row in root.findall('t:Results/t:UnitTestResult', NS):
                    duration = seconds(row.attrib['duration'])
                    summed += duration
                    if duration > 60:
                        slow.append((duration, leg, row.attrib['testName'], row.attrib.get('outcome', '?')))
                legs.append((leg, elapsed, start, summed))
            except (OSError, ET.ParseError, ValueError, KeyError) as exc:
                errors.append((leg, str(exc)))
    lines = ['TRX leg wall times (Times start/finish):']
    for leg, elapsed, _, summed in legs:
        jump = f' (CLOCK JUMP SUSPECTED: summed test time {summed:.3f} s; use host elapsed)' if elapsed > summed + JUMP_SLACK else ''
        lines.append(f'{leg}: {elapsed:.3f} s{jump}')
    if legs:
        first = min(legs, key=lambda row: row[2])
        lines.append(f'First leg: {first[0]}: {first[1]:.3f} s')
    lines.append('Tests over 60 s (descending duration):')
    for duration, leg, name, outcome in sorted(slow, key=lambda row: (-row[0], row[1], row[2])):
        lines.append(f'{duration:.3f} s | {leg} | {outcome} | {name}')
    lines.extend('ERROR ' + leg + ': ' + error for leg, error in errors)
    return '\n'.join(lines), not errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', type=Path)
    args = parser.parse_args()
    output, complete = report(args.out)
    print(output)
    return 0 if complete else 1


if __name__ == '__main__':
    raise SystemExit(main())
