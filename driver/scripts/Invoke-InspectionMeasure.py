#!/usr/bin/env python3
"""Read-only, fresh-process inspector measurements on the recorded builder.

Retains source/corpus hashes, raw build/results and independent receipt checks.
Does not install/boot a product, edit policy, publish, or purge filesystem cache.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import zipfile

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('exact_matrix', REPO / 'driver/scripts/Invoke-ExactAgentMatrixBuild.py')
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


def write_value(output, count, tail):
    remaining = count - len(tail)
    block = b'x' * 65536
    while remaining:
        size = min(remaining, len(block))
        output.write(block[:size])
        remaining -= size
    output.write(tail)


def office(path, count, tail):
    word = path.suffix == '.docx'
    namespace = 'http://schemas.openxmlformats.org/'
    main = 'word/document.xml' if word else 'xl/workbook.xml'
    main_type = ('wordprocessingml.document' if word else 'spreadsheetml.sheet') + '.main+xml'
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        extra = '' if word else '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        archive.writestr('[Content_Types].xml', '<Types xmlns="' + namespace + 'package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/' + main + '" ContentType="application/vnd.openxmlformats-officedocument.' + main_type + '"/>' + extra + '</Types>')
        archive.writestr('_rels/.rels', '<Relationships xmlns="' + namespace + 'package/2006/relationships"><Relationship Id="main" Type="' + namespace + 'officeDocument/2006/relationships/officeDocument" Target="/' + main + '"/></Relationships>')
        if word:
            name = main
            prefix = '<w:document xmlns:w="' + namespace + 'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'
            suffix = '</w:t></w:r></w:p></w:body></w:document>'
        else:
            archive.writestr(main, '<workbook xmlns="' + namespace + 'spreadsheetml/2006/main" xmlns:r="' + namespace + 'officeDocument/2006/relationships"><sheets><sheet name="Fixture" sheetId="1" r:id="sheet"/></sheets></workbook>')
            archive.writestr('xl/_rels/workbook.xml.rels', '<Relationships xmlns="' + namespace + 'package/2006/relationships"><Relationship Id="sheet" Type="' + namespace + 'officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
            name = 'xl/worksheets/sheet1.xml'
            prefix = '<worksheet xmlns="' + namespace + 'spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>'
            suffix = '</t></is></c></row></sheetData></worksheet>'
        with archive.open(name, 'w') as output:
            output.write(prefix.encode())
            write_value(output, count, tail)
            output.write(suffix.encode())


def pdf(path, tail):
    pages, per_page = 16, 65536
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>',
               ('<< /Type /Pages /Count 16 /Kids [' + ' '.join(str(4 + 2*i) + ' 0 R' for i in range(pages)) + '] >>').encode(),
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    for i in range(pages):
        objects.append(('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ' + str(5 + 2*i) + ' 0 R >>').encode())
        ending = tail if i == pages - 1 else b''
        value = b'x' * (per_page - len(ending)) + ending
        content = b'BT /F1 12 Tf 40 740 Td (' + value + b') Tj ET\n'
        objects.append(('<< /Length ' + str(len(content)) + ' >>\nstream\n').encode() + content + b'endstream')
    with path.open('wb') as output:
        output.write(b'%PDF-1.4\n')
        offsets = [0]
        for i, value in enumerate(objects, 1):
            offsets.append(output.tell())
            output.write(str(i).encode() + b' 0 obj\n' + value + b'\nendobj\n')
        start = output.tell()
        output.write(('xref\n0 ' + str(len(offsets)) + '\n0000000000 65535 f \n').encode())
        for offset in offsets[1:]:
            output.write(f'{offset:010d} 00000 n \n'.encode())
        output.write(('trailer\n<< /Size ' + str(len(offsets)) + ' /Root 1 0 R >>\nstartxref\n' + str(start) + '\n%%EOF\n').encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('label')
    parser.add_argument('--commit', default='HEAD')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch('[A-Za-z0-9._-]{3,60}', args.label):
        parser.error('Invalid label')
    commit = subprocess.check_output(['git', 'rev-parse', '--verify', args.commit + '^{commit}'], cwd=REPO, text=True).strip()
    work = REPO / 'output/inspection-measure' / args.label
    work.mkdir(parents=True, exist_ok=False)
    subprocess.run(['git', 'archive', '--format=zip', '-o', str(work/'source.zip'), commit,
                    'agente', 'driver/scripts/InspectionMeasure'], cwd=REPO, check=True)
    corpus = work/'corpus'
    corpus.mkdir()
    cases = []
    for extension in ['.txt', '.docx', '.xlsx', '.pdf']:
        for megabytes in ([1] if extension == '.pdf' else [1, 20]):
            for kind in ['clean', 'cpf']:
                name = extension[1:] + '-' + str(megabytes) + 'm-' + kind + extension
                path = corpus/name
                tail = b' CPF: 529.982.247-25' if kind == 'cpf' else b' clean EOF'
                count = megabytes*1024*1024
                if extension == '.txt':
                    with path.open('wb') as output:
                        write_value(output, count, tail)
                elif extension == '.pdf':
                    pdf(path, tail)
                else:
                    office(path, count, tail)
                cases.append(dict(name=name, kind=kind, decodedFixtureBytes=count,
                                  inputBytes=path.stat().st_size, sha256=matrix.sha(path).upper()))
    (corpus/'cases.json').write_text(json.dumps(cases, indent=2)+'\n')
    with zipfile.ZipFile(work/'corpus.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(corpus.iterdir()):
            archive.write(path, path.name)
    evidence = REPO/'driver/evidence'/datetime.date.today().isoformat()
    evidence.mkdir(parents=True, exist_ok=True)
    prefix = 'inspection-measure-'+args.label
    provenance = dict(sourceCommit=commit, sourceSha256=matrix.sha(work/'source.zip').upper(),
                      corpusSha256=matrix.sha(work/'corpus.zip').upper(), cases=cases)
    (evidence/(prefix+'-source.json')).write_text(json.dumps(provenance, indent=2)+'\n')
    print('SOURCE_COMMIT='+commit+'; prepared 14 retained fixtures', flush=True)
    if args.prepare_only:
        return
    remote_root = 'C:\\Users\\vika\\Documents\\'+prefix
    preflight = """$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
 (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or
 -not @(Get-NetAdapter|Where-Object {$_.MacAddress -eq '52-54-00-63-87-7A'}).Count){throw 'Wrong builder.'}
if((Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace -lt 300000000){throw 'Insufficient measurement headroom.'}
"""
    for leaf in [remote_root, remote_root+'-source.zip', remote_root+'-corpus.zip']:
        preflight += "if(Test-Path -LiteralPath '"+leaf+"'){throw 'Measurement destination already exists.'}\n"
    check = subprocess.run(['python3', str(REPO/'driver/scripts/remote_ps.py'), matrix.HOST],
                           input=preflight.encode(), capture_output=True)
    (evidence/(prefix+'-preflight.stdout.txt')).write_bytes(check.stdout)
    (evidence/(prefix+'-preflight.stderr.txt')).write_bytes(check.stderr)
    if check.returncode:
        raise RuntimeError('Builder preflight failed before delivery')
    for name in ['source.zip', 'corpus.zip']:
        subprocess.run(['scp', *matrix.SSH, str(work/name), matrix.REMOTE+prefix+'-'+name], check=True)
    script = build_script(remote_root, provenance)
    (evidence/(prefix+'-build.ps1')).write_text(script, encoding='utf-8-sig')
    result = subprocess.run(['python3', str(REPO/'driver/scripts/remote_ps.py'), matrix.HOST],
                            input=script.encode(), capture_output=True)
    (evidence/(prefix+'-build.stdout.txt')).write_bytes(result.stdout)
    (evidence/(prefix+'-build.stderr.txt')).write_bytes(result.stderr)
    results = work/'results'
    subprocess.run(['scp', *matrix.SSH, '-r', matrix.REMOTE+prefix+'/results', str(results)], check=True)
    for path in results.iterdir():
        if path.is_file():
            (evidence/(prefix+'-'+path.name)).write_bytes(path.read_bytes())
    if result.returncode:
        raise RuntimeError('Measurement/build failed; raw receipts retained, no later case inferred passed')
    verify(results, provenance)
    print('InspectionMeasureGate=PASS', flush=True)


def build_script(root, source):
    script = r'''$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$OutputEncoding=New-Object Text.UTF8Encoding($false)
$env:DOTNET_CLI_UI_LANGUAGE='en-US'
$root='@@ROOT@@'
if(Test-Path -LiteralPath $root){throw 'Root already exists.'}
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
 (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or
 -not @(Get-NetAdapter|Where-Object {$_.MacAddress -eq '52-54-00-63-87-7A'}).Count){throw 'Wrong builder.'}
if((Get-FileHash -LiteralPath ($root+'-source.zip') -Algorithm SHA256).Hash -ne '@@SOURCE_SHA@@' -or
 (Get-FileHash -LiteralPath ($root+'-corpus.zip') -Algorithm SHA256).Hash -ne '@@CORPUS_SHA@@'){throw 'Delivery hash mismatch.'}
if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'PowerShell 5.1 required.'}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[void][IO.Directory]::CreateDirectory($root)
$src=Join-Path $root 'src';$corpus=Join-Path $root 'corpus';$publish=Join-Path $root 'publish';$results=Join-Path $root 'results'
[void][IO.Directory]::CreateDirectory($results)
[IO.Compression.ZipFile]::ExtractToDirectory(($root+'-source.zip'),$src)
[IO.Compression.ZipFile]::ExtractToDirectory(($root+'-corpus.zip'),$corpus)
$build=Join-Path $results 'build.txt';$publishLog=Join-Path $results 'publish.txt'
& dotnet build (Join-Path $src 'driver\scripts\InspectionMeasure\InspectionMeasure.csproj') -c Release -v:minimal '-consoleloggerparameters:Summary' *> $build
if($LASTEXITCODE -ne 0){throw 'Probe build failed.'}
$log=[IO.File]::ReadAllText($build)
if($log -notmatch '(?m)^\s*0 Warning\(s\)\s*$' -or $log -notmatch '(?m)^\s*0 Error\(s\)\s*$'){throw 'Probe build is not 0/0.'}
& dotnet publish (Join-Path $src 'driver\scripts\InspectionMeasure\InspectionMeasure.csproj') -c Release --no-build --no-restore -o $publish *> $publishLog
if($LASTEXITCODE -ne 0){throw 'Probe publication failed.'}
$core=Join-Path $publish 'SafeUpload.Agent.Core.dll'
Copy-Item -LiteralPath $core -Destination (Join-Path $results 'SafeUpload.Agent.Core.dll')
Copy-Item -LiteralPath (Join-Path $publish 'InspectionMeasure.dll') -Destination (Join-Path $results 'InspectionMeasure.dll')
$cases=Get-Content -LiteralPath (Join-Path $corpus 'cases.json') -Raw|ConvertFrom-Json
if($cases.Count -ne 14){throw 'Incomplete measurement corpus.'}
foreach($case in $cases){
 if($case.name -notmatch '^[a-z0-9-]+\.(txt|docx|xlsx|pdf)$' -or $case.kind -notin @('clean','cpf')){throw 'Unsafe corpus entry.'}
 $input=Join-Path $corpus $case.name
 if((Get-Item -LiteralPath $input).Length -ne $case.inputBytes -or
  (Get-FileHash -LiteralPath $input -Algorithm SHA256).Hash -ne $case.sha256){throw 'Corpus changed before measurement.'}
 $stdout=Join-Path $results ($case.name+'.json');$stderr=Join-Path $results ($case.name+'.stderr.txt')
 & dotnet (Join-Path $publish 'InspectionMeasure.dll') $input $case.kind '@@COMMIT@@' 1> $stdout 2> $stderr
 if($LASTEXITCODE -ne 0){throw ('Measurement failed: '+$case.name)}
 if((Get-FileHash -LiteralPath $input -Algorithm SHA256).Hash -ne $case.sha256){throw 'Corpus changed after measurement.'}
}
$receipt=@{SourceCommit='@@COMMIT@@';SourceSha256='@@SOURCE_SHA@@';CorpusSha256='@@CORPUS_SHA@@';CoreSha256=(Get-FileHash -LiteralPath $core -Algorithm SHA256).Hash;ProbeSha256=(Get-FileHash -LiteralPath (Join-Path $publish 'InspectionMeasure.dll') -Algorithm SHA256).Hash;Gate='PASS';Cases=14;PolicyDefaultsChanged=$false;FilesystemCacheControlled=$false;ProtectedQualification=$false}
$receipt|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $results 'receipt.json') -Encoding UTF8
Write-Output 'INSPECTION_MEASURE=PASS cases=14 fresh_process_and_repeat no_policy_edit_no_purge_no_publication'
'''
    return script.replace('@@ROOT@@', root).replace('@@COMMIT@@', source['sourceCommit']).replace(
        '@@SOURCE_SHA@@', source['sourceSha256']).replace('@@CORPUS_SHA@@', source['corpusSha256'])


def verify(results, source):
    receipt = json.loads(matrix.read_captured_text(results/'receipt.json'))
    for key, field in [('SourceCommit', 'sourceCommit'), ('SourceSha256', 'sourceSha256'), ('CorpusSha256', 'corpusSha256')]:
        if receipt[key] != source[field]:
            raise RuntimeError('Measurement provenance mismatch: '+key)
    if receipt['Gate'] != 'PASS' or receipt['Cases'] != 14 or receipt['PolicyDefaultsChanged'] or receipt['FilesystemCacheControlled'] or receipt['ProtectedQualification']:
        raise RuntimeError('Invalid measurement scope/completion receipt')
    for key, name in [('CoreSha256', 'SafeUpload.Agent.Core.dll'), ('ProbeSha256', 'InspectionMeasure.dll')]:
        if matrix.sha(results/name).upper() != receipt[key]:
            raise RuntimeError('Measured assembly mismatch: '+name)
    fingerprints = set()
    processes = set()
    for case in source['cases']:
        measured = json.loads(matrix.read_captured_text(results/(case['name']+'.json')))
        if (measured['Gate'] != 'PASS' or measured['SourceCommit'] != source['sourceCommit'] or
            measured['SourceSha256'] != case['sha256'] or not measured['SourceUnchanged'] or
            measured['InputBytes'] != case['inputBytes'] or measured['FileName'] != case['name'] or
            measured['CoreAssemblySha256'] != receipt['CoreSha256'] or len(measured['Rows']) != 2 or
            measured['MaxFileSizeBytes'] != 20*1024*1024 or measured['InspectionTimeoutMs'] != 5000):
            raise RuntimeError('Measurement case/provenance/default mismatch: '+case['name'])
        fingerprints.add(measured['PolicyFingerprint'])
        process = (measured['ProcessId'], measured['ProcessStartUtcTicks'])
        if process in processes:
            raise RuntimeError('A fixture did not run in a fresh process')
        processes.add(process)
        for row, scan in zip(measured['Rows'], ['fresh-process-first', 'same-process-repeat']):
            if (row['Scan'] != scan or not row['ExpectedResult'] or row['FromCache'] or row['Reason'] is not None or
                row['Verdict'] != ('Blocked' if case['kind'] == 'cpf' else 'Approved') or
                row['FindingCount'] != (1 if case['kind'] == 'cpf' else 0) or row['WallMs'] < 0 or
                row['PeakWorkingSetBytes'] < row['PeakWorkingSetBeforeBytes']):
                raise RuntimeError('Invalid result/measurement row: '+case['name'])
    if len(fingerprints) != 1:
        raise RuntimeError('Measurement policy changed between cases')


if __name__ == '__main__':
    main()
