#requires -Version 5.1
param([string[]]$RealPack = @((Join-Path $PSScriptRoot 'fixtures/C01-00000001.pack'), (Join-Path $PSScriptRoot 'fixtures/m2t5ord4-00000001.pack')))
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'notepad-coordinator.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Coordinator parse errors'}
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $fn.Extent.Text}
$checks=0
function Check([bool]$Good,[string]$Label){if(-not $Good){throw $Label};$script:checks++}
function Reject([scriptblock]$Body,[string]$Label){$bad=$false;try{& $Body | Out-Null}catch{$bad=$true};Check $bad $Label}
foreach($path in $RealPack){
    if(-not (Test-Path -LiteralPath $path)){throw ('Required retained positive control missing: '+$path)}
    $pack=[IO.File]::ReadAllBytes($path)
    $records=@([pscustomobject]@{Path='completed/segments.state';Bytes=[Text.Encoding]::UTF8.GetBytes('{"Version":1,"SegmentCount":1}')},
        [pscustomobject]@{Path='completed/00000001.pack';Bytes=$pack;Artifact=$path;Owner=$null;Sddl=$null})
    $rows=ConvertFrom-ServiceArchive $records '/tmp/t5-journal'
    Check ($rows.Count -gt 0) 'Real pack must decode'
    foreach($row in $rows){
        $entry=[Text.Encoding]::UTF8.GetString($row.Bytes) | ConvertFrom-Json
        Check (@(Get-JournalSchemaErrors $entry $row.Path -RequireStateHistory -RequireV20).Count -eq 0) 'Every real archived manifest must pass T5 schema'
        Check ((Get-T5GuidText $entry.Transfer.TransferId) -ceq [IO.Path]::GetFileNameWithoutExtension($row.Path)) 'Frame binds transfer'
    }
    foreach($offset in @(0,4,8,16,4096,4100,4104,4108,4124,4156)){
        $copy=[byte[]]$pack.Clone();$copy[$offset]=$copy[$offset] -bxor 1;$records[1].Bytes=$copy
        Reject {ConvertFrom-ServiceArchive $records '/tmp/t5-journal'} ('Reject corrupt real pack offset '+$offset)
    }
    $records[1].Bytes=$pack;$records[0].Bytes=[Text.Encoding]::UTF8.GetBytes('{"Version":1,"SegmentCount":2}')
    Reject {ConvertFrom-ServiceArchive $records '/tmp/t5-journal'} 'Missing committed segment'
}
$temp=Join-Path $env:TEMP ('t5-journal-storage-'+[guid]::NewGuid().ToString('N'))
try {
    $journalDir=Join-Path $temp 'journal';$completed=Join-Path $journalDir 'completed'
    [void][IO.Directory]::CreateDirectory($completed)
    $script:T5JournalEvidenceDirectory=Join-Path $temp 'retained'
    Copy-Item -LiteralPath $RealPack[-1] -Destination (Join-Path $completed '00000001.pack')
    [IO.File]::WriteAllText((Join-Path $completed 'segments.state'),'{"Version":1,"SegmentCount":1}')
    [IO.File]::WriteAllText((Join-Path $journalDir 'driver-epoch.state'),'{"DriverInstanceId":"11111111-1111-1111-1111-111111111111","AcceptedAtUtc":"2026-10-20T00:00:00Z","DrainRequestId":null,"DrainNonce":null,"DrainedAtUtc":null}')
    $rows=ConvertFrom-ServiceArchive @([pscustomobject]@{Path='segments.state';Bytes=[Text.Encoding]::UTF8.GetBytes('{"Version":1,"SegmentCount":1}')},[pscustomobject]@{Path='00000001.pack';Bytes=[IO.File]::ReadAllBytes($RealPack[-1])}) $journalDir
    $manifest=[Text.Encoding]::UTF8.GetString($rows[-1].Bytes) | ConvertFrom-Json
    $journal=Get-JournalFor $manifest.Transfer.DestinationPath -BaselineTransferIds @() -RequireHistoryForNewRecords
    Check (@($journal.ParseErrors).Count -eq 0 -and @($journal.SchemaErrors).Count -eq 0) ('Archive directory must pass full schema/lineage reader: '+($journal | ConvertTo-Json -Depth 8 -Compress))
    Check (@($journal.Records).Count -gt 0 -and $null -ne $journal.Records[0].ArchiveRecord) 'Projected records retain physical artifact/frame binding'
    Check (@(Get-ChildItem -LiteralPath $script:T5JournalEvidenceDirectory -Filter '*.bin').Count -eq 3) 'Pack, epoch, inventory retained'
    $unknown=Join-Path $journalDir 'unexpected.state';[IO.File]::WriteAllText($unknown,'{}')
    Check (@((Get-JournalFor $manifest.Transfer.DestinationPath).ParseErrors).Count -gt 0) 'Unexpected storage file fails closed'
    Remove-Item -LiteralPath $unknown
    $oversize=Join-Path $journalDir ([guid]::NewGuid().ToString('N')+'.json');[IO.File]::WriteAllBytes($oversize,(New-Object byte[] 131073))
    Check (@((Get-JournalFor $manifest.Transfer.DestinationPath).ParseErrors).Count -gt 0) '128 KiB is still a per-manifest bound'
    Remove-Item -LiteralPath $oversize
    $duplicate=Join-Path $journalDir ([IO.Path]::GetFileName($rows[-1].Path));[IO.File]::WriteAllBytes($duplicate,$rows[-1].Bytes)
    $paired=Get-JournalFor $manifest.Transfer.DestinationPath
    Check (@($paired.ParseErrors).Count -eq 0 -and @($paired.SchemaErrors).Count -eq 0 -and $null -ne $paired.Records[-1].ArchiveRecord.HotArtifact) 'Exact hot/archive consolidation retains both artifacts'
    [IO.File]::AppendAllText($duplicate,' ')
    Check (@((Get-JournalFor $manifest.Transfer.DestinationPath).ParseErrors).Count -gt 0) 'Conflicting hot/archive bytes fail closed'
    Remove-Item -LiteralPath $duplicate
    $tmp=Join-Path $journalDir ('driver-epoch.state.'+[guid]::NewGuid().ToString('N')+'.tmp');[IO.File]::WriteAllText($tmp,'in flight')
    Check (@((Get-JournalFor $manifest.Transfer.DestinationPath).ParseErrors).Count -eq 0) 'Product transient tmp sidecar is tolerated'
    Remove-Item -LiteralPath $tmp
    $bytes=New-Object byte[] 4194304
    foreach($number in 2..17){[IO.File]::WriteAllBytes((Join-Path $completed ($number.ToString('X8')+'.pack')),$bytes)}
    Check (@((Get-JournalFor $manifest.Transfer.DestinationPath).ParseErrors | Where-Object {$_.Error -match '64-MiB'}).Count -gt 0) '64 MiB bound applies before decoding the containers'
    Remove-Item -LiteralPath $completed -Recurse -Force
    foreach($number in 1..1025){[IO.File]::WriteAllText((Join-Path $journalDir ([guid]::NewGuid().ToString('N')+'.json')),'{}')}
    Check (@((Get-JournalFor $manifest.Transfer.DestinationPath).ParseErrors | Where-Object {$_.Error -match '1024-record'}).Count -gt 0) '1024 logical-record bound still applies'
}finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Recurse -Force}}
'T5JournalStorageSelfCheck=PASS;Assertions='+$checks+';ProductQualified=False'
