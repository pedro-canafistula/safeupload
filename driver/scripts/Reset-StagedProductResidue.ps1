# One-time reset of SafeUpload product residue left on a debuggee by earlier test runs (2026-10-07).
# Journals, staged files, notification records and the audit queue persisted across runs, and the service kept
# maintaining earlier runs' transfers inside later observation windows (A05 m1c2). Activation rows now restore
# their product state exactly (dce1ef27); this clears what accumulated before that. Requires no running agent.
# Archives everything first; keeps the folders, the notification record and queue.jsonl in place so their ACLs are untouched.
$ErrorActionPreference='Stop'
if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'Agent is running; refusing to reset product state.'}
$root='C:\ProgramData\SafeUpload'
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$archive=Join-Path 'C:\Users\vika\Documents' ('product-residue-'+$stamp+'.zip')
$items=@()
foreach($leaf in 'staging','staging-journal','notifications','queue.jsonl'){
    $path=Join-Path $root $leaf
    if(Test-Path -LiteralPath $path){$items+=$path}
}
foreach($item in Get-ChildItem -LiteralPath $root -Recurse -Force){
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse point in product state: '+$item.FullName)}
}
Compress-Archive -LiteralPath $items -DestinationPath $archive
'Archive=' + $archive + ';Sha256=' + (Get-FileHash -LiteralPath $archive).Hash
# notifications is archived but kept: R03 snapshots the service-written record while the service is offline and its
# strict reader requires emissions.jsonl, head.json and writer.lock to exist (they only appear after a service run).
foreach($leaf in 'staging','staging-journal'){
    $path=Join-Path $root $leaf
    if(Test-Path -LiteralPath $path){
        $n=@(Get-ChildItem -LiteralPath $path -Force).Count
        Get-ChildItem -LiteralPath $path -Force | Remove-Item -Recurse -Force
        $leaf + 'Removed=' + $n
    }
}
$queue=Join-Path $root 'queue.jsonl'
if(Test-Path -LiteralPath $queue){
    $length=(Get-Item -LiteralPath $queue).Length
    $stream=[IO.File]::Open($queue,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.SetLength(0);$stream.Flush($true)}finally{$stream.Dispose()}
    'QueueTruncatedFrom=' + $length
}
'PRODUCT_RESIDUE_RESET=True'
