$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 't4\memory-debugger.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('T4MemorySelfCheck-' + [guid]::NewGuid().ToString('N'))
try {
    $corpus=New-T4MemoryCorpus $root 4
    if ($corpus.Count -ne 4 -or (Test-T4MemoryCorpus $corpus 2) -ne 8) { throw 'Fixed identity control failed.' }
    'FixedPhysicalIdentities=PASS'
    $path=@($corpus.Keys)[0]
    $hash=(Get-FileHash -LiteralPath $path).Hash
    $held=$path + '.original'
    [IO.File]::Move($path,$held)
    [IO.File]::WriteAllText($path,'a distinct file with the same pathname')
    $refused=$false
    try { $null=Test-T4MemoryCorpus $corpus 1 } catch {
        if ($_.Exception.Message -notlike 'Physical identity changed*') { throw }
        $refused=$true
    }
    if (-not $refused) { throw 'Replacement identity was not refused.' }
    Remove-Item -LiteralPath $path
    [IO.File]::Move($held,$path)
    $null=Test-T4MemoryCorpus $corpus 1
    if ((Get-FileHash -LiteralPath $path).Hash -ne $hash) { throw 'Open/close control changed content.' }
    'ReplacementIdentityRefused=PASS'
    'ContentUnchanged=PASS'
    $commands=Get-T4MemoryCommands
    if ($commands -notmatch 'T4_MEMORY_END' -or $commands -notmatch '!fltkd.filters 7' -or
        $commands -notmatch '!verifier 3 SafeUpload.sys') { throw 'Attribution commands are incomplete.' }
    'T4MemorySelfCheck=PASS'
} finally {
    if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}
}
