param([string]$Root = 'C:\T4')
$ErrorActionPreference = 'Stop'
function Get-T4Progress([string]$Root) {
    # result.json appears only after the coordinator closes its complete
    # result and atomically renames it. The live append log is read share-all.
    if (Test-Path -LiteralPath (Join-Path $Root 'result.json')) { return 'DONE' }
    $path = Join-Path $Root 'cycles.jsonl'
    $count = 0
    if (Test-Path -LiteralPath $path) {
        $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try {
            $reader = [IO.StreamReader]::new($stream)
            try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $stream.Dispose() }
        $count = @($text -split '\r?\n' | Where-Object { $_ -ne '' }).Count
    }
    return ('RUNNING ' + $count)
}
Get-T4Progress $Root
