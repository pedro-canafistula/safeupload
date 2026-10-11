#requires -Version 5.1
$ErrorActionPreference = 'Stop'

function Read-T4AgentFrame([string]$PipeName = 'SafeUpload.Agent', [int]$TimeoutMilliseconds = 5000) {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $PipeName,
        [IO.Pipes.PipeDirection]::In, [IO.Pipes.PipeOptions]::Asynchronous)
    $reader = $null
    try {
        $pipe.Connect($TimeoutMilliseconds)
        $reader = [IO.StreamReader]::new($pipe)
        $read = $reader.ReadLineAsync()
        if (-not $read.Wait($TimeoutMilliseconds)) {
            throw [TimeoutException]::new('Agent frame read timed out.')
        }
        $line = $read.Result
        if ($null -eq $line) { throw [IO.EndOfStreamException]::new('Agent pipe closed before a frame.') }
        return $line
    } finally {
        # Close the asynchronous pipe even when a connected server never sends a line.
        $pipe.Dispose()
        if ($reader) { $reader.Dispose() }
    }
}

$ready = $false
$last = ''
$watch = [Diagnostics.Stopwatch]::StartNew()
while (-not $ready -and $watch.Elapsed.TotalSeconds -lt 600) {
    try {
        $last = Read-T4AgentFrame
        $ready = $last -match '"admissionCoverage"\s*:\s*"Ready"'
    } catch { $last = 'ERR ' + $_.Exception.Message }
    if (-not $ready) { Start-Sleep -Seconds 5 }
}
'READY=' + $ready
'LAST_AGENT_FRAME=' + $last
'READINESS_ELAPSED_MS=' + $watch.ElapsedMilliseconds
'DRIVER_LOADED=' + [bool](fltmc.exe filters | Select-String SafeUpload)
