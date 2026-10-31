#Requires -Version 5.1
[CmdletBinding()]
param([string]$ResultsPath)
$ErrorActionPreference = 'Stop'
# Exercise the exact production functions against unique synthetic pipes. The installed script retains its
# administrator requirement and fixed pipe name; no service, driver, queue or machine configuration is touched.
$source = Join-Path $PSScriptRoot '../Get-SafeUploadDiagnostics.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile([IO.Path]::GetFullPath($source), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Production diagnostics script does not parse.' }
foreach ($name in @('Get-DiagnosticsRemainingMilliseconds','Wait-DiagnosticsTask','Invoke-DiagnosticsQuery')) {
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if ($null -eq $function) { throw 'Production diagnostics function missing.' }
    . ([scriptblock]::Create($function.Extent.Text))
}
$selection = $ast.Find({ param($node) $node -is [Management.Automation.Language.SwitchStatementAst] }, $true)
$selectQuery = [scriptblock]::Create($selection.Extent.Text)
$parameterProbe = [scriptblock]::Create($ast.ParamBlock.Extent.Text)

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
public sealed class DiagnosticsClientFixture : IDisposable {
    public readonly string PipeName = "SafeUpload.Diagnostics.Test." + Guid.NewGuid().ToString("N");
    public string Request;
    public int Connections;
    public Exception Failure;
    public bool WorkerExited;
    private NamedPipeServerStream pipe;
    private readonly CancellationTokenSource stop = new CancellationTokenSource();
    private readonly Task worker;
    private NamedPipeServerStream NewPipe() {
        return new NamedPipeServerStream(PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 4096, 4096);
    }
    public DiagnosticsClientFixture(string mode, byte[] payload, int delay) {
        pipe = NewPipe();
        worker = Task.Run(async () => {
            try {
                int pages = mode == "pages" || mode == "repeat" ? 3 : 1;
                for (int page = 0; page < pages; page++) {
                    await pipe.WaitForConnectionAsync(stop.Token);
                    Connections++;
                    if (mode == "no-read") { await Task.Delay(10000, stop.Token); return; }
                    using (var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 1024, true))
                        Request = await reader.ReadLineAsync();
                    if (delay > 0) await Task.Delay(delay, stop.Token);
                    if (mode == "silent") { await Task.Delay(10000, stop.Token); return; }
                    byte[] data = payload;
                    if (pages > 1) {
                        string records = page == 2 ? "[]" : "[{\"sequence\":" + (mode == "repeat" ? 1 : page + 1) + "}]";
                        data = Encoding.UTF8.GetBytes("{\"ok\":true,\"query\":\"deny-ring\",\"data\":{\"records\":" + records + ",\"gap\":false}}\n");
                    }
                    if (mode == "slow") {
                        foreach (byte value in data) {
                            await pipe.WriteAsync(new byte[] { value }, 0, 1, stop.Token);
                            await Task.Delay(250, stop.Token);
                        }
                    } else if (mode == "fragment") {
                        foreach (byte value in data) await pipe.WriteAsync(new byte[] { value }, 0, 1, stop.Token);
                    } else if (data.Length > 0) await pipe.WriteAsync(data, 0, data.Length, stop.Token);
                    if (mode == "partial-stall") { await Task.Delay(10000, stop.Token); return; }
                    pipe.Dispose();
                    if (page + 1 < pages) pipe = NewPipe();
                }
            } catch (Exception error) {
                if (!(error is IOException) && !(error is OperationCanceledException) && !(error is ObjectDisposedException)) Failure = error;
            }
        });
    }
    public void Dispose() {
        stop.Cancel(); pipe.Dispose();
        WorkerExited = worker.Wait(3000);
        if (WorkerExited) stop.Dispose();
    }
}
'@

$results = [Collections.Generic.List[object]]::new()
$utf8 = [Text.UTF8Encoding]::new($false)
$good = $utf8.GetBytes('{"ok":true,"query":"help","data":{"text":"a' + [char]0x00e7 + [char]0x00e3 + 'o"}}' + "`r`n")
function Assert-True([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Test-Case([string]$Name, [scriptblock]$Run) {
    Write-Host ('TEST=' + $Name)
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    try { & $Run | Out-Null; $results.Add([pscustomobject]@{name=$Name;passed=$true;milliseconds=$elapsed.ElapsedMilliseconds;error=$null}) }
    catch { $results.Add([pscustomobject]@{name=$Name;passed=$false;milliseconds=$elapsed.ElapsedMilliseconds;error=$_.Exception.Message}) }
}
function Set-Context([string]$Name, [int]$Timeout=1) {
    $script:pipeName = $Name
    $script:TimeoutSeconds = $Timeout
    $script:diagnosticsClock = [Diagnostics.Stopwatch]::StartNew()
    $script:Query = 'help'
    $script:After = [uint64]0
}
function With-Fixture([string]$Mode, [byte[]]$Payload, [scriptblock]$Run, [int]$Delay=0) {
    $fixture = [DiagnosticsClientFixture]::new($Mode, $Payload, $Delay)
    try { Set-Context $fixture.PipeName; & $Run $fixture }
    finally {
        $fixture.Dispose()
        Assert-True $fixture.WorkerExited 'Synthetic server worker did not exit.'
        Assert-True ($null -eq $fixture.Failure) 'Synthetic server failed unexpectedly.'
    }
}
function Assert-Fails([scriptblock]$Run, [string]$Message) {
    $failure = $null
    try { & $Run | Out-Null } catch { $failure = $_.Exception.Message }
    Assert-True ($null -ne $failure -and $failure.Contains($Message)) ('Expected failure: ' + $Message + '; actual: ' + $failure)
}
function Read-Help { Invoke-DiagnosticsQuery @{query='help'} }

Test-Case 'Fragmented UTF-8 and CRLF return the complete data and preserve the request' {
    With-Fixture 'fragment' $good { param($fixture)
        $reply = Read-Help
        Assert-True ($reply.text -eq ('a' + [char]0x00e7 + [char]0x00e3 + 'o')) 'UTF-8 data changed.'
        Assert-True (($fixture.Request | ConvertFrom-Json).query -eq 'help') 'Request changed.'
    }
}
Test-Case 'An exact 1 MiB frame is accepted' {
    $prefix = '{"ok":true,"query":"help","data":"'
    $suffix = '"}'
    $text = $prefix + ('x' * (1048576 - $prefix.Length - $suffix.Length)) + $suffix + "`n"
    With-Fixture 'reply' ($utf8.GetBytes($text)) {
        Assert-True ((Read-Help).Length -eq (1048576 - $prefix.Length - $suffix.Length)) 'Boundary response was truncated.'
    }
}
Test-Case 'A frame larger than 1 MiB is rejected before JSON parsing' {
    With-Fixture 'reply' ($utf8.GetBytes(('x' * 1048577) + "`n")) { Assert-Fails { Read-Help } 'reply exceeds 1 MiB' }
}
Test-Case 'A silent connected server times out and the client closes its pipe' {
    With-Fixture 'silent' ([byte[]]@()) {
        Assert-Fails { Read-Help } 'query timed out'
        Assert-True ($diagnosticsClock.ElapsedMilliseconds -lt 3000) 'Silent server exceeded the total budget tolerance.'
    }
}
Test-Case 'A partial frame without EOF times out' {
    With-Fixture 'partial-stall' ($utf8.GetBytes('{"ok":')) { Assert-Fails { Read-Help } 'query timed out' }
}
Test-Case 'A slow stream does not renew the deadline on each read' {
    With-Fixture 'slow' $good {
        Assert-Fails { Read-Help } 'query timed out'
        Assert-True ($diagnosticsClock.ElapsedMilliseconds -lt 3000) 'Slow stream renewed the deadline.'
    }
}
Test-Case 'Blocked request writing shares the same deadline' {
    With-Fixture 'no-read' ([byte[]]@()) {
        Assert-Fails { Invoke-DiagnosticsQuery @{query='help';padding=('x' * 1048576)} } 'query timed out'
        Assert-True ($diagnosticsClock.ElapsedMilliseconds -lt 3000) 'Write exceeded the total budget tolerance.'
    }
}
Test-Case 'An absent server fails within the total connection budget' {
    Set-Context ('SafeUpload.Diagnostics.Absent.' + [guid]::NewGuid().ToString('N'))
    Assert-Fails { Read-Help } 'query timed out'
    Assert-True ($diagnosticsClock.ElapsedMilliseconds -lt 3000) 'Connection exceeded the total budget tolerance.'
}
foreach ($body in @('', '{"ok":', '{"ok":true,"query":"help","data":{}}')) {
    $payload = $utf8.GetBytes($body)
    Test-Case ('EOF without newline is rejected: ' + $payload.Length) {
        With-Fixture 'reply' $payload { Assert-Fails { Read-Help } 'incomplete reply' }
    }
}
foreach ($body in @('', 'not-json', 'null', '[]', '{"ok":"true","query":"help"}', '{"ok":true,"query":"counters","data":{}}',
    '{"ok":true,"query":"help"}', '{"ok":false,"query":"help"}')) {
    $payload = $utf8.GetBytes($body + "`n")
    Test-Case ('Invalid JSON or envelope is rejected: ' + $results.Count) {
        With-Fixture 'reply' $payload { Assert-Fails { Read-Help } 'invalid reply' }
    }
}
Test-Case 'Invalid UTF-8 is rejected without replacement characters' {
    With-Fixture 'reply' ([byte[]]@(0xc3,0x28,10)) { Assert-Fails { Read-Help } 'invalid reply' }
}
Test-Case 'A service error is reported without returning its data' {
    With-Fixture 'reply' ($utf8.GetBytes('{"ok":false,"query":"help","error":"unavailable","data":{"sentinel":true}}' + "`n")) {
        Assert-Fails { Read-Help } 'SafeUpload diagnostics: unavailable'
    }
}
Test-Case 'A completed two-page deny ring stops on the empty page' {
    With-Fixture 'pages' ([byte[]]@()) { param($fixture)
        $script:Query = 'deny-ring'
        $data = @(& $selectQuery)
        Assert-True ($data.Count -eq 2 -and $data[0].sequence -eq 1 -and $data[1].sequence -eq 2 -and $fixture.Connections -eq 3) 'Pagination changed.'
    }
}
Test-Case 'All deny-ring pages share one budget' {
    With-Fixture 'pages' ([byte[]]@()) {
        $script:Query = 'deny-ring'
        Assert-Fails { & $selectQuery } 'query timed out'
        Assert-True ($diagnosticsClock.ElapsedMilliseconds -lt 3000) 'Pagination renewed the deadline.'
    } 650
}
Test-Case 'A repeated deny-ring sequence fails instead of looping' {
    With-Fixture 'repeat' ([byte[]]@()) {
        $script:Query = 'deny-ring'
        Assert-Fails { & $selectQuery } 'cursor did not advance'
    }
}
Test-Case 'The next query succeeds after timeout cleanup' {
    With-Fixture 'reply' $good { Assert-True ($null -ne (Read-Help).text) 'Subsequent query failed.' }
}
foreach ($value in @(-1,0,301,[int]::MaxValue)) {
    Test-Case ('Invalid timeout rejected by production parameter binding: ' + $value) {
        Assert-Fails { & $parameterProbe -TimeoutSeconds $value } 'TimeoutSeconds'
    }
}

$result = [ordered]@{powerShell=$PSVersionTable.PSVersion.ToString();productionScriptSha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash;
    tests=@($results.ToArray());passed=@($results | Where-Object passed).Count;failed=@($results | Where-Object { -not $_.passed }).Count;
    serviceInstalled=$false;driverQualified=$false}
if ($ResultsPath) { $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 }
$result | ConvertTo-Json -Depth 6
if ($result.failed -ne 0) { throw 'Diagnostics client transport tests failed.' }
