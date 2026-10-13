#requires -Version 5.1
# Run the actual coordinator's Restart Manager holder query against a temporary
# file this check holds open, and against one nobody holds. No product file,
# driver or privilege is touched; the temporary file is removed afterwards.
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 't4\cycles-coordinator.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Coordinator does not parse' }
$functions = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-T4FileHolders'
}, $false))
if ($functions.Count -ne 1) { throw 'Actual holder query function unavailable' }
Invoke-Expression $functions[0].Extent.Text
$held = Join-Path $env:TEMP ('t4-holders-' + [guid]::NewGuid().ToString('N') + '.txt')
$free = Join-Path $env:TEMP ('t4-holders-' + [guid]::NewGuid().ToString('N') + '.txt')
[IO.File]::WriteAllText($held, 'held'); [IO.File]::WriteAllText($free, 'free')
$stream = [IO.FileStream]::new($held, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    $row = Get-T4FileHolders 'Held' @($held)
    if ($row.Error) { throw ('Holder query failed: ' + $row.Error) }
    if (@($row.Holders | Where-Object { $_.Pid -eq $PID }).Count -ne 1) { throw ('Own handle not reported: ' + ($row | ConvertTo-Json -Depth 4 -Compress)) }
    $row = Get-T4FileHolders 'Free' @($free)
    if ($row.Error -or @($row.Holders).Count -ne 0) { throw ('Unheld file reported: ' + ($row | ConvertTo-Json -Depth 4 -Compress)) }
    $row = Get-T4FileHolders 'Empty' @()
    if ($row.Error -or $row.Files -ne 0) { throw 'Empty category must not query' }
    $many = @($free) * 1201
    $row = Get-T4FileHolders 'Batched' $many
    if ($row.Error -or $row.Files -ne 1201) { throw ('Batched registration failed: ' + $row.Error) }
} finally {
    $stream.Dispose()
    Remove-Item -LiteralPath $held, $free -Force -ErrorAction SilentlyContinue
}
'T4HoldersSelfCheck=PASS;OwnHandleReported=True;UnheldFileClear=True'
