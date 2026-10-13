#requires -Version 5.1
# Compile the actual coordinator's native declarations without executing a
# privilege adjustment or memory purge on the validation builder.
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 't4\cycles-coordinator.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Coordinator does not parse' }
$functions = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-T4MemoryPurge'
}, $false))
if ($functions.Count -ne 1) { throw 'Actual memory purge function unavailable' }
$declarations = @($functions[0].Body.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Add-Type'
}, $false))
if ($declarations.Count -ne 1) { throw 'Actual memory purge Add-Type unavailable' }
Invoke-Expression $declarations[0].Extent.Text
$adjust = [T4MemoryPurge].GetMethod('RtlAdjustPrivilege')
$set = [T4MemoryPurge].GetMethod('NtSetSystemInformation')
if ($adjust.ReturnType -ne [int] -or $set.ReturnType -ne [int]) { throw 'NTSTATUS must be signed 32-bit' }
$adjustParameters = $adjust.GetParameters()
if ($adjustParameters.Count -ne 4 -or $adjustParameters[0].ParameterType -ne [uint32]) { throw 'Privilege signature changed' }
foreach ($i in 1, 2, 3) {
    $marshal = $adjustParameters[$i].GetCustomAttributes([Runtime.InteropServices.MarshalAsAttribute], $false)
    if ($marshal.Count -ne 1 -or $marshal[0].Value -ne [Runtime.InteropServices.UnmanagedType]::U1) { throw 'BOOLEAN must occupy one byte' }
}
if (-not $adjustParameters[3].IsOut -or $adjustParameters[3].ParameterType -ne [bool].MakeByRefType()) { throw 'Previous privilege state must be an output BOOLEAN' }
$setParameters = $set.GetParameters()
if ($setParameters.Count -ne 3 -or $setParameters[0].ParameterType -ne [int] -or
    $setParameters[1].ParameterType -ne [int].MakeByRefType() -or $setParameters[2].ParameterType -ne [int]) {
    throw 'Memory-list command must be passed as a four-byte integer by reference'
}
foreach ($method in $adjust, $set) {
    $import = $method.GetCustomAttributes([Runtime.InteropServices.DllImportAttribute], $false)
    if ($import.Count -ne 1 -or $import[0].Value -cne 'ntdll.dll' -or -not $import[0].ExactSpelling) { throw 'Native import changed' }
}
'T4PurgeSignatureSelfCheck=PASS;NativeCalls=False'
