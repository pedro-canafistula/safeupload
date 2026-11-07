#Requires -Version 5.1
Set-StrictMode -Version Latest

function Assert-SafeUploadDirectory {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedPath)
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $expected = [IO.Path]::GetFullPath($ExpectedPath).TrimEnd('\')
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path -match '["\r\n]' -or
        -not $full.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unexpected installation directory.'
    }
    $ancestor = $full
    while ($ancestor) {
        if (Test-Path -LiteralPath $ancestor) {
            $item = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'Installation directories must not be files, links or junctions.'
            }
        }
        $parent = Split-Path -Parent $ancestor
        if ($parent -eq $ancestor) { break }
        $ancestor = $parent
    }
    return $full
}

function New-SafeUploadInstallPlan {
    param([Parameter(Mandatory)][string]$InstallRoot,
          [ValidateSet('Drive', 'FileSystemWatcher')][string]$Mode = 'Drive')
    if (-not [IO.Path]::IsPathRooted($InstallRoot) -or $InstallRoot -match '["\r\n]') { throw 'Invalid install root.' }
    $exe = Join-Path $InstallRoot 'service\SafeUpload.Agent.Service.exe'
    [pscustomobject]@{
        Mode = $Mode; Executable = $exe
        CommandLine = '"' + $exe + '" --Interception:Mode=' + $Mode + ' --InspecaoTls:Habilitada=false'
        RestartRequired = $false
    }
}

function Assert-SafeUploadInstallAcl {
    param([Parameter(Mandatory)][Security.AccessControl.DirectorySecurity]$Acl)
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    try { $trusted += ([Security.Principal.NTAccount]::new('NT SERVICE', 'TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { <# Without a verified service SID, accept only SYSTEM and Administrators. #> }
    if ($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Installation directory owner is not trusted.' }
    $write = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or -not ($rule.FileSystemRights -band $write)) { continue }
        $sid = $rule.IdentityReference.Value
        if ($sid -in $trusted) { continue }
        if ($sid -eq 'S-1-3-0' -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        throw 'An unprivileged principal can modify the installation directory.'
    }
}

function Assert-SafeUploadMachineState {
    param([Parameter(Mandatory)]$State,
          [ValidateSet('Drive', 'FileSystemWatcher')][string]$Mode,
          [ValidateSet('Install', 'Uninstall')][string]$Operation,
          [bool]$WinFspAvailable = $true)
    if ($Operation -eq 'Install') {
        if ($State.AgentInstalled) { throw 'An agent service already exists. This initial installer does not perform upgrades.' }
        if ($Mode -eq 'Drive' -and -not $WinFspAvailable) {
            throw 'Drive mode needs WinFsp: install it first or use an installer that bundles it.'
        }
        if ($Mode -eq 'FileSystemWatcher' -and $State.DriverInstalled) {
            throw 'Driver-free test mode cannot be installed while a SafeUpload driver is registered.'
        }
    }
    # Uninstall removes the gate driver together with the agent; nothing to check here.
}

function Test-SafeUploadPayload {
    param([Parameter(Mandatory)][string]$Root)
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $manifestPath = Join-Path $rootPath 'payload-manifest.json'
    if ((Get-Item -LiteralPath $manifestPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The manifest must not be a reparse point.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 1 -or @($manifest.files).Count -eq 0) { throw 'Invalid payload manifest.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $manifest.files) {
        $relative = [string]$file.path
        if (-not $relative -or [IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)|[:\x00-\x1f]' -or
            $file.sha256 -notmatch '^[0-9a-fA-F]{64}$' -or -not $seen.Add($relative.Replace('/', '\'))) {
            throw 'Unsafe, repeated or invalid payload entry.'
        }
        $candidate = [IO.Path]::GetFullPath((Join-Path $rootPath $relative))
        if (-not $candidate.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Payload escapes its root.' }
        $parent = Split-Path -Parent $candidate
        $null = Assert-SafeUploadDirectory -Path $parent -ExpectedPath $parent
        $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Payload entry is not a regular file.' }
        if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash -ne $file.sha256) { throw "Payload integrity check failed: $relative" }
    }
    return $manifest
}

function Stop-SafeUploadInstalledUi {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ExecutablePath)
    if (-not [IO.Path]::IsPathRooted($ExecutablePath) -or
        [IO.Path]::GetFileName($ExecutablePath) -ne 'SafeUpload.Agent.App.exe') {
        throw 'Expected an absolute installed UI executable path.'
    }
    # The caller validates the protected installation root/ACL first. A matching
    # process name alone never authorizes termination. Keep the Process handle
    # open while checking the module and terminating that exact process.
    $expected = [IO.Path]::GetFullPath($ExecutablePath)
    $stopped = 0
    foreach ($process in @(Get-Process -Name SafeUpload.Agent.App -ErrorAction SilentlyContinue)) {
        try {
            if ($process.HasExited) { continue }
            try {
                $null = $process.Handle
                $actual = $process.MainModule.FileName
            } catch {
                if ($process.HasExited) { continue }
                throw 'Cannot verify the executable of a running agent UI; removal refused.'
            }
            if ([string]::IsNullOrEmpty($actual)) { throw 'Cannot verify the running UI executable.' }
            if (-not [IO.Path]::GetFullPath($actual).Equals($expected, [StringComparison]::OrdinalIgnoreCase)) { continue }
            # Closing a WPF panel can hide it in the tray instead of exiting.
            $process.Kill()
            if (-not $process.WaitForExit(10000)) { throw 'The installed UI did not exit; removal refused.' }
            $stopped++
        } finally { $process.Dispose() }
    }
    return $stopped
}

Export-ModuleMember -Function Stop-SafeUploadInstalledUi, Assert-SafeUploadDirectory, New-SafeUploadInstallPlan, Assert-SafeUploadMachineState, Test-SafeUploadPayload, Assert-SafeUploadInstallAcl
