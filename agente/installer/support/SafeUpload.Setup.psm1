#Requires -Version 5.1
Set-StrictMode -Version Latest

function ConvertTo-SafeUploadAdminUrl {
    param([AllowEmptyString()][string]$Value = '')
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    if ($Value -match '[\x00-\x20"<>]') { throw 'The server URL contains whitespace or unsafe characters.' }
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -notin @('http', 'https') -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
        throw 'Use an absolute HTTP(S) URL without credentials, query or fragment.'
    }
    if ($uri.Scheme -eq 'http' -and -not $uri.IsLoopback) {
        throw 'A remote server requires HTTPS. HTTP is allowed only on loopback for local tests.'
    }
    $normalized = $uri.AbsoluteUri.TrimEnd('/') + '/'
    if (-not ([Uri]$normalized).AbsolutePath.EndsWith('/agent/', [StringComparison]::Ordinal)) {
        throw 'The server URL must end with /agent/.'
    }
    return $normalized
}

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
          [ValidateSet('Minifilter', 'FileSystemWatcher')][string]$Mode = 'Minifilter',
          [AllowEmptyString()][string]$AdminBaseUrl = '')
    if (-not [IO.Path]::IsPathRooted($InstallRoot) -or $InstallRoot -match '["\r\n]') { throw 'Invalid install root.' }
    $url = ConvertTo-SafeUploadAdminUrl $AdminBaseUrl
    $exe = Join-Path $InstallRoot 'service\SafeUpload.Agent.Service.exe'
    $arguments = @('--Interception:Mode=' + $Mode)
    if ($Mode -eq 'Minifilter') { $arguments += '--Interception:StagingPrototype=true' }
    $arguments += @(('--CentroAdministracao:BaseUrl=' + $url), '--InspecaoTls:Habilitada=false')
    [pscustomobject]@{
        Mode = $Mode; AdminBaseUrl = $url; Executable = $exe
        CommandLine = '"' + $exe + '" ' + ($arguments -join ' ')
        RestartRequired = ($Mode -eq 'Minifilter')
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
          [ValidateSet('Minifilter', 'FileSystemWatcher')][string]$Mode,
          [ValidateSet('Install', 'Uninstall')][string]$Operation)
    if ($Operation -eq 'Install') {
        if ($State.AgentInstalled) { throw 'An agent service already exists. This initial installer does not perform upgrades.' }
        if ($Mode -eq 'Minifilter' -and (-not $State.DriverInstalled -or $State.DriverState -ne 'Stopped')) {
            throw 'Minifilter mode requires the driver package installed and its driver stopped. Use a disposable VM.'
        }
        if ($Mode -eq 'FileSystemWatcher' -and $State.DriverInstalled) {
            throw 'Driver-free test mode cannot be installed while a SafeUpload driver is registered.'
        }
    } elseif ($State.DriverInstalled -and ($State.DriverStart -ne 4 -or $State.DriverState -ne 'Stopped')) {
        throw 'Disable and unload the driver in the approved maintenance procedure before removing the agent. The installer never disables a driver for you.'
    }
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

Export-ModuleMember -Function ConvertTo-SafeUploadAdminUrl, Assert-SafeUploadDirectory, New-SafeUploadInstallPlan, Assert-SafeUploadMachineState, Test-SafeUploadPayload, Assert-SafeUploadInstallAcl
