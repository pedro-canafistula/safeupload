#Requires -Version 5.1
Set-StrictMode -Version Latest

function Set-SafeUploadPayloadAccess {
    param([string]$Path, [string]$OwnerRoot, [switch]$Recurse)
    # Same-volume moves retain staging ACLs. Seal private copies, then inherit
    # the installed parent's read-only binary access when activating them.
    $owner = (Get-Acl -LiteralPath $OwnerRoot).GetOwner([Security.Principal.SecurityIdentifier]).Value
    $arguments = @($Path, '/setowner', ('*' + $owner), '/Q')
    if ($Recurse) { $arguments += '/T' }
    & (Join-Path $env:SystemRoot 'System32/icacls.exe') @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not set the payload owner.' }
    $arguments = @($Path, '/reset', '/Q')
    if ($Recurse) { $arguments += '/T' }
    & (Join-Path $env:SystemRoot 'System32/icacls.exe') @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not inherit payload access from its trusted parent.' }
}

function Get-SafeUploadManagedPayload {
    param([Parameter(Mandatory)][string]$Root)
    $manifest = Test-SafeUploadPayload -Root $Root
    foreach ($file in $manifest.files) {
        $path = [string]$file.path
        if ($path -notmatch '^(service|ui|setup)/.+$|^driver/SafeUpload\.(sys|inf)$|^prereq/winfsp\.msi$|^(LICENSE|LEIA-ME)\.txt$' -or $path.Contains('\') -or
            $path -eq 'setup/installation.json') {
            throw 'Unexpected maintenance payload layout.'
        }
        foreach ($part in $path.Split('/')) {
            if ($part -in @('', '.', '..') -or $part -match '[<>:"|?*\x00-\x1f]|[. ]$' -or
                $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') { throw 'Noncanonical Windows payload path.' }
        }
    }
    foreach ($relative in @('service/SafeUpload.Agent.Service.exe', 'ui/SafeUpload.Agent.App.exe',
        'setup/Invoke-AgentSetup.ps1', 'setup/SafeUpload.Setup.psm1')) {
        if (@($manifest.files | Where-Object path -eq $relative).Count -ne 1) { throw 'Required maintenance payload file is absent.' }
    }
    return $manifest
}

function Assert-SafeUploadMaintenancePrerequisites {
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$InstallRoot)
    $manifest = Get-SafeUploadMaintenancePayload $Source
    foreach ($file in @($manifest.files | Where-Object { $_.path -match '^(driver|prereq)/' })) {
        $target = Join-Path $InstallRoot $file.path
        $parent = Split-Path -Parent $target
        $null = Assert-SafeUploadDirectory $parent $parent
        if (-not (Test-Path -LiteralPath $target -PathType Leaf) -or
            ((Get-Item -LiteralPath $target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            (Get-FileHash -LiteralPath $target).Hash -ne $file.sha256) {
            throw 'Application maintenance cannot add or replace driver/WinFsp prerequisites.'
        }
    }
}

function Get-SafeUploadMaintenancePayload {
    param([Parameter(Mandatory)][string]$Root)
    $manifest = Get-SafeUploadManagedPayload $Root
    $version = $null
    if (-not [Version]::TryParse([string]$manifest.version, [ref]$version) -or
        $manifest.commit -notmatch '^[0-9a-f]{40}$' -or $manifest.sourceDirty -ne $false -or
        $manifest.runtime -ne 'win-x64' -or $manifest.selfContained -ne $true) {
        throw 'Maintenance requires a clean, versioned win-x64 self-contained package.'
    }
    return $manifest
}

function Copy-SafeUploadMaintenancePayload {
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
    $manifest = Get-SafeUploadMaintenancePayload $Source
    if (Test-Path -LiteralPath $Destination) { throw 'Maintenance staging destination already exists.' }
    $destinationRoot = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    $null = Assert-SafeUploadDirectory $destinationRoot $destinationRoot
    New-Item -ItemType Directory -Path $destinationRoot | Out-Null
    foreach ($file in $manifest.files) {
        $target = Join-Path $destinationRoot $file.path
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        [IO.File]::Copy((Join-Path $Source $file.path), $target, $false)
    }
    [IO.File]::Copy((Join-Path $Source 'payload-manifest.json'), (Join-Path $destinationRoot 'payload-manifest.json'), $false)
    Set-SafeUploadPayloadAccess $destinationRoot $destinationRoot -Recurse
    $copied = Get-SafeUploadMaintenancePayload $destinationRoot
    if ($copied.commit -ne $manifest.commit -or $copied.version -ne $manifest.version) { throw 'Payload changed during staging.' }
    return $copied
}

function Assert-SafeUploadMaintenanceTree {
    param([Parameter(Mandatory)][string]$Root)
    $null = Assert-SafeUploadDirectory $Root $Root
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue([IO.Path]::GetFullPath($Root))
    $count = 0
    while ($pending.Count) {
        foreach ($entry in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
            if (++$count -gt 20000) { throw 'Maintenance tree exceeds its entry limit.' }
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Links and junctions are not maintenance targets.' }
            if ($entry.PSIsContainer) { $pending.Enqueue($entry.FullName) }
        }
    }
}

function Set-SafeUploadMaintenancePayload {
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$InstallRoot,
          [Parameter(Mandatory)][string]$WorkRoot)
    # Only these three binary/helper directories are moved. Neither endpoint data
    # nor driver/WinFsp files are maintenance payloads.
    $null = Get-SafeUploadMaintenancePayload $Source
    Assert-SafeUploadMaintenancePrerequisites $Source $InstallRoot
    $install = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
    $work = [IO.Path]::GetFullPath($WorkRoot).TrimEnd('\')
    foreach ($path in @($install, $work)) { $null = Assert-SafeUploadDirectory $path $path }
    if ($work.Equals($install, [StringComparison]::OrdinalIgnoreCase) -or
        $work.StartsWith($install + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $install.StartsWith($work + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Maintenance roots must be separate.' }
    foreach ($name in @('service', 'ui', 'setup')) {
        $target = Join-Path $install $name
        if (Test-Path -LiteralPath $target) { Assert-SafeUploadMaintenanceTree $target }
    }
    $activation = Join-Path $work ('activation-' + [Guid]::NewGuid().ToString('N'))
    $null = Copy-SafeUploadMaintenancePayload $Source $activation
    $displaced = Join-Path $work ('displaced-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $displaced | Out-Null
    foreach ($name in @('service', 'ui', 'setup')) {
        $target = [IO.Path]::GetFullPath((Join-Path $install $name))
        $saved = [IO.Path]::GetFullPath((Join-Path $displaced $name))
        if (-not $target.StartsWith($install + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not $saved.StartsWith($work + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe maintenance move.' }
        if (Test-Path -LiteralPath $target) { Move-Item -LiteralPath $target -Destination $saved }
        Move-Item -LiteralPath (Join-Path $activation $name) -Destination $target
        Set-SafeUploadPayloadAccess $target $install -Recurse
    }
    foreach ($name in @('LICENSE.txt', 'LEIA-ME.txt', 'payload-manifest.json')) {
        $target = Join-Path $install $name
        if (Test-Path -LiteralPath $target) {
            if ((Get-Item -LiteralPath $target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked payload metadata refused.' }
            Move-Item -LiteralPath $target -Destination (Join-Path $displaced $name)
        }
        if (Test-Path -LiteralPath (Join-Path $activation $name)) {
            Move-Item -LiteralPath (Join-Path $activation $name) -Destination $target
            Set-SafeUploadPayloadAccess $target $install
        }
    }
    return Get-SafeUploadMaintenancePayload $install
}

function Remove-SafeUploadManagedPayload {
    param([Parameter(Mandatory)][string]$InstallRoot)
    $manifest = Get-SafeUploadManagedPayload $InstallRoot
    # Validate the whole managed tree before the first deletion. Inno's original
    # uninstall log cannot know files introduced by a later maintenance package.
    foreach ($name in @('service', 'ui', 'setup')) { Assert-SafeUploadMaintenanceTree (Join-Path $InstallRoot $name) }
    foreach ($file in $manifest.files) { Remove-Item -LiteralPath (Join-Path $InstallRoot $file.path) -Force }
    Remove-Item -LiteralPath (Join-Path $InstallRoot 'payload-manifest.json') -Force
    # Leave untracked files and runtime state for Inno/administrator review.
}

Export-ModuleMember -Function Get-SafeUploadManagedPayload, Get-SafeUploadMaintenancePayload, Copy-SafeUploadMaintenancePayload,
    Assert-SafeUploadMaintenanceTree, Assert-SafeUploadMaintenancePrerequisites, Set-SafeUploadMaintenancePayload, Remove-SafeUploadManagedPayload
