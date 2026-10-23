#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputParent,
    [Parameter(Mandatory)][string]$ProbePath,
    [Parameter(Mandatory)][string]$ManifestPath,
    [ValidateSet('GitHubHosted','Clone')][string]$Context='GitHubHosted'
)
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
# Refuse ordinary development hosts before creating files or calling DiskPart.
if($Context -eq 'GitHubHosted'){
    Require ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted' -and $env:GITHUB_REPOSITORY -eq 'pedro-canafistula/safeupload') 'Somente runner GitHub-hosted descartavel.'
    $allowedParent=[IO.Path]::GetFullPath((Join-Path $env:GITHUB_WORKSPACE 'artifacts\queue-full'))
}else{
    Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Somente clone de homologacao.'
    $allowedParent='C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\disk-full'
}
Require (([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao necessaria.'
$parent=[IO.Path]::GetFullPath($OutputParent).TrimEnd('\')
Require ($parent.Equals($allowedParent,[StringComparison]::OrdinalIgnoreCase)) 'Diretorio de laboratorio inesperado.'
for($dir=[IO.DirectoryInfo]::new($parent);$null -ne $dir;$dir=$dir.Parent){if($dir.Exists){Require (-not($dir.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Ancestral redirecionado.'}}
$probe=Get-Item -LiteralPath $ProbePath
$manifest=Get-Content -LiteralPath $ManifestPath -Raw|ConvertFrom-Json
Require ($probe.Name -eq 'QueueFullVolumeProbe.exe' -and (Get-FileHash -LiteralPath $probe.FullName).Hash -eq $manifest.sha256 -and $probe.Length -eq $manifest.bytes) 'Ferramenta divergente do manifesto.'
$drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($parent))
Require ($drive.AvailableFreeSpace -gt 2GB) 'Manter ao menos 2 GiB livres no disco de apoio.'
$nonce=[Guid]::NewGuid().ToString('N');$label='SUQ'+$nonce.Substring(0,12)
$lab=Join-Path $parent ('volume-'+$nonce)
Require (-not(Test-Path $lab)) 'Laboratorio anterior; nao sobrescrever.'
New-Item -ItemType Directory -Path $lab -Force|Out-Null
$vhd=Join-Path $lab 'owned-64mb.vhd'
$state=[ordered]@{result='running';context=$Context;startedAtUtc=[DateTime]::UtcNow.ToString('o');nonce=$nonce;vhd=$vhd;maximumMiB=64;probeSha256=$manifest.sha256;probeSource=$manifest.commit;detached=$false}
function Save-State{$state|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $lab 'wrapper-result.json') -Encoding UTF8}
function Invoke-CapturedProcess([string]$File,[string]$Arguments,[string]$Name,[int]$TimeoutMs){
    # Own the Process handle from Start through ExitCode; Windows PowerShell 5.1
    # Start-Process -PassThru can lose the exit code of an already-exited child.
    $child=[Diagnostics.Process]::new()
    $child.StartInfo.FileName=$File;$child.StartInfo.Arguments=$Arguments
    $child.StartInfo.UseShellExecute=$false;$child.StartInfo.CreateNoWindow=$true
    $child.StartInfo.RedirectStandardOutput=$true;$child.StartInfo.RedirectStandardError=$true
    try{
        Require ($child.Start()) 'Processo nao iniciou.'
        $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
        if(-not $child.WaitForExit($TimeoutMs)){$child.Kill();$child.WaitForExit();throw 'Processo excedeu o tempo; preservar VHD e recibos.'}
        $exitCode=$child.ExitCode
        [IO.File]::WriteAllText((Join-Path $lab ($Name+'.log')),$stdout.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $lab ($Name+'.err.log')),$stderr.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
        return $exitCode
    }finally{$child.Dispose()}
}
function Invoke-OwnedDiskPart([string]$Name,[string[]]$Lines){
    $scriptFile=Join-Path $lab ($Name+'.txt');$log=Join-Path $lab ($Name+'.log')
    $Lines|Set-Content -LiteralPath $scriptFile -Encoding ASCII
    $exitCode=Invoke-CapturedProcess (Join-Path $env:SystemRoot 'System32\diskpart.exe') ('/s "'+$scriptFile+'"') $Name 60000
    $state[($Name+'ExitCode')]=$exitCode
    Require ($exitCode -eq 0) 'DiskPart falhou; preservar log.'
}
try{
    Require (-not(Test-Path $vhd)) 'Imagem existente; recusar criacao.'
    Save-State
    # No physical disk number or image supplied by the caller is accepted.
    Invoke-OwnedDiskPart 'create-attach' @(('create vdisk file="'+$vhd+'" maximum=64 type=expandable'),('select vdisk file="'+$vhd+'"'),'attach vdisk','exit')
    $image=Get-DiskImage -ImagePath $vhd
    Require ($image.Attached -and [IO.Path]::GetFullPath($image.ImagePath).Equals($vhd,[StringComparison]::OrdinalIgnoreCase)) 'Imagem montada divergente.'
    $disk=$image|Get-Disk
    Require ($null -ne $disk -and -not $disk.IsBoot -and -not $disk.IsSystem -and $disk.Size -eq 64MB) 'Nao e o disco virtual pequeno criado pelo ensaio.'
    Require (@(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue).Count -eq 0) 'Imagem nova ja contem particoes.'
    $letter=@('P','Q','R','S','T','U','V','W','X','Y','Z')|Where-Object{-not(Test-Path ($_+':\')) -and -not(Get-Volume -DriveLetter $_ -ErrorAction SilentlyContinue)}|Select-Object -First 1
    Require ([bool]$letter) 'Nenhuma letra de volume livre.'
    # Disk number comes only from the just-created, verified VHD. Never clean a disk.
    Invoke-OwnedDiskPart 'partition-format' @(('select disk '+$disk.Number),'create partition primary',('format fs=ntfs quick label='+$label),('assign letter='+$letter),'exit')
    $partitions=@(Get-Partition -DiskNumber $disk.Number|Where-Object DriveLetter -eq $letter)
    Require ($partitions.Count -eq 1) 'Particao atribuida nao pertence ao VHD.'
    $volume=$partitions[0]|Get-Volume
    Require ($volume.FileSystem -eq 'NTFS' -and $volume.FileSystemLabel -eq $label -and $volume.Size -ge 32MB -and $volume.Size -le 64MB) 'Volume formatado divergente.'
    $root=$letter+':\';$volumeId=[string]$volume.Path
    Require ($volumeId -match '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$') 'Identidade de volume invalida.'
    [IO.File]::WriteAllText((Join-Path $root 'safeupload-full-volume.marker'),("SafeUpload disposable full-volume probe v1`n"+$nonce),[Text.UTF8Encoding]::new($false))
    $state.diskNumber=$disk.Number;$state.driveLetter=$letter;$state.volumeId=$volumeId;$state.volumeBytes=$volume.Size
    Save-State
    $results=Join-Path $lab 'probe-results'
    $state.probeExitCode=Invoke-CapturedProcess $probe.FullName ($root+' '+$nonce+' '+$volumeId+' "'+$results+'"') 'probe' 240000
    Require ($state.probeExitCode -eq 0) 'Ensaio falhou; consultar failure.json e logs.'
    $receipt=Get-Content (Join-Path $results 'result.json') -Raw|ConvertFrom-Json
    Require ($receipt.result -eq 'passed' -and @($receipt.phases).Count -eq 4) 'Recibo de quatro operacoes ausente.'
    $state.result='passed'
}catch{$state.result='failed';$state.error=$_.Exception.Message;throw}
finally{
    try{
        $image=Get-DiskImage -ImagePath $vhd -ErrorAction SilentlyContinue
        if($image -and $image.Attached){Dismount-DiskImage -ImagePath $vhd|Out-Null}
        $image=Get-DiskImage -ImagePath $vhd -ErrorAction SilentlyContinue
        $state.detached=(-not $image -or -not $image.Attached)
        if(-not $state.detached){$state.result='failed';$state.detachError='Imagem ainda montada.'}
    }catch{$state.result='failed';$state.detachError=$_.Exception.Message}
    $state.finishedAtUtc=[DateTime]::UtcNow.ToString('o');Save-State
}
Require ($state.result -eq 'passed' -and $state.detached) 'Aceite final incompleto; verificar recibo.'
Write-Output ('PASS: '+(Join-Path $lab 'wrapper-result.json'))
