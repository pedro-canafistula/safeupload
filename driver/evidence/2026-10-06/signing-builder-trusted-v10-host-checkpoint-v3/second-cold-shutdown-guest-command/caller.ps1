$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.User.Value -cne 'S-1-5-21-316478115-1595729549-2803163825-1001'){throw 'Wrong user SID'}
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Expected enabled administrator token'}
$actors=@(Get-Process -Name 'msiexec','MSBuild','dotnet','csc','VBCSCompiler' -ErrorAction SilentlyContinue)
if($actors.Count){throw 'Build/installer actors active; shutdown withheld'}
Write-Output 'PinnedBuilderIdentityAndNoActorsVerified=True; NormalShutdownRequested=True; ForcedShutdown=False'
& 'C:\Windows\System32\shutdown.exe' /s /t 0
$code=$LASTEXITCODE
Write-Output ('NormalShutdownNativeExitCode='+$code)
if($code -ne 0){throw 'Normal shutdown command failed'}
