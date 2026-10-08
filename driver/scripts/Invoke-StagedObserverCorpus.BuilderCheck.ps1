<# Windows PowerShell 5.1 builder-only check. Runs no coordinator main or corpus code.
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-StagedObserverCorpus.BuilderCheck.ps1
     -Coordinator .\Invoke-StagedObserverCorpus.ps1
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Coordinator)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Windows PowerShell 5.1 required'}

$expected='86A099AD380A0F29563624712B613982E550EDB4373FD2886BAEBA202F8C90FA'
$bytes=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Coordinator).ProviderPath)
$sha=[Security.Cryptography.SHA256]::Create()
try{$actual=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')}
finally{$sha.Dispose()}
if($actual -cne $expected){throw ('Coordinator source hash mismatch: '+$actual)}
Write-Output ('CoordinatorSha256='+$actual)
$source=(New-Object System.Text.UTF8Encoding($false,$true)).GetString($bytes)
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
Write-Output ('CoordinatorParseErrors='+@($errors).Count)
if(@($errors).Count -ne 0){foreach($e in $errors){Write-Output ('ParseError='+$e.Extent.StartLineNumber+':'+$e.Message)};throw 'Coordinator parse failed'}
foreach($name in @('Write-NewJson','Hash-Stream','New-VerifiedArchive')){
    $definitions=@($ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($definitions.Count -ne 1){throw ('Missing/duplicate actual top-level helper: '+$name)}
    . ([scriptblock]::Create($definitions[0].Extent.Text))
    Write-Output ('ActualHelper='+$name+';Line='+$definitions[0].Extent.StartLineNumber)
}
$exclusiveAddTypes=@($ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Add-Type' -and
    $node.Extent.Text.Contains('SafeUploadExclusiveDirectory')
},$true))
if($exclusiveAddTypes.Count -ne 1 -or
   -not $exclusiveAddTypes[0].Extent.Text.Contains('EntryPoint="CreateDirectoryW"')){
    throw 'Missing/duplicate actual exclusive-directory Add-Type declaration'
}
. ([scriptblock]::Create($exclusiveAddTypes[0].Extent.Text))
Write-Output ('ActualExclusiveDirectoryDeclaration=COMPILED;Line='+$exclusiveAddTypes[0].Extent.StartLineNumber)

# Independent CRC check over central-directory entries made by the actual archive helper.
Add-Type -ReferencedAssemblies 'System.IO.Compression' -TypeDefinition @'
using System; using System.IO; using System.IO.Compression; using System.Text;
public static class BuilderArchiveCrc {
  static uint Crc(byte[] data) { uint c=0xffffffffu; foreach(byte b in data) {
    c ^= b; for(int i=0;i<8;i++) c=(c&1u)!=0 ? (c>>1)^0xedb88320u : c>>1;
  } return ~c; }
  public static int Check(string path) {
    byte[] raw=File.ReadAllBytes(path); int end=-1;
    for(int p=raw.Length-22;p>=0 && p>=raw.Length-65557;p--)
      if(BitConverter.ToUInt32(raw,p)==0x06054b50u){end=p;break;}
    if(end<0) throw new Exception("ZIP end record absent");
    int count=BitConverter.ToUInt16(raw,end+10), cursor=(int)BitConverter.ToUInt32(raw,end+16);
    using(var input=File.OpenRead(path)) using(var zip=new ZipArchive(input,ZipArchiveMode.Read,false)) {
      if(zip.Entries.Count!=count) throw new Exception("ZIP central inventory count mismatch");
      for(int i=0;i<count;i++) {
        if(cursor+46>raw.Length || BitConverter.ToUInt32(raw,cursor)!=0x02014b50u) throw new Exception("ZIP central header absent");
        uint stored=BitConverter.ToUInt32(raw,cursor+16), length=BitConverter.ToUInt32(raw,cursor+24);
        int nameLen=BitConverter.ToUInt16(raw,cursor+28),extra=BitConverter.ToUInt16(raw,cursor+30),comment=BitConverter.ToUInt16(raw,cursor+32);
        if(cursor+46+nameLen+extra+comment>raw.Length) throw new Exception("ZIP central bounds");
        string name=Encoding.UTF8.GetString(raw,cursor+46,nameLen);
        var entry=zip.Entries[i]; if(entry.FullName!=name || entry.Length!=length) throw new Exception("ZIP entry identity/length mismatch: "+name);
        using(var stream=entry.Open()) using(var copy=new MemoryStream()) {stream.CopyTo(copy);if(Crc(copy.ToArray())!=stored)throw new Exception("ZIP CRC mismatch: "+name);}
        cursor+=46+nameLen+extra+comment;
      }
    }
    return count;
  }
}
'@ -ErrorAction Stop

$RunGuid=[guid]::NewGuid().ToString('N').ToLowerInvariant()
$leaf='SafeUpload-coordinator-builder-check-'+$RunGuid
$temp=Join-Path $env:TEMP $leaf
$report=Join-Path $PSScriptRoot ('observer-coordinator-builder-check-'+$RunGuid+'.json')
if([IO.Directory]::Exists($temp) -or [IO.File]::Exists($report)){throw 'GUID-owned check path collision'}
$process=$null;$safeToClean=$true;$passed=$false
$records=New-Object 'System.Collections.Generic.List[object]'
try {
    [void][IO.Directory]::CreateDirectory($temp)
    $exclusive=Join-Path $temp 'exclusive-create'
    if([IO.Directory]::Exists($exclusive) -or [IO.File]::Exists($exclusive)){throw 'Exclusive directory control collision'}
    if(-not [SafeUploadExclusiveDirectory]::Create($exclusive,[IntPtr]::Zero) -or
       -not [IO.Directory]::Exists($exclusive)){throw 'Actual exclusive directory create failed'}
    if([SafeUploadExclusiveDirectory]::Create($exclusive,[IntPtr]::Zero)){
        throw 'Actual exclusive directory create accepted duplicate'
    }
    $duplicateError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if($duplicateError -ne 183){throw ('Duplicate create did not return ERROR_ALREADY_EXISTS: '+$duplicateError)}
    Write-Output 'ActualExclusiveDirectoryCreate=PASS;DuplicateRejected=True;Win32=183'
    $fixture=Join-Path $temp 'evidence';[void][IO.Directory]::CreateDirectory($fixture)
    $nested=Join-Path $fixture 'nested';[void][IO.Directory]::CreateDirectory($nested)
    $data=[byte[]](0,1,2,3,128,255,42,17)
    [IO.File]::WriteAllBytes((Join-Path $nested 'bytes.bin'),$data)
    Write-NewJson (Join-Path $nested 'facts.json') ([pscustomobject]@{Schema='BuilderFixture/1';RunGuid=$RunGuid;Bytes=$data.Length})
    $child=Join-Path $temp 'child.ps1'
    [IO.File]::WriteAllText($child,"param([int]`$Code)`n[Console]::Out.WriteLine('stdout-'+`$Code)`n[Console]::Error.WriteLine('stderr-'+`$Code)`nexit `$Code`n",[Text.Encoding]::UTF8)
    foreach($code in @(0,1,2)) {
        $stdout=Join-Path $temp ('child-'+$code+'-stdout.txt')
        $stderr=Join-Path $temp ('child-'+$code+'-stderr.txt')
        $args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$child+'" -Code '+$code
        $process=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $args -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        try {
            $handle=$process.Handle
            if($handle -eq [IntPtr]::Zero){throw 'Child process Handle unavailable'}
            if(-not $process.WaitForExit(15000)) {
                try{$process.Kill()}catch{}
                [void]$process.WaitForExit(5000)
                throw ('Child timeout for exit '+$code)
            }
            if(-not $process.HasExited){throw 'Child remains live after finite wait'}
            $exitValue=$process.ExitCode
            if($null -eq $exitValue -or [int]$exitValue -ne $code){throw ('Child ExitCode mismatch for '+$code)}
        } finally {
            if($null -ne $process){
                if(-not $process.HasExited){try{$process.Kill();[void]$process.WaitForExit(5000)}catch{}}
                if(-not $process.HasExited){$safeToClean=$false;throw 'Child remains live; preserve owned path'}
                $process.Dispose();$process=$null
            }
        }
        $outText=[IO.File]::ReadAllText($stdout);$errText=[IO.File]::ReadAllText($stderr)
        if($outText.Trim() -cne ('stdout-'+$code) -or $errText.Trim() -cne ('stderr-'+$code)){throw ('Child stream mismatch for '+$code)}
        [IO.File]::Copy($stdout,(Join-Path $fixture ('child-'+$code+'-stdout.txt')))
        [IO.File]::Copy($stderr,(Join-Path $fixture ('child-'+$code+'-stderr.txt')))
        $records.Add([pscustomobject]@{ExitExpected=$code;ExitActual=$code;Stdout=$outText.Trim();Stderr=$errText.Trim();HandleNonzero=$true})
        Write-Output ('ChildExit'+$code+'=PASS;StdoutAndStderrPreserved=True')
    }
    $zipPath=Join-Path $temp 'evidence.zip'
    $archiveHash=New-VerifiedArchive $fixture $zipPath
    if($archiveHash -cne (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToUpperInvariant()){throw 'Archive result hash mismatch'}
    $manifest=Get-Content -LiteralPath (Join-Path $fixture 'archive-manifest.json') -Raw | ConvertFrom-Json
    if($manifest.Schema -cne 'ObserverCorpusArchive/1' -or $manifest.RunGuid -cne $RunGuid -or @($manifest.Entries).Count -ne 8){throw 'Archive manifest inventory mismatch'}
    $expectedNames=@('nested/bytes.bin','nested/facts.json','child-0-stdout.txt','child-0-stderr.txt','child-1-stdout.txt','child-1-stderr.txt','child-2-stdout.txt','child-2-stderr.txt')
    if(@($manifest.Entries | Where-Object {$expectedNames -cnotcontains $_.Path}).Count -ne 0){throw 'Unexpected archive manifest path'}
    foreach($entry in $manifest.Entries){
        $file=Join-Path $fixture ($entry.Path.Replace('/','\'))
        if((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToUpperInvariant() -cne $entry.Sha256 -or (Get-Item -LiteralPath $file).Length -ne $entry.Length){throw ('Manifest content mismatch: '+$entry.Path)}
    }
    $crcCount=[BuilderArchiveCrc]::Check($zipPath)
    if($crcCount -ne 9){throw ('ZIP inventory/CRC count mismatch: '+$crcCount)}
    $passed=$true
    Write-Output ('ActualArchiveRoundTrip=PASS;Entries='+$crcCount+';ArchiveSha256='+$archiveHash+';CentralDirectoryCrcChecked=True')
} finally {
    if($null -ne $process){
        try{if(-not $process.HasExited){$process.Kill();[void]$process.WaitForExit(5000)}}catch{}
        if($process.HasExited){$process.Dispose();$process=$null}else{$safeToClean=$false}
    }
    $saved=[pscustomobject]@{Schema='ObserverCoordinatorBuilderCheck/1';RunGuid=$RunGuid;CoordinatorSha256=$actual;
        Passed=$passed;NotVmQualification=$true;ChildRuns=$records.ToArray();ArchiveSha256=$(if($passed){$archiveHash}else{$null});
        CentralDirectoryCrcChecked=$passed;ExclusiveDirectoryDuplicateRejected=$passed;TempPath=$temp;TempCleanupPlanned=$safeToClean;Utc=[DateTime]::UtcNow.ToString('o')}
    if([IO.File]::Exists($report)){throw 'Report path collision'}
    Write-NewJson $report $saved
    Write-Output ('BuilderCheckReport='+$report)
    if($safeToClean -and [IO.Directory]::Exists($temp)){
        if([IO.Path]::GetFileName($temp) -cne $leaf){throw 'Unsafe temporary cleanup path'}
        foreach($item in @(Get-Item -LiteralPath $temp -Force) + @(Get-ChildItem -LiteralPath $temp -Recurse -Force)){
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse path in owned temporary tree; preserve it'}
        }
        [IO.Directory]::Delete($temp,$true)
        if([IO.Directory]::Exists($temp)){throw 'Owned temporary tree still exists'}
        Write-Output 'OwnedTemporaryTreeCleaned=True'
    }
}
if(-not $passed){throw 'Builder-only coordinator check failed; inspect preserved report'}
Write-Output 'BuilderCoordinatorCheck=PASS;NotVmQualification=True'
