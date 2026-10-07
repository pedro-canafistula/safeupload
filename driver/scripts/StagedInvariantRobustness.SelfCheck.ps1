#requires -Version 5.1
# Synthetic inventory/extent controls and local native error probes only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
try {
    Import-Module (Join-Path $PSScriptRoot 'StagedInvariantObserver.psm1') -Force -DisableNameChecking
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors | Out-String)}
    foreach($name in @('Get-NotificationInventoryDecision','Get-ErrorChain','Test-ActivationRawWholeImage','Get-ActivationSha256','Test-CachedImage')){
        $defs=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
        if($defs.Count -ne 1){throw ('Missing/ambiguous function: '+$name)}
        Invoke-Expression ($defs[0].Extent.Text.Replace(('function '+$name),('function script:'+$name)))
    }
    $checks=0
    function Check([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason};$script:checks++}
    function InventoryWait {
        return [ordered]@{StartQpc=$null;DeadlineQpc=$null;OuterDeadlineQpc=30000;EndQpc=$null;QpcFrequency=1000;
            TimeoutSeconds=5;PollMilliseconds=25;DurationMs=$null;Cleared=$false;TimedOut=$false;Windows=@();Observations=@()}
    }
    $known=@('emissions.jsonl','previous.jsonl','head.json','writer.lock')
    $w=InventoryWait;$r=Get-NotificationInventoryDecision $known 100 $w
    Check ($r.Decision -ceq 'Accept' -and $null -eq $w.StartQpc) 'Known inventory needs no transient wait.'
    $w=InventoryWait;$r=Get-NotificationInventoryDecision ($known+@('head.tmp')) 100 $w
    Check ($r.Decision -ceq 'Wait' -and $w.StartQpc -eq 100 -and $w.DeadlineQpc -eq 5100 -and $r.UnknownChildNames.Count -eq 1 -and $r.UnknownChildNames[0] -ceq 'head.tmp') 'Only head.tmp gets a recorded five-second QPC budget.'
    $r=Get-NotificationInventoryDecision ($known+@('head.tmp')) 5099 $w
    Check ($r.Decision -ceq 'Wait' -and $w.DeadlineQpc -eq 5100) 'Repeated head.tmp cannot extend the budget.'
    $r=Get-NotificationInventoryDecision $known 5099 $w
    Check ($r.Decision -ceq 'Accept' -and $w.Cleared -and $w.DurationMs -eq 4999 -and $w.Observations.Count -eq 3 -and $w.Observations[0].ChildNames -ccontains 'head.tmp') 'A complete retry before the deadline retains the original exact inventory.'
    $r=Get-NotificationInventoryDecision $known 9000 $w
    Check ($r.Decision -ceq 'Accept' -and $w.DurationMs -eq 4999 -and $w.EndQpc -eq 5099) 'A cleared transient does not expire later clean heartbeat snapshots or extend its duration.'
    $r=Get-NotificationInventoryDecision ($known+@('head.tmp')) 9001 $w
    Check ($r.Decision -ceq 'Wait' -and $w.DeadlineQpc -eq 14001 -and $w.Windows.Count -eq 2 -and $w.Windows[0].Cleared -and $w.Windows[0].DurationMs -eq 4999) 'A later atomic replacement gets its own bounded window while prior wait evidence survives.'
    foreach($now in @(5100,5101)){
        $w=InventoryWait;$null=Get-NotificationInventoryDecision ($known+@('head.tmp')) 100 $w
        $r=Get-NotificationInventoryDecision ($known+@('head.tmp')) $now $w
        Check ($r.Decision -ceq 'Reject' -and $w.TimedOut -and $r.Reason -like '*head.tmp*QPC-bounded 5 s*') 'Persistent head.tmp fails at/after deadline.'
        $r=Get-NotificationInventoryDecision $known $now $w
        Check ($r.Decision -ceq 'Reject' -and -not $w.Cleared) 'A late clean inventory cannot qualify.'
    }
    foreach($extra in @(@('other.tmp'),@('head.tmp','other.tmp'),@('HEAD.TMP'),@('odd|name','another.tmp'))){
        $w=InventoryWait;$r=Get-NotificationInventoryDecision ($known+$extra) 100 $w
        Check ($r.Decision -ceq 'Reject' -and $null -eq $w.StartQpc -and ($r.UnknownChildNames -join ',') -ceq ($extra -join ',')) 'Other unknowns retain exact names and never get a head.tmp retry.'
        foreach($name in $extra){Check ($r.Reason.Contains($name)) 'The exception reason retains each unrecognized name.'}
    }
    $w=InventoryWait;$r=Get-NotificationInventoryDecision @('emissions.jsonl','writer.lock','head.tmp') 100 $w
    Check ($r.Decision -ceq 'Reject' -and $r.MissingChildNames[0] -ceq 'head.json') 'head.tmp does not excuse a missing required child.'
    $w=InventoryWait;$w.OuterDeadlineQpc=200;$r=Get-NotificationInventoryDecision ($known+@('head.tmp')) 100 $w
    Check ($w.DeadlineQpc -eq 200) 'Transient wait also respects the outer snapshot deadline.'
    $w=InventoryWait;$null=Get-NotificationInventoryDecision ($known+@('head.tmp')) 100 $w
    $r=Get-NotificationInventoryDecision ($known+@('head.tmp','new.tmp')) 200 $w
    Check ($r.Decision -ceq 'Reject' -and $r.UnknownChildNames.Count -eq 2) 'An unexpected child on a retry fails immediately.'

    $dir=Join-Path ([IO.Path]::GetTempPath()) ('observer-robustness-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($dir);$v=$null;$exclusive=$null
    try {
        $target=Join-Path $dir 'marker.txt';[IO.File]::WriteAllBytes($target,[byte[]]@(1,2,3))
        $exclusive=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $diagnostic=& (Get-Module StagedInvariantObserver) {param($p) Get-IONamedOpenDiagnostic $p} $target
        Check ($diagnostic.Status -ceq 'ERROR' -and $diagnostic.DiagnosticOnly -and $diagnostic.DiagnosticErrors[0].NativeCode -eq 32 -and $diagnostic.DiagnosticErrors[0].NativeNtStatus -ceq '0xC0000043') 'Named sharing failure retains Win32 32 plus immediate STATUS_SHARING_VIOLATION.'
        Check ($diagnostic.DiagnosticErrors[0].Chain[-1].Message -like '*RtlGetLastNtStatus=0xC0000043*' -and $diagnostic.EndQpc -ge $diagnostic.StartQpc) 'Exception and diagnostic evidence both retain NTSTATUS and QPC bracket.'
        $missing=$null
        try{$h=[StagedInvariant.Native]::Open((Join-Path $dir 'absent.txt'),$false,$false);$h.Dispose()}catch{$missing=$_.Exception}
        $chain=Get-ErrorChain $missing
        Check ($chain[-1].NativeCode -eq 2 -and $chain[-1].NativeNtStatus -ceq '0xC0000034') 'Missing native open retains the distinct STATUS_OBJECT_NAME_NOT_FOUND in suite evidence.'
        Check ($diagnostic.DiagnosticErrors[0].NativeNtStatus -ceq '0xC0000043') 'A later failing native call cannot overwrite the earlier error receipt.'
        function PinnedImage {
            $x=[StagedInvariant.Image]::new();$x.Identity=[StagedInvariant.Identity]::new()
            $x.Identity.VolumeSerial=42;$x.Identity.Reference=844424930131975;$x.Identity.FileId='07000000000003000000000000000000'
            $x.Identity.Eof=8192;$x.Identity.Allocation=8192;$x.Identity.Attributes=32;$x.Identity.Links=1
            $x.RawMetadata=$x.Identity;$x.CrossCheckErrors=[string[]]@();$x.Names=[StagedInvariant.NameEntry[]]@();$x.Resident=$false
            $r1=[StagedInvariant.Run]::new();$r1.Vcn=0;$r1.NextVcn=1;$r1.Lcn=2
            $r2=[StagedInvariant.Run]::new();$r2.Vcn=1;$r2.NextVcn=2;$r2.Lcn=4
            $x.Runs=[StagedInvariant.Run[]]@($r1,$r2)
            $a=[StagedInvariant.Attribute]::new();$a.Type=0x80;$a.Name='';$a.Id=1;$a.RecordReference=$x.Identity.Reference
            $a.NonResident=$true;$a.StartVcn=0;$a.LastVcn=1;$a.Eof=8192;$a.ValidData=8192;$a.Allocation=8192;$a.Runs=$x.Runs
            $x.Attributes=[StagedInvariant.Attribute[]]@($a)
            $rec=[StagedInvariant.Record]::new();$rec.Number=7;$rec.Sequence=3;$rec.Raw=[byte[]]::new(1024);$rec.Fixed=[byte[]]::new(1024);$rec.Fixed[18]=1
            $x.Records=[StagedInvariant.Record[]]@($rec)
            $n=[StagedInvariant.NameEntry]::new();$n.Name='marker.txt';$n.Namespace=1;$n.Reference=$x.Identity.Reference;$n.Parent=844424930131976
            $x.FileNames=[StagedInvariant.NameEntry[]]@($n);return $x
        }
        $p=[byte[]]::new(8192);$u=[byte[]]::new(8192)
        for($i=0;$i -lt $u.Length;$i++){$p[$i]=[byte]($i%251);$u[$i]=[byte](($i+13)%251)}
        $disk=[byte[]]::new(20480);[Array]::Copy($u,0,$disk,8192,4096);[Array]::Copy($u,4096,$disk,16384,4096)
        $diskPath=Join-Path $dir 'synthetic-volume.bin';[IO.File]::WriteAllBytes($diskPath,$disk)
        $v=[StagedInvariant.Volume]::new();$v.Raw=[StagedInvariant.Native]::Open($diskPath,$false,$false)
        $v.Geometry=[StagedInvariant.Geometry]::new();$v.Geometry.Serial=42;$v.Geometry.Cluster=4096;$v.Geometry.Alignment=512;$v.Geometry.TotalBytes=20480
        $original=PinnedImage;$original.Logical=$p;$original.Digest=[StagedInvariant.Native]::Hash($p)
        $result=[StagedInvariant.Native]::SelfCheckPinnedCapture($v,$original,[StagedInvariant.Image[]]@((PinnedImage),(PinnedImage),(PinnedImage)))
        Check ($result.Digest -ceq [StagedInvariant.Native]::Hash($u) -and $result.Digest -cne $original.Digest -and $result.Containers.Count -eq 4 -and $result.Containers[0].Offset -eq 8192 -and $result.Containers[1].Offset -eq 16384) 'Raw sample reads current U from every pinned fragmented extent despite the denied named open.'
        $context=[pscustomobject]@{EvidenceDirectory=$dir}
        $saved=& (Get-Module StagedInvariantObserver) {param($c,$i,$p) Save-IOPinnedImage $c $i $p 'Current'} $context $result $target
        $saved | Add-Member NoteProperty Absent $false
        Check ($saved.Path -ceq $target -and $saved.IdentitySource -ceq 'RawMft' -and $saved.DataSource -ceq 'RawVolumePreEpochExtents' -and $null -eq $saved.Sddl) 'Archiving a pinned sample needs no named ACL/data open and labels the raw source.'
        $sample=@{Status='OK';Images=@($saved)}
        Check ((Test-ActivationRawWholeImage $sample $target $u).Verdict -ceq 'PASS') 'Existing whole-byte A assertion accepts exact U.'
        Check ((Test-ActivationRawWholeImage $sample $target $p).Verdict -ceq 'FAIL') 'Existing whole-byte A assertion still rejects P when raw U is present.'
        # Exercise the unchanged A05 extent assertions on its cluster-aligned
        # contiguous fixture; the separate control above checks fragmented I/O.
        function ContiguousPinnedImage {
            $x=PinnedImage;$x.Runs[0].NextVcn=2;$x.Runs=[StagedInvariant.Run[]]@($x.Runs[0]);$x.Attributes[0].Runs=$x.Runs;return $x
        }
        [Array]::Copy($u,0,$disk,8192,$u.Length);[IO.File]::WriteAllBytes($diskPath,$disk)
        $contiguousOriginal=ContiguousPinnedImage
        $contiguous=[StagedInvariant.Native]::SelfCheckPinnedCapture($v,$contiguousOriginal,[StagedInvariant.Image[]]@((ContiguousPinnedImage),(ContiguousPinnedImage),(ContiguousPinnedImage)))
        $extentImage=& (Get-Module StagedInvariantObserver) {param($c,$i,$p) Save-IOPinnedImage $c $i $p 'Current'} $context $contiguous $target
        $extentImage | Add-Member NoteProperty Absent $false
        $extentChecks=Test-CachedImage $extentImage $v.Geometry $u 'PinnedControl'
        Check (@($extentChecks | Where-Object Verdict -cne 'PASS').Count -eq 0) ('Existing raw DATA coverage/hash/byte assertions all pass for exact U: '+($extentChecks | ConvertTo-Json -Depth 8 -Compress))
        $badBytes=[byte[]]$u.Clone();$badBytes[5000]=[byte]($badBytes[5000]+1)
        Check (@(Test-CachedImage $extentImage $v.Geometry $badBytes 'PinnedControl' | ForEach-Object {$_} | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'A single wrong byte still fails the raw DATA assertions.'
        foreach($stage in @(0,1,2)){
            foreach($change in @('volume','id','reference','eof','allocation','lcn','vcn','resident','vdl','flags','compression','attributes','record-sequence','record-links','name-parent')){
                $bracket=[StagedInvariant.Image[]]@((PinnedImage),(PinnedImage),(PinnedImage));$bad=$bracket[$stage]
                switch($change){
                    'volume'{$bad.Identity.VolumeSerial=43}'id'{$bad.Identity.FileId='other'}'reference'{$bad.Identity.Reference++}
                    'eof'{$bad.Identity.Eof--}'allocation'{$bad.Identity.Allocation+=4096}'lcn'{$bad.Runs[0].Lcn++}'vcn'{$bad.Runs[0].NextVcn++}
                    'resident'{$bad.Resident=$true}'vdl'{$bad.Attributes[0].ValidData--}'flags'{$bad.Attributes[0].Flags=0x8000}
                    'compression'{$bad.Attributes[0].CompressionUnit=1}'attributes'{$bad.Identity.Attributes=33}
                    'record-sequence'{$bad.Records[0].Sequence++}'record-links'{$bad.Records[0].Fixed[18]=2}'name-parent'{$bad.FileNames[0].Parent++}
                }
                $rejected=$false
                try{$null=[StagedInvariant.Native]::SelfCheckPinnedCapture($v,$original,$bracket)}catch{$rejected=$_.Exception.InnerException.Phase -ceq 'PinnedLayout'}
                Check $rejected ('Pinned capture fails closed for '+$change+' at metadata bracket '+$stage+'.')
            }
        }
        foreach($id in @('A01','A02','A03','A05','R02')){Check ([StagedInvariant.Native]::UsesPinnedExtents($id)) ('Pinned raw samples selected for '+$id+'.')}
        foreach($id in @('A04','C01','R01','R03','X01','a01')){Check (-not [StagedInvariant.Native]::UsesPinnedExtents($id)) ('Existing publication capture retained for '+$id+'.')}
    } finally {
        if($null -ne $v){$v.Dispose()};if($null -ne $exclusive){$exclusive.Dispose()}
        [IO.Directory]::Delete($dir,$true)
    }
    'RobustnessSelfCheck=PASS;Checks='+$checks
} catch { 'RobustnessSelfCheck=FAIL;'+$_.Exception.ToString()+';'+$_.ScriptStackTrace;exit 1 }
