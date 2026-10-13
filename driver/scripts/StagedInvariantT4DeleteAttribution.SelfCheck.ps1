#requires -Version 5.1
<# No kernel or VM needed. Extract the actual functions, never dot-source the coordinator.
   ALL KD samples below are SYNTHETIC, with invented addresses/IDs/counts. Pool rows follow:
   https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-poolfind
   https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-pool
   dd/dt field formatting follows:
   https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/dt--display-type-
   https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/d--da--db--dc--dd--dd--df--dp--dq--du--dw--dw--dyb--dyd--display-memory-
   FltMgr commands are documented via !fltkd.help (also retained in m2t4memdiag1):
   https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/development-and-testing-tools
   The context and T4 marker samples are synthetic contracts, not Microsoft documentation quotes
   or proof that a particular live extension build will supply every field. Unknown formats stay unresolved. #>
$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot 't4\memory-debugger.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ('Debugger helper parse errors: ' + ($errors | Out-String)) }
$names=@('Initialize-T4DeleteIdentity','ConvertTo-T4KdAddress','Get-T4KdSection','Get-T4KdErrors',
    'ConvertFrom-T4DeletePass1','Get-T4DeleteNewBlocks','ConvertFrom-T4DeleteIdentity','ConvertFrom-T4DeletePass2',
    'Get-T4MemoryCommands','Get-T4DeleteIdentityCommands','Get-T4DeleteFileCommands',
    'Write-T4DeleteEvidence','Get-T4DeleteSopCommands','Get-T4DeletePass1Commands','Get-T4DeletePass2Commands','Invoke-T4DeleteKdSession','Save-T4DeleteSnapshot')
foreach ($name in $names) {
    $functions=@($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    },$false))
    if ($functions.Count -ne 1) { throw ('Actual helper unavailable: ' + $name) }
    Invoke-Expression $functions[0].Extent.Text
}
$script:checks=0
function Assert-T4Delete([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }; $script:checks++
}
# The AST-loaded C# declaration must compile on Windows PowerShell 5.1 (C# 5), without invoking native calls.
Initialize-T4DeleteIdentity
Assert-T4Delete ($null -ne ('T4DeleteIdentity' -as [type])) 'Identity declaration did not compile.'
$flags=[Reflection.BindingFlags]'NonPublic,Static'
Assert-T4Delete ([T4DeleteIdentity].GetMethod('FindFirstStreamW',$flags).ReturnType -eq [IntPtr]) 'Stream enumeration signature.'
Assert-T4Delete ([T4DeleteIdentity].GetMethod('GetFileInformationByHandleEx',$flags).GetParameters()[0].ParameterType -eq [Microsoft.Win32.SafeHandles.SafeFileHandle]) 'Identity safe-handle signature.'

$pass1=@'
Windows 10 Kernel Version 19041 MP (4 procs) Free x64
fffff800`11220000 fffff800`11900000 SafeUpload (private pdb symbols)
T4_LAYOUT 10 60 68
T4_LOGICAL_BEGIN
   +0x014 TotalAllocates   : 0x300
   +0x01c TotalFrees       : 0x200
T4_LOGICAL 300 200 120 10
T4_LOGICAL_END
T4_ANCHOR_COUNT_BEGIN
fffff800`11330000  00000000
T4_ANCHOR_COUNT_END
T4_ANCHOR_WALK_END fffff80011330010 fffff80011330010
T4_POOL_BEGIN
Scanning large pool allocation table for Tag: SUfl
Searching NonPaged pool (ffff800011110000 : ffff800022220000) for Tag: SUfl
ffff8000`11110000 size: e0 previous size: 20 (Allocated) SUfl
ffff8000`11111000 size: e0 previous size: e0 (Free) SUfl
*ffff800011110000 size: e0 previous size: 20 (Allocated) *SUfl
ffff800011112000 size: 30 previous size: 10 (Allocated) SwUr
T4_POOL_END
T4_MEMORY_END
'@
$before=ConvertFrom-T4DeletePass1 $pass1
Assert-T4Delete ($before.Blocks.Count -eq 1 -and $before.Blocks[0].Size -eq 224) 'Allocated pool census, deduplication or hexadecimal size.'
Assert-T4Delete ($before.PoolComplete -and $before.Anchors -eq 0 -and $before.AnchorWalkComplete) 'Complete empty anchor census.'
Assert-T4Delete ($before.Layout.ContextNode -eq 96 -and $before.Layout.UserData -eq 104) 'Resolve headers; never treat 224 as payload size.'
Assert-T4Delete ($before.Logical.Outstanding -eq 256 -and $before.Logical.CachedEstimate -eq 16) 'Logical allocator storage must remain separate from attached contexts.'
$afterText=$pass1.Replace('ffff8000`11111000 size: e0 previous size: e0 (Free)', 'ffff8000`11111000 size: e0 previous size: e0 (Allocated)')
$after=ConvertFrom-T4DeletePass1 $afterText
$new=@(Get-T4DeleteNewBlocks $after $before)
Assert-T4Delete ($new.Count -eq 1 -and $new[0].Address -eq 'ffff800011111000') 'New means absent from the fresh baseline.'
Assert-T4Delete (@(Get-T4DeleteNewBlocks $before $before).Count -eq 0) 'Baseline must have zero new addresses.'
$bad=ConvertFrom-T4DeletePass1 ($pass1.Replace('T4_POOL_END',''))
Assert-T4Delete (-not $bad.PoolComplete -and @(Get-T4DeleteNewBlocks $after $bad).Count -eq 0) 'Truncated baseline cannot produce a new-block count.'
$bad=ConvertFrom-T4DeletePass1 ($pass1.Replace('size: e0 previous size: 20 (Allocated)', 'unknown-size (Allocated)'))
Assert-T4Delete (-not $bad.PoolComplete -and $bad.UnparsedPoolRows.Count -gt 0) 'Unrecognized allocated rows must not silently disappear.'
$bad=ConvertFrom-T4DeletePass1 ($pass1.Replace('T4_LAYOUT 10 60 68','T4_LAYOUT 10 60 e0'))
Assert-T4Delete ($null -eq $bad.Layout) 'Inconsistent symbol sizes must not invent a payload.'
$bad=ConvertFrom-T4DeletePass1 'Unable to load image SafeUpload.sys; symbols missing'
Assert-T4Delete ($null -eq $bad.Anchors -and $null -eq $bad.Logical -and -not $bad.PoolComplete -and $bad.Errors.Count -ge 3) 'Unavailable evidence must not be zero.'
Assert-T4Delete (@(Get-T4KdErrors 'Could not read field "UseCount" of FltMgr!_CONTEXT_NODE').Count -eq 1) 'Extension read failure retained.'

$corpus=@([pscustomobject]@{ Path='C:\synthetic\001.txt'; VolumeSerial='4ad66344d6632f7f'; FileId='0102030405060708090a0b0c0d0e0f10' })
$pass2=@'
T4_BLOCK_BEGIN ffff800011111000
*ffff8000`11111000 size: e0 previous size: e0 (Allocated) *SUfl
T4_CTX_BEGIN ffff800011111000
Could not read field "RegInfo" of FltMgr!_CONTEXT_NODE
T4_CTX_END
T4_CTX_BEGIN ffff800011111010
CONTEXT_NODE: ffff800011111010 [0008] StreamContext NonPagedPool
   ALLOCATE_CONTEXT_NODE: ffff800033330010 "SafeUpload" [01] LookasideList (size=200)
   AttachedObject           : ffff800044440010
   UseCount                 : 1
   TREE_NODE: ffff800011111028 (k1=ffff800066660010, k2=0000000000000000) [00010000] InTree
   UserData                 : ffff800011111070
   UserDataSize             : 104
T4_SAFEUPLOAD_STREAM
   +0x038 WriterObjects    : _LIST_ENTRY [ 0xffff8000`111110a8 - 0xffff8000`111110a8 ]
   +0x050 WriterRegistryEntry : 0xffff8000`55550000 Void
T4_PAYLOAD ffff800011111070 68
T4_WRITERS ffff8000111110a8 ffff8000111110a8 ffff8000111110a8
T4_ID 4ad66344d6632f7f 0807060504030201 100f0e0d0c0b0a09
T4_ENTRY ffff800066660010 0 0 0 1 0
T4_CTX_END
T4_CTX_BEGIN ffff800011111070
Could not read field "AllocationType" of FltMgr!_ALLOCATE_CONTEXT_HEADER
T4_CTX_END
T4_BLOCK_END
T4_MEMORY_END
'@
$parsed=ConvertFrom-T4DeletePass2 $pass2 $corpus ''
Assert-T4Delete ($parsed.Attempts.Count -eq 3 -and $parsed.Contexts.Count -eq 1) 'Correct node must be distinguished from block start and payload probes.'
$c=$parsed.Contexts[0]
Assert-T4Delete ($c.CorpusPath -eq $corpus[0].Path -and $c.IdentityKnown -and $c.Identity.FileId.Length -eq 32) 'Full little-endian FILE_ID_128 and volume identity match.'
Assert-T4Delete ($c.HasWriterNodes -eq $false -and $c.ReferencedBeyondAttachment -eq $false) 'Empty writer list and one attachment reference.'
Assert-T4Delete ($c.Classification -match 'owner unresolved') 'No driver reference is not proof of NTFS ownership.'
$held=$pass2.Replace('UseCount                 : 1','UseCount                 : 2').Replace('T4_WRITERS ffff8000111110a8 ffff8000111110a8 ffff8000111110a8','T4_WRITERS ffff8000111110a8 ffff800077770010 ffff800077770010')
$c=(ConvertFrom-T4DeletePass2 $held $corpus '').Contexts[0]
Assert-T4Delete ($c.HasWriterNodes -and $c.ReferencedBeyondAttachment -and $c.Classification -match 'owner unresolved') 'Raw writer pointers/extra refs cannot establish owning driver lifetime.'
foreach ($mutated in @($pass2.Replace('T4_SAFEUPLOAD_STREAM',''), $pass2.Replace('UserDataSize             : 104','UserDataSize             : 224'),
    $pass2.Replace('(Allocated) *SUfl','(Free) *SUfl'), $pass2.Replace('T4_BLOCK_END',''),
    $pass2.Replace('UseCount                 : 1','UseCount                 : 0'))) {
    Assert-T4Delete ((ConvertFrom-T4DeletePass2 $mutated $corpus '').Contexts.Count -eq 0) 'Reject reused/free, truncated or unvalidated contexts.'
}
$c=(ConvertFrom-T4DeletePass2 ($pass2.Replace('100f0e0d0c0b0a09','110f0e0d0c0b0a09')) $corpus '').Contexts[0]
Assert-T4Delete (-not $c.CorpusPath -and $c.Classification -match 'mixed/global') 'High 64 ID bits must participate in identity.'
$c=(ConvertFrom-T4DeletePass2 ($pass2.Replace('4ad66344d6632f7f','4ad66344d6632f70')) $corpus '').Contexts[0]
Assert-T4Delete (-not $c.CorpusPath) 'Volume serial must participate in identity.'
$c=(ConvertFrom-T4DeletePass2 ($pass2.Replace('T4_ENTRY ffff800066660010 0 0 0 1 0','T4_ENTRY ffff800066660010 0 0 0 0 0')) $corpus '').Contexts[0]
Assert-T4Delete (-not $c.IdentityKnown -and -not $c.CorpusPath) 'Unknown stream identity must not be corpus-matched.'
$anchor=@'
T4_ANCHOR_BEGIN
T4_ANCHOR_OWNER ffffffff80000100 ffff800088880010
T4_ID 4ad66344d6632f7f 0807060504030201 100f0e0d0c0b0a09
T4_ENTRY ffff800066660010 0 0 0 1 0
T4_ANCHOR_END
'@
$c=(ConvertFrom-T4DeletePass2 $pass2 $corpus $anchor).Contexts[0]
Assert-T4Delete ($c.MatchingAnchors -eq 1 -and $c.Classification -match 'owning anchor observed') 'Corpus owning anchor should be attributed with a non-atomic qualifier.'

$c=(ConvertFrom-T4DeletePass2 $pass2 $corpus ($anchor.Replace('ffff800066660010','ffff800066660020'))).Contexts[0]
Assert-T4Delete ($c.MatchingAnchors -eq 0) 'Anchor/context instance must match as well as full identity.'
$c=(ConvertFrom-T4DeletePass2 $pass2 $corpus ($anchor.Replace('ffffffff80000100','0000000000000000'))).Contexts[0]
Assert-T4Delete ($c.MatchingAnchors -eq 0) 'A null anchor handle is not an observed owning pair.'

$one=Get-T4DeletePass1Commands
$two=Get-T4DeletePass2Commands (@($new[0])*70) $before.Layout
foreach ($command in '!poolfind SUfl 0','dd SafeUpload!StageAnchorCount L1','!fltkd.filter @$t0 0x1f 1','!fltkd.help') {
    Assert-T4Delete ($one.Contains($command)) ('Missing census command: '+$command)
}
Assert-T4Delete ([regex]::Matches($two,'(?m)^\.echo T4_BLOCK_BEGIN ').Count -eq 64) 'Second pass must be bounded to 64 blocks.'
Assert-T4Delete ($two.Contains('!pool 0xffff800011111000 2') -and $two.Contains('!fltkd.ctx 0xffff800011111010 1') -and $two.Contains('!fltkd.ctx 0xffff800011111070 1')) 'Symbol-sized header/payload probes.'
Assert-T4Delete (-not (($one+$two) -match '(?im)^\s*(eb|ew|ed|eq|ea|eu|bp|bu|ba|\.call|\.reboot)\b')) 'No target writes or breakpoints.'

# Exercise the real failure writer with a missing local debugger. This must return a receipt, never attach.
$script:T4MemoryRoot=Join-Path ([IO.Path]::GetTempPath()) ('T4DeleteSelfCheck-'+[guid]::NewGuid().ToString('N'))
try {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [void](New-Item -ItemType Directory -Path $script:T4MemoryRoot)
        $member=Join-Path $script:T4MemoryRoot 'native.txt'
        $native=[T4DeleteIdentity]::Create($member)
        Assert-T4Delete ($native[0].Length -eq 16 -and $native[1].Length -eq 32) 'Native full FILE_ID_INFO receipt.'
        $exclusive=[IO.File]::Open($member,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $exclusive.Dispose()
        Assert-T4Delete ($true) 'Corpus helper leaves no file/stream-enumeration handle open.'
        $refused=$false; try { $null=[T4DeleteIdentity]::Create($member) } catch { $refused=$true }
        Assert-T4Delete $refused 'CreateNew must refuse an existing corpus name.'
    }
    $snapshot=Save-T4DeleteSnapshot 'del-baseline' $corpus $null
    Assert-T4Delete ($snapshot.Errors.Count -gt 0 -and $null -eq $snapshot.Counts.NewBlocks) 'KD startup failure must retain unknown counts.'
    Assert-T4Delete (Test-Path -LiteralPath (Join-Path $script:T4MemoryRoot 'output\del-baseline.summary.json')) 'Failure summary was not written.'
    Assert-T4Delete (Test-Path -LiteralPath (Join-Path $script:T4MemoryRoot 'output\del-baseline-pass2.result.json')) 'Both bounded pass receipts must survive missing KD.'
    $receipt=Join-Path $script:T4MemoryRoot 'output\del-baseline-pass1.result.json'
    $first=[IO.File]::ReadAllText($receipt)
    $again=Invoke-T4DeleteKdSession 'del-baseline-pass1' 'q'
    Assert-T4Delete ($again.Errors.Count -gt 0 -and [IO.File]::ReadAllText($receipt) -ceq $first) 'An attempted retry must not overwrite its failed receipt.'
} finally {
    if (Test-Path -LiteralPath $script:T4MemoryRoot) { Remove-Item -LiteralPath $script:T4MemoryRoot -Recurse -Force }
}
'T4DeleteAttributionSelfCheck=PASS;Controls='+$script:checks+';SyntheticKd=True;Qualification=False'
