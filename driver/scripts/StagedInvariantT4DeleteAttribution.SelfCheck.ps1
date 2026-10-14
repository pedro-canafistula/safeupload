#requires -Version 5.1
<# No kernel or VM needed. Extract the actual functions, never dot-source the coordinator.
   Samples marked SYNTHETIC use invented addresses/IDs/counts. Retained m2t4delattr1/2 fragments
   are identified separately with source line ranges. Pool rows follow:
   https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-poolfind
   https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-pool
   dd/dt field formatting follows:
   https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/dt--display-type-
   https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/d--da--db--dc--dd--dd--df--dp--dq--du--dw--dw--dyb--dyd--display-memor
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
    'ConvertFrom-T4KdTelemetry','ConvertFrom-T4UnloadVeto','Save-T4UnloadVeto','Get-T4DeleteSessionCommands',
    'Get-T4HandbackIdentities','ConvertFrom-T4PoolRow','ConvertFrom-T4DeletePass1','Get-T4DeleteNewBlocks','ConvertFrom-T4DeleteIdentity','ConvertFrom-T4DeletePass2',
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
Assert-T4Delete ([T4DeleteIdentity].GetMethod('CreateFileW',$flags).ReturnType -eq [Microsoft.Win32.SafeHandles.SafeFileHandle]) 'Metadata-only open uses an owning safe handle.'
Assert-T4Delete ([T4DeleteIdentity].GetMethod('FindFirstStreamW',$flags).ReturnType -eq [IntPtr]) 'Stream enumeration signature.'
Assert-T4Delete ([T4DeleteIdentity].GetMethod('GetFileInformationByHandleEx',$flags).GetParameters()[0].ParameterType -eq [Microsoft.Win32.SafeHandles.SafeFileHandle]) 'Identity safe-handle signature.'

# ACTUAL retained output, not synthetic. Source: driver/evidence/2026-10-13/
# m2t4delattr1-memory/output/del-baseline-pass1.stdout.txt in the staging checkout.
# Only CRLF and trailing whitespace normalized. The separated excerpts are partial observations;
# they intentionally have no invented KD completion markers.
# Layout: lines 1383-1400.
$realLayout=@'
   +0x000 TxCtxExtension   : Ptr64 _TX_CONTEXT_EXTENSION
   +0x000 SectionCtxExtension : Ptr64 _SECTION_CONTEXT_EXTENSION
   +0x000 Data             : Ptr64 Void
   +0x008 RegInfo          : Ptr64 _ALLOCATE_CONTEXT_HEADER
   +0x010 AttachedObject   : <anonymous-tag>
   +0x018 TreeLink         : _TREE_NODE
   +0x018 FltWork          : _FLTP_WORKITEM
   +0x050 UseCount         : Int4B
   +0x000 PreviousSize     : Pos 0, 8 Bits
   +0x000 PoolIndex        : Pos 8, 8 Bits
   +0x002 BlockSize        : Pos 0, 8 Bits
   +0x002 PoolType         : Pos 8, 8 Bits
   +0x000 Ulong1           : Uint4B
   +0x004 PoolTag          : Uint4B
   +0x008 ProcessBilled    : Ptr64 _EPROCESS
   +0x008 AllocatorBackTraceIndex : Uint2B
   +0x00a PoolTagHash      : Uint2B
T4_LAYOUT 10 60 68
'@
# !poolused: lines 680-697; !verifier summary/list: 739-778 (list intentionally partial).
$realTelemetry=@'
unable to get nt!PspSessionIdBitmap
..
 Sorting by NonPaged Pool Consumed

               NonPaged                  Paged
 Tag     Allocs         Used     Allocs         Used

 SUfl       718       179928          0            0	UNKNOWN pooltag 'SUfl', please update pooltag.txt

TOTAL       718       179928          0            0
..
 Sorting by NonPaged Pool Consumed

               NonPaged                  Paged
 Tag     Allocs         Used     Allocs         Used

 SwUr       246      6358592  18446744073709551614        -1080	UNKNOWN pooltag 'SwUr', please update pooltag.txt

  Pool Allocations Attempted             0x7b16aa
  Pool Allocations Succeeded             0x7b16c7
  Pool Allocations Succeeded SpecialPool 0x7b16df
  Pool Allocations With NO TAG           0x0
  Pool Allocations Failed                0x0

  Current paged pool allocations         0x0 for 00000000 bytes
  Peak paged pool allocations            0x17 for 000BB344 bytes
  Current nonpaged pool allocations      0x1eb for 00619198 bytes
  Peak nonpaged pool allocations         0x2f4 for 006AE3D8 bytes

Driver Verification List
------------------------

nt!_VF_TARGET_DRIVER 0xffffd30a96e92320: SafeUpload.sys (Loaded)

    Pool Allocation Statistics: ( NonPagedPool / PagedPool )

      Current Pool Allocations: ( 0x000001eb / 0x00000000 )
      Current Pool Bytes:       ( 0x00619198 / 0x00000000 )
      Peak Pool Allocations:    ( 0x000002f4 / 0x00000017 )
      Peak Pool Bytes:          ( 0x006ae3d8 / 0x000bb344 )
      Contiguous Memory Bytes:       0x00000000
      Peak Contiguous Memory Bytes:  0x00000000

    Pool Allocations:

      Address             Length      Tag   Caller Address
      ------------------  ----------  ----  ------------------
      0xffffd30aa028afd0  0x00000030  SUwH  0xfffff8047a65c98d  SafeUpload!SafeUploadStageWritersReserveCreate+0x6bd
      0xffffd30aa03f26a0  0x00000960  SwUr  0xfffff80479f90fb5  SafeUpload!StageRegistryAllocateNamedShell+0x25
      0xffffd30aa038afd0  0x00000030  SUwH  0xfffff8047a65c98d  SafeUpload!SafeUploadStageWritersReserveCreate+0x6bd
      0xffffd30aa0c406a0  0x00000960  SwUr  0xfffff80479f90fb5  SafeUpload!StageRegistryAllocateNamedShell+0x25
      0xffffd30a9e7b46a0  0x00000960  SwUr  0xfffff80479f90fb5  SafeUpload!StageRegistryAllocateNamedShell+0x25
      0xffffd30aa025afd0  0x00000030  SUwH  0xfffff8047a65c98d  SafeUpload!SafeUploadStageWritersReserveCreate+0x6bd
      0xffffd30a9f70e6a0  0x00000960  SwUr  0xfffff80479f90fb5  SafeUpload!StageRegistryAllocateNamedShell+0x25
      0xffffd30a9f7326a0  0x00000960  SwUr  0xfffff80479f90fb5  SafeUpload!StageRegistryAllocateNamedShell+0x25
      0xffffd30aa0c4cfd0  0x00000030  SUwH  0xfffff8047a65c98d  SafeUpload!SafeUploadStageWritersReserveCreate+0x6bd
      0xffffd30a9906afd0  0x00000030  SUwH  0xfffff8047a65c98d  SafeUpload!SafeUploadStageWritersReserveCreate+0x6bd
      0xffffd30aa042cfe0  0x00000020  SUfl  0xfffff80479f747dc  SafeUpload!SafeUploadPolicyAdmissionAcquire+0x2c
'@
# !fltkd.filter: lines 1402-1445 (registration) and 1553-1564 (usage/reference list).
$realFilter=@'
FLT_FILTER: ffffd30a98bcc010 "SafeUpload" "[ERROR READING NAME]"
   FLT_OBJECT: ffffd30a98bcc010  [02000000] Filter
      RundownRef               : 0x000000000000050e (647)
      PointerCount             : 0x00000002
      PrimaryLink              : [ffffd30a9e003a30-ffffd30a9dd92020]
   Frame                    : ffffd30a98bbf010 "Frame 0"
   Flags                    : [00000016] FilteringInitiated NameProvider BackedByPagefile
   DriverObject             : ffffd30a98bcadd0
   FilterLink               : [ffffd30a9e003a30-ffffd30a9dd92020]
   PreVolumeMount           : fffff80479f7ab60  SafeUpload!SafeUploadStageDispatch
   PostVolumeMount          : fffff80479f7b520  SafeUpload!SafeUploadStagePostOperation
   FilterUnload             : fffff8047a64f3e0  SafeUpload!SafeUploadUnload
   InstanceSetup            : fffff804781affb0  FLTMGR!FltvInstanceSetup
   InstanceQueryTeardown    : fffff804781afea0  FLTMGR!FltvInstanceQueryTeardown
   InstanceTeardownStart    : fffff804781b01d0  FLTMGR!FltvInstanceTeardownStart
   InstanceTeardownComplete : fffff804781b00d0  FLTMGR!FltvInstanceTeardownComplete
   ActiveOpens              : (ffffd30a98bcc1c8)  mCount=0
   Communication Port List  : (ffffd30a98bcc218)  mCount=1
   Client Port List         : (ffffd30a98bcc268)  mCount=1
   Operations               : ffffd30a98bcc2c0
   OldDriverUnload          : 0000000000000000  (null)
   SupportedContexts        : (ffffd30a98bcc140)
      VolumeContexts           : (ffffd30a98bcc140)
      InstanceContexts         : (ffffd30a98bcc148)
         ALLOCATE_CONTEXT_NODE: ffffd30a98bcb980  [01] LookasideList
            Filter                   : ffffd30a98bcc010 "SafeUpload"
            ContextCleanupCallback   : fffff80479f711b0  SafeUpload!SafeUploadInstanceContextCleanup
            Next                     : 0000000000000000
            ContextType              : [0002] InstanceContext
            Flags                    : [01] LookAsideListInited
               Size                     : 752
               PoolTag                  : SUfl
         ---
      FileContexts             : (ffffd30a98bcc150)
      StreamContexts           : (ffffd30a98bcc158)
         ALLOCATE_CONTEXT_NODE: ffffd30a98bcbac0  [01] LookasideList
            Filter                   : ffffd30a98bcc010 "SafeUpload"
            ContextCleanupCallback   : fffff80479f71120  SafeUpload!SafeUploadStreamContextCleanup
            Next                     : 0000000000000000
            ContextType              : [0008] StreamContext
            Flags                    : [01] LookAsideListInited
               Size                     : 104
               PoolTag                  : SUfl
         ---
   Object usage/reference information:
      References to FLT_CONTEXT                : 0
      Allocations of FLT_CALLBACK_DATA         : 0
      Allocations of FLT_DEFERRED_IO_WORKITEM  : 0
      Allocations of FLT_GENERIC_WORKITEM      : 0
      References to FLT_FILE_NAME_INFORMATION  : 0
      Open files                               : 0
      References to FLT_OBJECT                 : 492
   List of objects used/referenced::
      FLT_VERIFIER_OBJECT: ffffd30a98ea18a0
         Object: ffffd30a9931d010  Type: (null)  RefCount: 00000247
   VerifierExtension        : ffffd30a98bcc8a0
'@
$real=ConvertFrom-T4DeletePass1 ($realLayout+"`n"+$realTelemetry+"`n"+$realFilter)
Assert-T4Delete ($real.Layout.PoolHeader -eq 16 -and $real.Layout.ContextNode -eq 96 -and $real.Layout.UserData -eq 104) 'Actual KD symbol sizes.'
Assert-T4Delete (-not $real.PoolComplete -and $null -eq $real.Logical -and $null -eq $real.Anchors) 'Actual partial output must not invent the sections that never ran.'
$t=$real.Telemetry
Assert-T4Delete ($t.PoolUsed.Count -eq 2 -and $t.PoolUsed[0].NonPagedAllocs -eq 718 -and $t.PoolUsed[0].NonPagedBytes -eq 179928) 'Actual decimal SUfl poolused summary.'
Assert-T4Delete ($t.PoolUsed[1].PagedAllocs -eq [decimal]'18446744073709551614' -and $t.PoolUsed[1].PagedBytes -eq -1080) 'Retain the observed SwUr underflow, without rounding or clamping.'
Assert-T4Delete ($t.VerifierDriverStats.NonPagedAllocs -eq 491 -and $t.VerifierAllocations.Count -eq 11) 'Actual driver-scoped verifier statistics and partial allocation list.'
$v=@($t.VerifierAllocations | Where-Object { $_.Tag -ceq 'SUfl' })
Assert-T4Delete ($v.Count -eq 1 -and $v[0].Size -eq 32 -and $v[0].Symbol -eq 'SafeUpload!SafeUploadPolicyAdmissionAcquire+0x2c') 'Verifier SUfl is not necessarily a stream context.'
$f=$t.Filters[0]
Assert-T4Delete ($f.Address -eq 'ffffd30a98bcc010' -and $f.ContextRegistrations[1].ContextType -eq 8 -and $f.ContextRegistrations[1].Size -eq 104) 'Actual SafeUpload stream registration.'
Assert-T4Delete ($f.ObjectUsage['References to FLT_CONTEXT'] -eq 0 -and $f.ObjectUsage['References to FLT_OBJECT'] -eq 492 -and $f.VerifierObjects.Count -eq 1) 'Actual FltMgr verifier usage and reference list.'
Assert-T4Delete ($f.VerifierObjects[0].RefCountHex -eq '00000247' -and -not $t.VerifierSectionComplete -and -not $t.FilterSectionComplete) 'Partial lists are observations, not complete censuses.'
Assert-T4Delete (@(Get-T4KdErrors $realTelemetry).Count -eq 1) 'Real verifier Failed counter is data; real PspSessionIdBitmap error is retained.'
$bad=ConvertFrom-T4KdTelemetry ($realTelemetry.Replace('SUfl       718','SUfl       bad'))
Assert-T4Delete ($bad.UnparsedRows.Count -eq 1 -and $bad.PoolUsed.Count -eq 1) 'Malformed poolused rows stay unknown.'
Assert-T4Delete ($null -eq (ConvertFrom-T4KdTelemetry ($realTelemetry.Replace('SafeUpload.sys (Loaded)','Other.sys (Loaded)'))).VerifierDriverStats) 'Verifier lists must be scoped to SafeUpload.'
# Actual evaluator-error prefix from line 1697 (the rest is the aborted command program).
Assert-T4Delete (@(Get-T4KdErrors "Numeric expression missing from '& @@c++(@`$t11->AllocationType) == 1)'").Count -eq 1) 'Record the actual evaluator error.'

# ACTUAL row 2: m2t4delattr2-memory/output/del-baseline-poolfind.stdout.txt, lines 54-103.
$realPoolUsage2=@'
T4_POOL_BEGIN
Usage: !poolfind [-tag] <tag> [options] [-x "cmd"]

  tag:       A string or a hex value specifying the tag to search for,
             may include * and ? wildcards. If the tag contains spaces,
             use -tag switch and put the tag in quotes.

  cmd:       Command to execute for each found allocation. The @$extret register
             contains the address of the allocation.

Search options:

  -nonpaged  Search non-paged pool.
  -paged     Search paged pool.

  -global    Search global (non-session) pool.
  -session   Search session pool.

  -regular   Search regular (non-special) pool.
  -special   Search special pool.

  -small     Include small (sub-page) allocations.
  -large     Include large (page-aligned) allocations.

  -busy      Include busy allocations.
  -free      Include free allocations.

             The options above are additive. For example, specifying -global
             and -session will search both global and session pools.
             If no options are specified, a global non-paged search is
             performed. Both small and large allocations are included, as well
             regular and special pool. Free allocations are not included.

  -process   Interpret tag value as a process pointer and search for
             quota allocations charged to that process.

Notes:

  Allocation sizes reported by this command do not include the size of the
  pool header (if one is present). Similarly, allocation addresses represent
  the start of the user accessible portion of the allocation.

Examples:

  !poolfind Mm*               - Find all Mm allocations in nonpaged pool.
  !poolfind MmSt -paged       - Find MmSt allocations in paged pool.
  !poolfind Gla1 -session     - Find Gla1 allocations in session pool.
  !poolfind -tag "AB C"       - Find pool tag which contains a space.
  !poolfind -x "dt nt!_MDL @$extret" Mdl  - Find and print MDL allocations.
T4_POOL_END
'@

# ACTUAL row 2: m2t4delattr2-memory/output/del-after-logical.stdout.txt, lines 54-78.
$realLogical2=@'
T4_LOGICAL_BEGIN
   +0x000 ListHead         : _SLIST_HEADER
   +0x000 SingleListHead   : _SINGLE_LIST_ENTRY
   +0x010 Depth            : 4
   +0x012 MaximumDepth     : 0x100
   +0x014 TotalAllocates   : 0x19af
   +0x018 AllocateMisses   : 0xeee
   +0x018 AllocateHits     : 0xeee
   +0x01c TotalFrees       : 0x1794
   +0x020 FreeMisses       : 0xcd1
   +0x020 FreeHits         : 0xcd1
   +0x024 Type             : 200 ( NonPagedPoolNx )
   +0x028 Tag              : 0x6c665553
   +0x02c Size             : 0xc8
   +0x030 AllocateEx       : 0xfffff805`4a5b8010     void*  nt!ExAllocatePoolWithTag+0
   +0x030 Allocate         : 0xfffff805`4a5b8010     void*  nt!ExAllocatePoolWithTag+0
   +0x038 FreeEx           : 0xfffff805`4a5b80b0     void  nt!ExFreePool+0
   +0x038 Free             : 0xfffff805`4a5b80b0     void  nt!ExFreePool+0
   +0x040 ListEntry        : _LIST_ENTRY [ 0xffffaf0f`559d4310 - 0xffffaf0f`559d4090 ]
   +0x050 LastTotalAllocates : 0x19a9
   +0x054 LastAllocateMisses : 0xeea
   +0x054 LastAllocateHits : 0xeea
   +0x058 Future           : [2] 0
T4_LOGICAL 19af 1794 eee cd1
T4_LOGICAL_END
'@

# ACTUAL row 2: m2t4delattr2-memory/output/del-after-anchors.stdout.txt, lines 54-58.
$realAnchors2=@'
T4_ANCHOR_COUNT_BEGIN
fffff805`4bbad504  00000000
T4_ANCHOR_COUNT_END
Cannot find specified field members.
T4_ANCHOR_WALK_END fffff8054bbad510 fffff8054bbad510
'@
$row2=ConvertFrom-T4DeletePass1 ($realLayout+"`n"+$realLogical2+"`n"+$realAnchors2+"`n"+$realPoolUsage2)
Assert-T4Delete (-not $row2.PoolComplete -and $row2.Blocks.Count -eq 0 -and ($row2.Errors -join ';') -match 'Usage: !poolfind') 'Row 2 usage must be an error, never a successful zero census.'
Assert-T4Delete ($row2.Anchors -eq 0 -and $row2.AnchorWalkComplete -and $row2.Logical.Outstanding -eq 539 -and $row2.Logical.PoolStorage -eq 541) 'Actual row 2 independent counts survive the pool failure.'

# SYNTHETIC modern rows: NO successful !poolfind rows exist in row 2. These match the
# formatter strings in the delivered Microsoft 10.0.28000 x64/winxp/kdexts.dll; see parser SHA256.
# Its actual help above defines the user-allocation address/size contract. Legacy rows below
# separately cover Microsoft Learn's documented pool-header format.
$modernPool=@'
T4_POOL_BEGIN
Searching Nonpaged pool (ffff800011110000 : ffff800022220000) for tag 0x6c665553 (SUfl)
ffff800011110010 : tag SUfl, size      0xc8, Nonpaged pool
ffff800011111010 : (Allocated) tag SUfl, size      0xc8, Nonpaged special pool
ffff800011112010 : (Free )     tag SUfl, size      0xc8, Nonpaged pool
Scanning large pool allocation table for tag 0x6c665553 (SUfl) (ffff800088880000 : ffff800088889000)
T4_POOL_END
'@
$modern=ConvertFrom-T4DeletePass1 $modernPool
Assert-T4Delete ($modern.PoolComplete -and $modern.Blocks.Count -eq 2 -and $modern.Blocks[0].Size -eq 200 -and $modern.Blocks[0].AddressKind -eq 'Allocation') 'Modern rows exclude pool headers from both address and size.'
Assert-T4Delete ($modern.Blocks[1].Special) 'Special pool must participate in the default nonpaged census.'
Assert-T4Delete (-not (ConvertFrom-T4DeletePass1 ($modernPool.Replace('0xc8','garbled'))).PoolComplete) 'Malformed modern rows invalidate the census.'
Assert-T4Delete (-not (ConvertFrom-T4DeletePass1 ($modernPool.Replace('Nonpaged pool','Paged pool'))).PoolComplete) 'Unexpected paged rows are not a nonpaged census.'
Assert-T4Delete (-not (ConvertFrom-T4DeletePass1 ($modernPool.Replace('tag SUfl','tag sufl'))).PoolComplete) 'Pool tags are case sensitive.'
$emptyModern=ConvertFrom-T4DeletePass1 ([regex]::Replace($modernPool,'(?m)^ffff[^\r\n]*\r?\n',''))
Assert-T4Delete ($emptyModern.PoolComplete -and $emptyModern.Blocks.Count -eq 0) 'Completed modern empty scans differ from usage/errors.'
Assert-T4Delete (-not (ConvertFrom-T4DeletePass1 ($modernPool.Replace('T4_POOL_END',"Unable to read heap`nT4_POOL_END"))).PoolComplete) 'Read failures must invalidate a partly enumerated scan.'

# SYNTHETIC parser controls below.
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

# Modern !poolfind address, then legacy !pool output at allocation-0x10. The node is
# the allocation itself (200 bytes = 96-byte CONTEXT_NODE + 104-byte SafeUpload payload).
$modernPass2=$pass2.Replace('T4_BLOCK_BEGIN ffff800011111000',"T4_BLOCK_BEGIN ffff800011111010`nT4_BLOCK_INFO Allocation c8")
$c=(ConvertFrom-T4DeletePass2 $modernPass2 $corpus '').Contexts
Assert-T4Delete ($c.Count -eq 1 -and $c[0].Node -eq 'ffff800011111010' -and $c[0].CorpusPath) 'Modern allocation address must not gain a second pool header.'
$modernPass2=$modernPass2.Replace('*ffff8000`11111000 size: e0 previous size: e0 (Allocated) *SUfl','ffff800011111010 : tag SUfl, size      0xc8, Nonpaged pool')
Assert-T4Delete ((ConvertFrom-T4DeletePass2 $modernPass2 $corpus '').Contexts.Count -eq 1) 'Fresh modern allocation row is also supported.'
$specialPass2=$modernPass2.Replace('ffff800011111010 : tag SUfl, size      0xc8, Nonpaged pool','*ffff800011110000 size: c8 data: ffff800011111010 (Allocated) *SUfl')
Assert-T4Delete ((ConvertFrom-T4DeletePass2 $specialPass2 $corpus '').Contexts.Count -eq 1) 'Special-pool data address is not header+0x10.'
foreach ($mutated in @($modernPass2.Replace('size      0xc8','size      0x30'),$modernPass2.Replace('Allocation c8','PoolHeader c8'),$modernPass2.Replace('tag SUfl','(Free) tag SUfl'))) {
    Assert-T4Delete ((ConvertFrom-T4DeletePass2 $mutated $corpus '').Contexts.Count -eq 0) 'Modern wrong-size, wrong-base or freed allocations cannot certify a context.'
}
$ownerPass2=$modernPass2.Replace('T4_SAFEUPLOAD_STREAM',"T4_SAFEUPLOAD_STREAM`nT4_SOP ffff800012340010`nT4_SHARED_CACHE_MAP ffff800023450010`nT4_SCB ffff800034560010`nT4_CONTROL_AREA ffff800045670010`nT4_FILE_OBJECT ffff800056780010")
$c=(ConvertFrom-T4DeletePass2 $ownerPass2 $corpus '').Contexts[0]
Assert-T4Delete ($c.SectionObjectPointers.Count -eq 1 -and $c.SharedCacheMaps.Count -eq 1 -and $c.ScbCandidates.Count -eq 1 -and $c.ControlAreas.Count -eq 1 -and $c.FileObjects.Count -eq 1) 'Owner-walk pointers must survive parsing; they are candidates, not ownership proof.'
$modernCommands=Get-T4DeletePass2Commands $modern.Blocks $before.Layout
Assert-T4Delete ($modernCommands.Contains('!fltkd.ctx 0xffff800011111010 1') -and $modernCommands.Contains('!fltkd.ctx 0xffff800011111070 1') -and -not $modernCommands.Contains('!fltkd.ctx 0xffff800011111020')) 'Modern generation uses allocation and payload, not a double header.'
Assert-T4Delete ($modernCommands.Contains('SharedCacheMap)->FileObject') -and $modernCommands.Contains('T4_SCB') -and $modernCommands.Contains('ImageSectionObject')) 'Bounded read-only cache/SCB/control-area owner walks.'

$bodies=@{}
foreach ($block in 'layout','telemetry','logical','anchors','poolfind') {
    $bodies[$block]=(Get-T4DeletePass1Commands $block) -join "`r`n"
}
$one=@($bodies.Values) -join "`r`n"
$two=Get-T4DeletePass2Commands (@($new[0])*70) $before.Layout
foreach ($command in '!poolfind SUfl','dd SafeUpload!StageAnchorCount L1','!fltkd.filter @$t0 0x1f 1','!fltkd.help') {
    Assert-T4Delete ($one.Contains($command)) ('Missing census command: '+$command)
}
Assert-T4Delete ($bodies.poolfind -match '(?m)^!poolfind SUfl\r?$' -and $one -notmatch '!poolfind SUfl 0') 'Default nonpaged command accepts no positional pool type on 10.0.28000.'
Assert-T4Delete ([regex]::Matches($two,'(?m)^\.echo T4_BLOCK_BEGIN ').Count -eq 64) 'Second pass must be bounded to 64 blocks.'
Assert-T4Delete ($two.Contains('!pool 0xffff800011111000 2') -and $two.Contains('!fltkd.ctx 0xffff800011111010 1') -and $two.Contains('!fltkd.ctx 0xffff800011111070 1')) 'Symbol-sized header/payload probes.'
Assert-T4Delete (-not (($one+$two) -match '(?im)^\s*(eb|ew|ed|eq|ea|eu|bp|bu|ba|\.call|\.reboot)\b')) 'No target writes or breakpoints.'

# Audit every generated expression, including nested writer/anchor commands. This is a syntax
# contract, not a substitute for the real KD interpreter: no MASM-only 0n inside C++, and no
# C++ member/compound operators outside @@c++ or r?'s inherently C++ RHS.
function Remove-T4CppExpressions([string]$Commands) {
    $rest=[regex]::Replace($Commands,'"(?:\\.|[^"\\])*"','"format"')
    $rest=[regex]::Replace($rest,'r\? \$t\d+\s*=\s*[^;\r\n}]+','r_typed_assignment')
    while ($rest.Contains('@@c++(')) {
        $start=$rest.IndexOf('@@c++('); $end=$start+6; $depth=1
        while ($depth -gt 0 -and $end -lt $rest.Length) {
            if ($rest[$end] -eq '(') { $depth++ }
            if ($rest[$end] -eq ')') { $depth-- }
            $end++
        }
        if ($depth -ne 0) { throw 'Unbalanced C++ expression in generated KD.' }
        $expression=$rest.Substring($start,$end-$start)
        if ($expression -match '\b0n\d|@@c\+\+') {
            # Exactly the leading @@c++ is expected, never a nested evaluator workaround.
            if ($expression.Substring(6) -match '\b0n\d|@@c\+\+') { throw 'Mixed/nested evaluator in C++ condition.' }
        }
        $rest=$rest.Substring(0,$start)+'CPP_VALUE'+$rest.Substring($end)
    }
    $rest
}
$audit=Remove-T4CppExpressions ($one+"`n"+$two+"`n"+$modernCommands)
Assert-T4Delete (-not ($audit -match '&&|\|\||->|\bsizeof\s*\(|\bpoi\s*\(')) 'C++ operator escaped into MASM.'
Assert-T4Delete (-not ($audit -match '\.if\s*\((?!\s*CPP_VALUE\))|\.for\s*\(\s*;(?!\s*CPP_VALUE;)')) 'Whole .if/.for condition must be explicitly C++.'
Assert-T4Delete (-not ($audit -match '\br\s+(?!\$t\d+\s*=)')) 'Only debugger pseudo-registers may be assigned.'
Assert-T4Delete ($bodies.logical.Contains('@@c++(@$t11 != 0 && @$t11->ContextType == 8 && @$t11->AllocationType == 1)')) 'Regression: logical condition must use one evaluator.'
Assert-T4Delete ($bodies.anchors.Contains('@@c++(@$t1 != &SafeUpload!StageAnchorList && @$t1 != 0 && @$t2 < 64)')) 'Anchor address and decimal bound inside C++.'
$bodies['pass2']=$two
$markers=@()
foreach ($block in 'layout','telemetry','logical','anchors','poolfind','pass2') {
    $commands=Get-T4DeleteSessionCommands ('del-baseline-'+$block) $bodies[$block]
    $marker='T4_KD_DEL_BASELINE_'+$block.ToUpperInvariant()+'_END'
    Assert-T4Delete ($commands.EndsWith(".echo $marker`r`nq") -and $commands.StartsWith('.expr /s masm')) ('Isolated session completion/quit: '+$block)
    Assert-T4Delete ($commands.Contains(".catch {`r`n")) ('Missing read-error boundary: '+$block)
    $markers+=$marker
}
Assert-T4Delete (@($markers | Select-Object -Unique).Count -eq 6) 'Every session needs its own marker.'

# SYNTHETIC packed veto values, based on the getter and Protocol.h, not an actual veto observation.
$vetoText="T4_UNLOAD_VETO_BEGIN`nfffff804``79fa1000  00000004``c000009e`nT4_UNLOAD_VETO_END"
$veto=ConvertFrom-T4UnloadVeto $vetoText
Assert-T4Delete ($veto.ReasonName -eq 'STAGE_OBJECTS' -and $veto.NTSTATUS -eq '0xc000009e') 'Packed veto reason/status decoding.'
Assert-T4Delete ($null -eq (ConvertFrom-T4UnloadVeto ($vetoText.Replace('T4_UNLOAD_VETO_END','')))) 'Incomplete veto is unknown.'
Assert-T4Delete ((ConvertFrom-T4UnloadVeto ($vetoText.Replace('00000004`c000009e','00000000`00000000'))).ReasonName -eq 'NONE') 'Observed NONE differs from unknown.'
Assert-T4Delete ((ConvertFrom-T4UnloadVeto ($vetoText.Replace('00000004','000000ff'))).ReasonName -eq 'UNRECOGNIZED') 'Preserve unknown future veto reasons.'

# Exercise the real failure writer with a missing local debugger. This must return a receipt, never attach.
$script:T4MemoryRoot=Join-Path ([IO.Path]::GetTempPath()) ('T4DeleteSelfCheck-'+[guid]::NewGuid().ToString('N'))
try {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [void](New-Item -ItemType Directory -Path $script:T4MemoryRoot)
        $member=Join-Path $script:T4MemoryRoot 'native.txt'
        $native=[T4DeleteIdentity]::Create($member)
        Assert-T4Delete ($native[0].Length -eq 16 -and $native[1].Length -eq 32) 'Native full FILE_ID_INFO receipt.'
        $read=[T4DeleteIdentity]::Read($member)
        Assert-T4Delete (($read -join ':') -ceq ($native -join ':')) 'Metadata-only existing-file identity equals creation receipt.'
        Assert-T4Delete ([IO.File]::ReadAllText($member) -ceq "T4 ordinary delete attribution`r`n") 'Identity inventory must not modify file bytes.'
        $exclusive=[IO.File]::Open($member,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $exclusive.Dispose()
        Assert-T4Delete ($true) 'Corpus helper leaves no file/stream-enumeration handle open.'
        $refused=$false; try { $null=[T4DeleteIdentity]::Create($member) } catch { $refused=$true }
        Assert-T4Delete $refused 'CreateNew must refuse an existing corpus name.'
        $inventory=@(Get-T4HandbackIdentities $script:T4MemoryRoot)
        Assert-T4Delete ($inventory.Count -eq 1 -and $inventory[0].FileId -ceq $native[1] -and $inventory[0].HandlesClosed) 'Existing hand-back inventory retains native identity.'
        # Windows PowerShell 5.1 (.NET Framework) rejects 'file:stream' paths; use the provider's -Stream.
        Set-Content -LiteralPath $member -Stream 'extra' -Value 'synthetic named-stream control'
        $refused=$false; try { $null=[T4DeleteIdentity]::Read($member) } catch { $refused=$true }
        Assert-T4Delete $refused 'A hand-back with a named data stream must be refused.'
        $exclusive=[IO.File]::Open($member,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $exclusive.Dispose()
        Assert-T4Delete ($true) 'Failed existing-file inventory also closes all handles.'
    }
    $snapshot=Save-T4DeleteSnapshot 'del-baseline' $corpus $null
    Assert-T4Delete ($snapshot.Errors.Count -gt 0 -and $null -eq $snapshot.Counts.NewBlocks) 'KD startup failure must retain unknown counts.'
    Assert-T4Delete (Test-Path -LiteralPath (Join-Path $script:T4MemoryRoot 'output\del-baseline.summary.json')) 'Failure summary was not written.'
    Assert-T4Delete (Test-Path -LiteralPath (Join-Path $script:T4MemoryRoot 'output\del-baseline-pass2.result.json')) 'All bounded session receipts must survive missing KD.'
    Assert-T4Delete ($snapshot.Sessions.Count -eq 6) 'One startup failure must not skip another session.'
    foreach ($block in 'layout','telemetry','logical','anchors','poolfind','pass2') {
        Assert-T4Delete (Test-Path -LiteralPath (Join-Path $script:T4MemoryRoot ('output\del-baseline-'+$block+'.commands.txt'))) ('Missing independent script: '+$block)
    }
    $receipt=Join-Path $script:T4MemoryRoot 'output\del-baseline-logical.result.json'
    $first=[IO.File]::ReadAllText($receipt)
    $again=Invoke-T4DeleteKdSession 'del-baseline-logical' '.echo retry'
    Assert-T4Delete ($again.Errors.Count -gt 0 -and [IO.File]::ReadAllText($receipt) -ceq $first) 'An attempted retry must not overwrite its failed receipt.'
    $vetoFailure=Save-T4UnloadVeto 'unload-veto-after' $null
    Assert-T4Delete ($null -eq $vetoFailure.Veto -and $vetoFailure.Errors.Count -gt 0) 'Missing KD must not invent an unload veto.'
    $vetoCommands=[IO.File]::ReadAllText((Join-Path $script:T4MemoryRoot 'output\unload-veto-after.commands.txt'))
    Assert-T4Delete ($vetoCommands.Contains('dq SafeUpload!StageLastUnloadVeto L1') -and $vetoCommands.EndsWith(".echo T4_KD_UNLOAD_VETO_AFTER_END`r`nq")) 'Veto session reads the packed field and quits; never invokes the getter.'

    # Substitute only transport, with the same receipt shape as the real 180-second timeout.
    # Real parser and snapshot orchestration must preserve the independent successful pool census.
    $originalSession=(Get-Item Function:Invoke-T4DeleteKdSession).ScriptBlock
    try {
        $script:T4SelfCheckFailedBlock='logical'
        function Invoke-T4DeleteKdSession([string]$Label,[string]$Commands) {
            $body=if ($Label.EndsWith('-logical')) { "T4_LOGICAL_BEGIN`nNumeric expression missing from '& ...'" }
                elseif ($Label.EndsWith('-layout')) { $realLayout }
                elseif ($Label.EndsWith('-telemetry')) { $realTelemetry+"`n"+$realFilter }
                elseif ($Label.EndsWith('-poolfind')) { "T4_POOL_BEGIN`n"+(Get-T4KdSection $afterText 'POOL')+"`nT4_POOL_END" }
                elseif ($Label.EndsWith('-anchors')) { "T4_ANCHOR_COUNT_BEGIN`nfffff800``11330000  00000000`nT4_ANCHOR_COUNT_END`nT4_ANCHOR_WALK_END fffff80011330010 fffff80011330010" }
                else { $pass2 }
            $stdout=Join-Path $script:T4MemoryRoot ($Label+'.synthetic.txt')
            [IO.File]::WriteAllText($stdout,$body)
            $ok=-not $Label.EndsWith('-'+$script:T4SelfCheckFailedBlock)
            [pscustomobject]@{ Label=$Label; Stdout=$stdout; Finished=$ok; Complete=$ok; ExitCode=$(if ($ok) { 0 } else { -1 });
                KernelAttached=$true; PrivateSymbols=$true; Errors=$(if ($ok) { @() } else { @('KD session exceeded 180 seconds; killed, partial output retained.') }) }
        }
        $isolated=Save-T4DeleteSnapshot 'del-after' $corpus $before
        Assert-T4Delete ($isolated.Sessions.Count -eq 6 -and $isolated.Counts.NewBlocks -eq 1 -and $isolated.Census.PoolComplete) 'Logical timeout must not invalidate the independent address census.'
        Assert-T4Delete ($null -eq $isolated.Counts.LogicalOutstanding -and $isolated.Counts.Anchors -eq 0 -and $isolated.Counts.ParsedContexts -eq 1) 'Preserve successful sections and unknown failed logical count.'
        Assert-T4Delete (($isolated.Errors -join ';') -match 'Numeric expression missing' -and $isolated.Errors.Count -gt 0) 'Partial stdout error must survive the combined summary.'
        $script:T4SelfCheckFailedBlock='poolfind'
        $isolated=Save-T4DeleteSnapshot 'del-after-purge' $corpus $before
        Assert-T4Delete ($isolated.Sessions.Count -eq 6 -and $null -eq $isolated.Counts.NewBlocks -and -not $isolated.Census.PoolComplete) 'A timed-out pool session cannot certify a census even if section markers were printed.'
        Assert-T4Delete ($isolated.Census.Telemetry.PoolUsed.Count -eq 2 -and $isolated.Counts.Anchors -eq 0) 'A pool failure must not erase independent telemetry/anchors or turn poolused into a census.'
    } finally { Set-Item Function:Invoke-T4DeleteKdSession $originalSession }
} finally {
    if (Test-Path -LiteralPath $script:T4MemoryRoot) { Remove-Item -LiteralPath $script:T4MemoryRoot -Recurse -Force }
}
# Extract only the coordinator functions under test. Its actor, kernel and purge top level never runs.
$coordPath=Join-Path $PSScriptRoot 't4\cycles-coordinator.ps1'
$coordAst=[Management.Automation.Language.Parser]::ParseFile($coordPath,[ref]$tokens,[ref]$errors)
Assert-T4Delete ($errors.Count -eq 0) 'Coordinator parser errors.'
foreach ($name in 'Get-T4DeleteReleaseObservation','Invoke-T4DeleteAttribution') {
    $functions=@($coordAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name },$false))
    Assert-T4Delete ($functions.Count -eq 1) ('Actual coordinator helper unavailable: '+$name)
    Invoke-Expression $functions[0].Extent.Text
}
$coordSource=[IO.File]::ReadAllText($coordPath)
Assert-T4Delete ($coordSource.Contains('} elseif ($HandbackDiagnostic) { $result.HandbackDiagnostic = Invoke-T4HandbackDiagnostic }')) 'Combined mode must not delete hand-backs twice.'
Assert-T4Delete ($coordSource.Contains('if ($BlockHeavy) { $sensitive = ([math]::Floor(($i - 1) / 4) % 4) -ne 0 }')) 'Keep the actual block-heavy pattern.'
$blockCount=@(1..256 | Where-Object { ([math]::Floor(($_ - 1) / 4) % 4) -ne 0 }).Count
Assert-T4Delete ($blockCount -eq 192) '256 block-heavy cycles must request 192 hand-backs.'
# Local stand-ins model native observations; deletion runs against disposable files only.
& {
    $temp=Join-Path ([IO.Path]::GetTempPath()) ('T4DeleteFlow-'+[guid]::NewGuid().ToString('N'))
    $savedMemoryRoot=$script:T4MemoryRoot
    try {
        [void](New-Item -ItemType Directory -Path $temp)
        $script:T4MemoryRoot=$temp
        $handback=Join-Path $temp 'handbacks'; $journalDir=Join-Path $temp 'journals'; $root=Join-Path $temp 'public'
        [void](New-Item -ItemType Directory -Path $handback,$journalDir,$root)
        [IO.File]::WriteAllText((Join-Path $journalDir 'keep.json'),'journal')
        [IO.File]::WriteAllText((Join-Path $root 'keep.txt'),'public')
        $files=@(1..192 | ForEach-Object {
            $path=Join-Path $handback ($_.ToString()+'.txt'); [IO.File]::WriteAllText($path,'hand-back')
            [pscustomobject]@{ Path=$path; VolumeSerial='1234567890123456'; FileId=$_.ToString('x32'); HandlesClosed=$true; Streams=@('::$DATA') }
        })
        $events=New-Object 'Collections.Generic.List[string]'
        $MemoryDiagnostic=$true; $RequireVerifierPool=$true; $Cycles=256; $BlockHeavy=$true; $HandbackDiagnostic=$true
        function Get-T4HandbackIdentities($Directory) {
            $events.Add('identities'); $files
        }
        function New-T4DeleteCorpus($Directory) { throw 'Combined mode must never create a corpus.' }
        function Get-T4FileHolders($Category,$Paths) { $events.Add('holders-'+$Category); [pscustomobject]@{ Category=$Category; Files=$Paths.Count; Holders=@(); Error=$null } }
        function Invoke-T4MemoryPurge { $events.Add('purge'); @(1..5 | ForEach-Object { [pscustomobject]@{ Succeeded=$true } }) }
        function Start-Sleep([int]$Seconds) { $events.Add('sleep-'+$Seconds) }
        function Get-Sample($Cycle,$Label) {
            $events.Add('sample-'+$Label)
            if ($Label -eq 'del-baseline') { Assert-T4Delete (@($files | Where-Object { Test-Path -LiteralPath $_.Path }).Count -eq 192) 'No deletion before baseline.' }
            else { Assert-T4Delete (@($files | Where-Object { Test-Path -LiteralPath $_.Path }).Count -eq 0) 'Deletion must precede every post-delete sample.' }
            @{ Label=$Label; TagSUfl=@{ NonPagedAllocs=430; NonPagedFrees=100 } }
        }
        function Save-T4DeleteSnapshot($Label,$Corpus,$Baseline) {
            $events.Add('kd-'+$Label)
            Assert-T4Delete ($Corpus.Count -eq 192) 'KD must receive the original hand-back identities.'
            Assert-T4Delete (($Label -eq 'del-baseline') -eq ($null -eq $Baseline)) 'Post-delete census must diff the fresh baseline.'
            [pscustomobject]@{ Census=@{ PoolComplete=$true; Blocks=@() }; Counts=@{}; Classification='Synthetic'; Errors=@() }
        }
        function Write-T4DeleteEvidence($Path,$Text) { $events.Add('write-'+(Split-Path $Path -Leaf)); [IO.File]::WriteAllText($Path,$Text) }
        [void](New-Item -ItemType Directory -Path (Join-Path $temp 'output'))
        $start=@{ TagSUfl=@{ NonPagedAllocs=400; NonPagedFrees=100 } }
        $originalPurged=@{ TagSUfl=@{ NonPagedAllocs=450; NonPagedFrees=100 } }
        $diag=Invoke-T4DeleteAttribution $start $originalPurged
        Assert-T4Delete ($diag.Errors.Count -eq 0 -and $diag.Mode -eq 'Handbacks' -and $diag.Deleted -eq 192 -and $diag.DeleteErrors.Count -eq 0) 'Combined flow must delete exactly its verified hand-backs.'
        Assert-T4Delete ($diag.ReleasePrecondition.ReleaseProxyObserved -and $diag.ReleasePrecondition.ResidualAboveStart -eq 30 -and -not $diag.ReleasePrecondition.IndividualContextReleaseConfirmed) 'Record a near-start aggregate without inventing per-file proof.'
        Assert-T4Delete ($diag.HandbackDiagnostic.HandbacksDeleted -eq 192 -and $diag.HandbackDiagnostic.HandbacksLeft -eq 0 -and $diag.HandbackDiagnostic.Holders.Count -eq 3) 'Preserve hand-back diagnostic receipts.'
        Assert-T4Delete ([IO.File]::ReadAllText((Join-Path $root 'keep.txt')) -ceq 'public' -and [IO.File]::ReadAllText((Join-Path $journalDir 'keep.json')) -ceq 'journal') 'Public files and journals must survive.'
        $expected=@('identities','holders-Handbacks','holders-Journals','holders-Public','write-handback-identities.json',
            'purge','sleep-30','sample-del-baseline','kd-del-baseline','sleep-30','sample-handbacks-deleted','sample-del-after','kd-del-after',
            'purge','sleep-30','sample-handbacks-deleted-purged','sample-del-after-purge','kd-del-after-purge','write-delete-attribution.json')
        Assert-T4Delete (($events -join '|') -ceq ($expected -join '|')) ('Wrong diagnostic order: '+($events -join '|'))
        $stored=[IO.File]::ReadAllText((Join-Path $temp 'output/handback-identities.json')) | ConvertFrom-Json
        Assert-T4Delete ($stored.Count -eq 192 -and $stored[0].FileId.Length -eq 32) 'Full pre-deletion identity inventory must be saved.'
        $statuses=@(1..5 | ForEach-Object { [pscustomobject]@{ Succeeded=$true } })
        $obs=Get-T4DeleteReleaseObservation $start $originalPurged @{ TagSUfl=@{ NonPagedAllocs=700; NonPagedFrees=100 } } 192 $statuses
        Assert-T4Delete (-not $obs.ReleaseProxyObserved -and $obs.NearStart -eq $false) 'High baseline is explicitly an unconfirmed release precondition.'
        $obs=Get-T4DeleteReleaseObservation $start $originalPurged $null 192 $statuses
        Assert-T4Delete (-not $obs.ReleaseProxyObserved -and $null -eq $obs.NearStart) 'Missing baseline cannot imply release.'
        $statuses[0].Succeeded=$false
        $obs=Get-T4DeleteReleaseObservation $start $originalPurged $start 192 $statuses
        Assert-T4Delete (-not $obs.ReleaseProxyObserved) 'Refused purge cannot certify the precondition.'

        # Incomplete identity inventory must retain receipts and perform no purge/KD/deletion.
        $kept=Join-Path $handback 'incomplete.txt'; [IO.File]::WriteAllText($kept,'keep')
        $events.Clear()
        function Get-T4HandbackIdentities($Directory) { [pscustomobject]@{ Path=$kept }; throw 'Synthetic identity failure' }
        $diag=Invoke-T4DeleteAttribution $start $originalPurged
        Assert-T4Delete ($diag.Errors.Count -gt 0 -and $diag.Deleted -eq 0 -and $diag.CorpusCount -eq 1 -and (Test-Path -LiteralPath $kept) -and ($events -join '|') -ceq 'write-delete-attribution.json') 'Failed identity collection must preserve partial evidence without deleting.'

        # Separate corpus mode remains available and never queries the hand-back inventory.
        $HandbackDiagnostic=$false; $events.Clear()
        function New-T4DeleteCorpus($Directory) {
            $events.Add('new-corpus'); [void](New-Item -ItemType Directory -Path $Directory)
            1..256 | ForEach-Object { $path=Join-Path $Directory ($_.ToString()+'.txt'); [IO.File]::WriteAllText($path,'corpus'); [pscustomobject]@{ Path=$path } }
        }
        function Get-Sample($Cycle,$Label) { @{ Label=$Label } }
        function Save-T4DeleteSnapshot($Label,$Corpus,$Baseline) { [pscustomobject]@{ Census=@{ PoolComplete=$true }; Counts=@{}; Errors=@() } }
        $diag=Invoke-T4DeleteAttribution $start $originalPurged
        Assert-T4Delete ($diag.Errors.Count -eq 0 -and $diag.Mode -eq 'Corpus' -and $diag.Deleted -eq 256 -and $null -eq $diag.ReleasePrecondition -and $null -eq $diag.HandbackDiagnostic -and (Test-Path -LiteralPath $kept)) 'Separate 256-file corpus mode must remain independent.'
    } finally {
        $script:T4MemoryRoot=$savedMemoryRoot
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    }
}

'T4DeleteAttributionSelfCheck=PASS;Controls='+$script:checks+';SyntheticKd=True;RetainedKd=m2t4delattr1,m2t4delattr2;Qualification=False'
