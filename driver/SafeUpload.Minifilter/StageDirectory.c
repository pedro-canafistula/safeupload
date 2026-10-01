#include "Filter.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE

// A directory handle owns a snapshot and a cursor. Only the owner process's
// staged names are merged into it. Physical enumeration is issued below this
// instance using a separate handle so pagination never corrupts NTFS's cursor.
typedef struct _STAGE_DIRECTORY_ENTRY {
    LIST_ENTRY Link;
    ULONG Bytes;
    FILE_ID_128 ExtendedId;
    FILE_ID_BOTH_DIR_INFORMATION Info;
} STAGE_DIRECTORY_ENTRY, *PSTAGE_DIRECTORY_ENTRY;

typedef struct _STAGE_DIRECTORY_VIEW {
    LIST_ENTRY Entries;
    PLIST_ENTRY Cursor;
    UNICODE_STRING Pattern;
    BOOLEAN Started;
    ULONG Bytes;
    PEPROCESS Owner;
} STAGE_DIRECTORY_VIEW, *PSTAGE_DIRECTORY_VIEW;

VOID SafeUploadFreeDirectoryView(_In_opt_ PVOID View)
{
    PSTAGE_DIRECTORY_VIEW view = View;
    if (view == NULL) return;
    while (!IsListEmpty( &view->Entries )) {
        ExFreePoolWithTag( CONTAINING_RECORD( RemoveHeadList( &view->Entries ),
            STAGE_DIRECTORY_ENTRY, Link ), SAFEUPLOAD_POOL_TAG );
    }
    if (view->Pattern.Buffer != NULL) RtlFreeUnicodeString( &view->Pattern );
    if (view->Owner != NULL) ObDereferenceObject(view->Owner);
    ExFreePoolWithTag( view, SAFEUPLOAD_POOL_TAG );
}

static NTSTATUS StageDirectoryAdd(_Inout_ PSTAGE_DIRECTORY_VIEW View,
    _In_ PFILE_ID_BOTH_DIR_INFORMATION Info, _In_opt_ PFILE_ID_128 ExtendedId)
{
    ULONG bytes = FIELD_OFFSET( STAGE_DIRECTORY_ENTRY, Info.FileName ) + Info->FileNameLength;
    PSTAGE_DIRECTORY_ENTRY entry;
    if (Info->FileNameLength > SAFEUPLOAD_MAX_PATH_BYTES || View->Bytes + bytes > 16 * 1024 * 1024)
        return STATUS_INSUFFICIENT_RESOURCES;
    entry = ExAllocatePool2( POOL_FLAG_PAGED, bytes, SAFEUPLOAD_POOL_TAG );
    if (entry == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    entry->Bytes = bytes;
    if (ExtendedId != NULL) entry->ExtendedId = *ExtendedId;
    else RtlCopyMemory(&entry->ExtendedId, &Info->FileId, sizeof(Info->FileId));
    RtlCopyMemory( &entry->Info, Info,
        FIELD_OFFSET( FILE_ID_BOTH_DIR_INFORMATION, FileName ) + Info->FileNameLength );
    entry->Info.NextEntryOffset = 0;
    InsertTailList( &View->Entries, &entry->Link );
    View->Bytes += bytes;
    return STATUS_SUCCESS;
}

static VOID StageDirectoryRemove(_Inout_ PSTAGE_DIRECTORY_VIEW View, _In_ PUNICODE_STRING Name)
{
    PLIST_ENTRY link = View->Entries.Flink;
    while (link != &View->Entries) {
        PSTAGE_DIRECTORY_ENTRY entry = CONTAINING_RECORD( link, STAGE_DIRECTORY_ENTRY, Link );
        UNICODE_STRING name;
        link = link->Flink;
        name.Buffer = entry->Info.FileName;
        name.Length = (USHORT) entry->Info.FileNameLength;
        name.MaximumLength = name.Length;
        if (RtlEqualUnicodeString( Name, &name, TRUE )) {
            RemoveEntryList( &entry->Link );
            View->Bytes -= entry->Bytes;
            ExFreePoolWithTag( entry, SAFEUPLOAD_POOL_TAG );
        }
    }
}

static NTSTATUS StageDirectoryBuild(_In_ PFLT_INSTANCE Instance, _In_ PUNICODE_STRING Directory,
    _In_ ULONG Owner, _In_opt_ PUNICODE_STRING Pattern, _Outptr_ PSTAGE_DIRECTORY_VIEW *Result)
{
    PSTAGE_DIRECTORY_VIEW view = NULL;
    PVOID buffer = NULL;
    HANDLE handle = NULL;
    PFILE_OBJECT file = NULL;
    IO_STATUS_BLOCK io;
    OBJECT_ATTRIBUTES attributes;
    LIST_ENTRY overlays;
    PLIST_ENTRY link;
    ULONG returned, offset;
    BOOLEAN first = TRUE;
    NTSTATUS status;
    UNICODE_STRING all = RTL_CONSTANT_STRING( L"*" );
    *Result = NULL;
    InitializeListHead( &overlays );
    view = ExAllocatePool2( POOL_FLAG_PAGED, sizeof( *view ), SAFEUPLOAD_POOL_TAG );
    if (view != NULL) InitializeListHead( &view->Entries );
    buffer = ExAllocatePool2( POOL_FLAG_PAGED, 65536, SAFEUPLOAD_POOL_TAG );
    if (view == NULL || buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    status = PsLookupProcessByProcessId(ULongToHandle(Owner), &view->Owner);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlUpcaseUnicodeString( &view->Pattern, Pattern != NULL ? Pattern : &all, TRUE );
    if (!NT_SUCCESS( status )) goto Exit;
    status = SafeUploadCollectDirectoryOverlay( Owner, Directory, &overlays );
    if (!NT_SUCCESS( status )) goto Exit;
    InitializeObjectAttributes( &attributes, Directory, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL );
    status = FltCreateFileEx2( SafeUploadData.Filter, Instance, &handle, &file,
        FILE_LIST_DIRECTORY | SYNCHRONIZE, &attributes, &io, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, 0, NULL );
    if (!NT_SUCCESS( status )) goto Exit;
    for (;;) {
        status = FltQueryDirectoryFile( Instance, file, buffer, 65536,
            FileIdBothDirectoryInformation, FALSE, NULL, first, &returned );
        first = FALSE;
        if (status == STATUS_NO_MORE_FILES || status == STATUS_NO_SUCH_FILE) { status = STATUS_SUCCESS; break; }
        if (!NT_SUCCESS( status )) goto Exit;
        if (returned == 0) { status = STATUS_INTERNAL_ERROR; goto Exit; }
        offset = 0;
        for (;;) {
            PFILE_ID_BOTH_DIR_INFORMATION info = (PFILE_ID_BOTH_DIR_INFORMATION) ((PUCHAR) buffer + offset);
            ULONG header = FIELD_OFFSET( FILE_ID_BOTH_DIR_INFORMATION, FileName );
            if (offset > returned || returned - offset < header ||
                info->FileNameLength > returned - offset - header || (info->FileNameLength & 1)) {
                status = STATUS_DATA_ERROR; goto Exit;
            }
            status = StageDirectoryAdd( view, info, NULL );
            if (!NT_SUCCESS( status )) goto Exit;
            if (info->NextEntryOffset == 0) break;
            if (info->NextEntryOffset < header || info->NextEntryOffset > returned - offset) {
                status = STATUS_DATA_ERROR; goto Exit;
            }
            offset += info->NextEntryOffset;
        }
    }
    FltClose( handle ); handle = NULL;
    ObDereferenceObject( file ); file = NULL;
    for (link = overlays.Flink; link != &overlays; link = link->Flink) {
        PSAFEUPLOAD_DIRECTORY_OVERLAY overlay = CONTAINING_RECORD( link, SAFEUPLOAD_DIRECTORY_OVERLAY, Link );
        StageDirectoryRemove( view, &overlay->Name );
        if (!overlay->Deleted) {
            FILE_BASIC_INFORMATION basic = overlay->Basic;
            FILE_STANDARD_INFORMATION standard = overlay->Standard;
            PFILE_ID_BOTH_DIR_INFORMATION info = buffer;
            RtlZeroMemory( buffer, FIELD_OFFSET( FILE_ID_BOTH_DIR_INFORMATION, FileName ) );
            info->CreationTime = basic.CreationTime; info->LastAccessTime = basic.LastAccessTime;
            info->LastWriteTime = basic.LastWriteTime; info->ChangeTime = basic.ChangeTime;
            info->EndOfFile = standard.EndOfFile; info->AllocationSize = standard.AllocationSize;
            info->FileAttributes = basic.FileAttributes; info->FileId = overlay->FileId;
            info->FileNameLength = overlay->Name.Length;
            RtlCopyMemory( info->FileName, overlay->Name.Buffer, overlay->Name.Length );
            status = StageDirectoryAdd( view, info, &overlay->ExtendedId );
            if (!NT_SUCCESS( status )) goto Exit;
        }
    }
    view->Cursor = view->Entries.Flink;
    *Result = view; view = NULL;
    status = STATUS_SUCCESS;
Exit:
    if (handle != NULL) FltClose( handle );
    if (file != NULL) ObDereferenceObject( file );
    if (buffer != NULL) ExFreePoolWithTag( buffer, SAFEUPLOAD_POOL_TAG );
    while (!IsListEmpty( &overlays )) ExFreePoolWithTag( CONTAINING_RECORD(
        RemoveHeadList( &overlays ), SAFEUPLOAD_DIRECTORY_OVERLAY, Link ), SAFEUPLOAD_POOL_TAG );
    // Pool allocation may fail before the entries list has been initialized.
    if (view != NULL && view->Entries.Flink == NULL) InitializeListHead( &view->Entries );
    SafeUploadFreeDirectoryView( view );
    return status;
}

static ULONG StageDirectoryHeader(FILE_INFORMATION_CLASS Class)
{
    switch (Class) {
    case FileDirectoryInformation: return FIELD_OFFSET( FILE_DIRECTORY_INFORMATION, FileName );
    case FileFullDirectoryInformation: return FIELD_OFFSET( FILE_FULL_DIR_INFORMATION, FileName );
    case FileBothDirectoryInformation: return FIELD_OFFSET( FILE_BOTH_DIR_INFORMATION, FileName );
    case FileNamesInformation: return FIELD_OFFSET( FILE_NAMES_INFORMATION, FileName );
    case FileIdBothDirectoryInformation: return FIELD_OFFSET( FILE_ID_BOTH_DIR_INFORMATION, FileName );
    case FileIdFullDirectoryInformation: return FIELD_OFFSET( FILE_ID_FULL_DIR_INFORMATION, FileName );
    case FileIdExtdDirectoryInformation: return FIELD_OFFSET( FILE_ID_EXTD_DIR_INFORMATION, FileName );
    case FileIdExtdBothDirectoryInformation: return FIELD_OFFSET( FILE_ID_EXTD_BOTH_DIR_INFORMATION, FileName );
    default: return 0;
    }
}

static NTSTATUS StageDirectoryOutput(PFLT_CALLBACK_DATA Data, PSTAGE_DIRECTORY_VIEW View,
    PVOID Output, PULONG Written)
{
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
    ULONG header = StageDirectoryHeader( cls );
    ULONG length = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
    PUCHAR previous = NULL;
    BOOLEAN single = (BOOLEAN) FlagOn( Data->Iopb->OperationFlags, SL_RETURN_SINGLE_ENTRY );
    *Written = 0;
    if (header == 0) return STATUS_INVALID_INFO_CLASS;
    if (length < header) return STATUS_INFO_LENGTH_MISMATCH;
    while (View->Cursor != &View->Entries) {
        PSTAGE_DIRECTORY_ENTRY entry = CONTAINING_RECORD( View->Cursor, STAGE_DIRECTORY_ENTRY, Link );
        UNICODE_STRING name;
        ULONG required, copied;
        PUCHAR out = (PUCHAR) Output + *Written;
        name.Buffer = entry->Info.FileName;
        name.Length = (USHORT) entry->Info.FileNameLength;
        name.MaximumLength = name.Length;
        if (!FsRtlIsNameInExpression( &View->Pattern, &name, TRUE, NULL )) {
            View->Cursor = View->Cursor->Flink;
            continue;
        }
        required = (header + name.Length + 7) & ~7UL;
        if (required > length - *Written && (*Written != 0 || View->Started)) break;
        RtlZeroMemory( out, min( required, length - *Written ) );
        if (cls == FileNamesInformation) ((PFILE_NAMES_INFORMATION) out)->FileNameLength = name.Length;
        else {
            // All supported non-Names structures share this fixed prefix.
            RtlCopyMemory( out, &entry->Info, FIELD_OFFSET( FILE_DIRECTORY_INFORMATION, FileName ) );
            if (cls != FileDirectoryInformation) ((PFILE_FULL_DIR_INFORMATION) out)->EaSize = entry->Info.EaSize;
            if (cls == FileBothDirectoryInformation || cls == FileIdBothDirectoryInformation) {
                ((PFILE_BOTH_DIR_INFORMATION) out)->ShortNameLength = entry->Info.ShortNameLength;
                RtlCopyMemory( ((PFILE_BOTH_DIR_INFORMATION) out)->ShortName,
                    entry->Info.ShortName, sizeof( entry->Info.ShortName ) );
            }
            if (cls == FileIdBothDirectoryInformation) ((PFILE_ID_BOTH_DIR_INFORMATION) out)->FileId = entry->Info.FileId;
            if (cls == FileIdFullDirectoryInformation) ((PFILE_ID_FULL_DIR_INFORMATION) out)->FileId = entry->Info.FileId;
            if (cls == FileIdExtdDirectoryInformation || cls == FileIdExtdBothDirectoryInformation) {
                PFILE_ID_EXTD_DIR_INFORMATION extended = (PFILE_ID_EXTD_DIR_INFORMATION) out;
                extended->FileId = entry->ExtendedId;
            }
        }
        copied = min( name.Length, length - *Written - header ) & ~1UL;
        RtlCopyMemory( out + header, name.Buffer, copied );
        if (previous != NULL) *(PULONG) previous = (ULONG) (out - previous);
        previous = out;
        *Written += min( required, length - *Written );
        View->Cursor = View->Cursor->Flink;
        if (copied < name.Length) { View->Started = TRUE; return STATUS_BUFFER_OVERFLOW; }
        if (single) break;
    }
    if (*Written == 0) {
        NTSTATUS status = View->Started ? STATUS_NO_MORE_FILES : STATUS_NO_SUCH_FILE;
        // A later too-small buffer is STATUS_SUCCESS with no entries, as NTFS.
        if (View->Cursor != &View->Entries) status = STATUS_SUCCESS;
        View->Started = TRUE;
        return status;
    }
    View->Started = TRUE;
    return STATUS_SUCCESS;
}

static VOID StageDirectoryWorker(_In_ PFLT_DEFERRED_IO_WORKITEM Item,
    _In_ PFLT_CALLBACK_DATA Data, _In_opt_ PVOID Context)
{
    PFLT_RELATED_OBJECTS objects = Context;
    PVOID completion = NULL;
    FLT_PREOP_CALLBACK_STATUS result;
    if (objects == NULL) {
        Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Data->IoStatus.Information = 0;
        FltCompletePendedPreOperation(Data, FLT_PREOP_COMPLETE, NULL);
        FltFreeDeferredIoWorkItem(Item);
        return;
    }
    if (FltIsIoCanceled( Data )) {
        Data->IoStatus.Status = STATUS_CANCELLED;
        Data->IoStatus.Information = 0;
        result = FLT_PREOP_COMPLETE;
    } else {
        result = SafeUploadStageDirectoryQuery( Data, objects, &completion );
    }
    FltCompletePendedPreOperation( Data, result, completion );
    ObDereferenceObject( objects->FileObject );
    FltObjectDereference( objects->Volume );
    FltObjectDereference( objects->Instance );
    FltObjectDereference( objects->Filter );
    ExFreePoolWithTag( objects, SAFEUPLOAD_POOL_TAG );
    FltFreeDeferredIoWorkItem( Item );
}

FLT_PREOP_CALLBACK_STATUS SafeUploadStageDirectoryQuery(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PSAFEUPLOAD_STREAMHANDLE_CONTEXT handleContext = NULL, created = NULL;
    PFLT_FILE_NAME_INFORMATION directory = NULL;
    ULONG owner = FltGetRequestorProcessId( Data );
    PVOID output;
    ULONG written = 0;
    NTSTATUS status;
    *CompletionContext = NULL;
    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY || owner == 0 ||
        owner == SafeUploadData.InspectorProcessId) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL) {
        PFLT_DEFERRED_IO_WORKITEM item;
        PFLT_RELATED_OBJECTS objects;
        if (!SafeUploadProcessHasMappings( owner )) return FLT_PREOP_SUCCESS_NO_CALLBACK;
        if (!FLT_IS_IRP_OPERATION( Data )) return FLT_PREOP_DISALLOW_FASTIO;
        item = FltAllocateDeferredIoWorkItem();
        objects = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( *objects ), SAFEUPLOAD_POOL_TAG );
        if (item == NULL || objects == NULL) {
            if (item != NULL) FltFreeDeferredIoWorkItem( item );
            if (objects != NULL) ExFreePoolWithTag( objects, SAFEUPLOAD_POOL_TAG );
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        RtlCopyMemory( objects, FltObjects, sizeof( *objects ) );
        status = FltObjectReference(objects->Filter);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(objects, SAFEUPLOAD_POOL_TAG); FltFreeDeferredIoWorkItem(item);
            goto Exit;
        }
        status = FltObjectReference(objects->Instance);
        if (!NT_SUCCESS(status)) {
            FltObjectDereference(objects->Filter);
            ExFreePoolWithTag(objects, SAFEUPLOAD_POOL_TAG); FltFreeDeferredIoWorkItem(item);
            goto Exit;
        }
        status = FltObjectReference(objects->Volume);
        if (!NT_SUCCESS(status)) {
            FltObjectDereference(objects->Instance); FltObjectDereference(objects->Filter);
            ExFreePoolWithTag(objects, SAFEUPLOAD_POOL_TAG); FltFreeDeferredIoWorkItem(item);
            goto Exit;
        }
        ObReferenceObject(objects->FileObject);
        status = FltQueueDeferredIoWorkItem( item, Data, StageDirectoryWorker, DelayedWorkQueue, objects );
        if (NT_SUCCESS( status )) return FLT_PREOP_PENDING;
        ObDereferenceObject( objects->FileObject ); FltObjectDereference( objects->Volume );
        FltObjectDereference( objects->Instance ); FltObjectDereference( objects->Filter );
        ExFreePoolWithTag( objects, SAFEUPLOAD_POOL_TAG ); FltFreeDeferredIoWorkItem( item );
        goto Exit;
    }
    if (FLT_IS_IRP_OPERATION( Data ) && FltIsIoCanceled( Data )) { status = STATUS_CANCELLED; goto Exit; }
    status = FltGetFileNameInformation( Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &directory );
    if (!NT_SUCCESS( status )) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!SafeUploadHasDirectoryOverlay( owner, &directory->Name )) {
        FltReleaseFileNameInformation( directory );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (!FltSupportsStreamHandleContexts( FltObjects->FileObject )) { status = STATUS_NOT_SUPPORTED; goto Exit; }
    status = FltGetStreamHandleContext( FltObjects->Instance, FltObjects->FileObject,
        (PFLT_CONTEXT *) &handleContext );
    if (status == STATUS_NOT_FOUND) {
        status = FltAllocateContext( FltObjects->Filter, FLT_STREAMHANDLE_CONTEXT,
            sizeof( *created ), NonPagedPool, (PFLT_CONTEXT *) &created );
        if (!NT_SUCCESS( status )) goto Exit;
        RtlZeroMemory( created, sizeof( *created ) );
        FltInitializePushLock( &created->DirectoryLock );
        status = FltSetStreamHandleContext( FltObjects->Instance, FltObjects->FileObject,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS, created, (PFLT_CONTEXT *) &handleContext );
        if (NT_SUCCESS( status )) { handleContext = created; FltReferenceContext( handleContext ); }
        else if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) status = STATUS_SUCCESS;
        FltReleaseContext( created );
    }
    if (!NT_SUCCESS( status )) goto Exit;
    if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress == NULL) {
        status = FltLockUserBuffer( Data );
        if (!NT_SUCCESS( status )) goto Exit;
    }
    output = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL
        ? MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
                                      NormalPagePriority | MdlMappingNoExecute)
        : Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    if (output == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    FltAcquirePushLockExclusive( &handleContext->DirectoryLock );
    if (handleContext->DirectoryView == NULL ||
        ((PSTAGE_DIRECTORY_VIEW) handleContext->DirectoryView)->Owner != FltGetRequestorProcess(Data) ||
        FlagOn( Data->Iopb->OperationFlags, SL_RESTART_SCAN )) {
        PSTAGE_DIRECTORY_VIEW view = NULL;
        PUNICODE_STRING pattern = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileName;
        // NT captures the pattern only on the initial query of this handle.
        if (handleContext->DirectoryView != NULL) pattern = &((PSTAGE_DIRECTORY_VIEW) handleContext->DirectoryView)->Pattern;
        status = StageDirectoryBuild( FltObjects->Instance, &directory->Name, owner, pattern, &view );
        if (NT_SUCCESS( status )) {
            SafeUploadFreeDirectoryView( handleContext->DirectoryView );
            handleContext->DirectoryView = view;
        }
    }
    __try {
        if (NT_SUCCESS( status )) status = StageDirectoryOutput( Data, handleContext->DirectoryView, output, &written );
    } __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); written = 0; }
    FltReleasePushLock( &handleContext->DirectoryLock );
Exit:
    if (handleContext != NULL) FltReleaseContext( handleContext );
    if (directory != NULL) FltReleaseFileNameInformation( directory );
    Data->IoStatus.Status = status; Data->IoStatus.Information = written;
    return FLT_PREOP_COMPLETE;
}
#endif
