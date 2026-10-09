using System.Text.Json.Nodes;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Diagnostics;

/// <summary>
/// Read-only queries to the driver over the service's own filter-port connection. The port accepts one client and
/// the service holds it, so this is the only way to read driver state while the product runs. The interceptor
/// binds the port while it is connected and unbinds it before the port closes.
/// </summary>
public sealed class DriverDiagnosticsSource
{
    private readonly object _gate = new();
    private FilterPort? _port;
    private bool _layoutVerified;
    private string? _layoutError;

    public void Bind(FilterPort port)
    {
        lock (_gate)
        {
            _port = port;
        }
    }

    public void Unbind(FilterPort port)
    {
        lock (_gate)
        {
            if (ReferenceEquals(_port, port)) _port = null;
        }
    }

    public bool IsConnected
    {
        get
        {
            lock (_gate) return _port is not null;
        }
    }

    /// <summary>Driver counters plus the writer-state status (registry, reclaim worker, sections, stage streams).</summary>
    public JsonObject ReadCounters()
    {
        return WithPort(port =>
        {
            SafeUploadDiagCounters diag = port.ReadDiagnosticCounters();
            SafeUploadWriterStateStatus writer = port.ReadWriterStateStatus();
            return new JsonObject
            {
                ["refusals"] = new JsonObject
                {
                    ["recorded"] = diag.DenyRecorded,
                    ["accessDenied"] = diag.DenyAccessDenied,
                    ["retry"] = diag.DenyRetry,
                    ["otherStatus"] = diag.DenyOtherStatus,
                    ["benignIgnored"] = diag.DenyBenignIgnored,
                    ["notRecorded"] = diag.DenyNotRecorded,
                    ["nextSequence"] = diag.NextDenySequence,
                },
                ["volumeWideFallback"] = new JsonObject
                {
                    ["queries"] = diag.VolumeWideQueries,
                    ["answeredTrue"] = diag.VolumeWideAnswers,
                },
                ["reclaimWorker"] = new JsonObject
                {
                    ["passes"] = diag.ReclaimPasses,
                    ["parkedPasses"] = diag.ReclaimParkedPasses,
                    ["moreWorkRequeues"] = diag.ReclaimMoreWorkRequeues,
                },
                ["imageBase"] = Hex(diag.ImageBase),
                ["writerState"] = new JsonObject
                {
                    ["registryEntries"] = writer.RegistryEntries,
                    ["registryCapacity"] = writer.RegistryCapacity,
                    ["registryReservations"] = writer.RegistryReservations,
                    ["registryOverflow"] = writer.RegistryOverflow,
                    ["registryUnknownReasons"] = writer.RegistryUnknownReasons,
                    ["registryInstanceUnknown"] = writer.RegistryInstanceUnknown,
                    ["registryPruned"] = writer.RegistryPruned,
                    ["registryReclaimPasses"] = writer.RegistryReclaimPasses,
                    ["registryCapacityFailures"] = writer.RegistryCapacityFailures,
                    ["registryNameTierEntries"] = writer.RegistryNameTierEntries,
                    ["registryCompactTierEntries"] = writer.RegistryCompactTierEntries,
                    ["sectionInFlightNow"] = writer.SectionInFlightNow,
                    ["sectionInFlightMaxDepth"] = writer.SectionInFlightMaxDepth,
                    ["sectionInFlightStuck"] = writer.SectionInFlightStuck,
                    ["stageStreams"] = writer.StageStreams,
                    ["stageFileObjects"] = writer.StageFileObjects,
                    ["untrackedCreates"] = writer.UntrackedCreates,
                    ["txfRefused"] = writer.TxfRefused,
                    ["instanceTeardownsDismount"] = writer.InstanceTeardownsDismount,
                    ["instanceTeardownsOther"] = writer.InstanceTeardownsOther,
                },
            };
        });
    }

    /// <summary>One page of the deny ring. The caller repeats with <c>nextSequence</c> until it equals its cursor.</summary>
    public JsonObject ReadDenyRing(ulong afterSequence)
    {
        return WithPort(port =>
        {
            DenyRingPage page = port.ReadDenyRing(afterSequence);
            var records = new JsonArray();
            foreach (DenyRecord record in page.Records)
            {
                records.Add(new JsonObject
                {
                    ["sequence"] = record.Sequence,
                    ["timeUtc"] = record.TimeUtc == DateTime.MinValue ? null : record.TimeUtc.ToString("O"),
                    ["status"] = "0x" + record.Status.ToString("X8"),
                    ["statusName"] = StatusName(record.Status),
                    ["siteOffset"] = record.SiteOffset == 0 ? null : "0x" + record.SiteOffset.ToString("X"),
                    ["processId"] = record.ProcessId,
                    ["threadId"] = record.ThreadId,
                    ["major"] = MajorName(record.MajorFunction),
                    ["minor"] = record.MinorFunction,
                    ["irql"] = record.Irql,
                    ["flags"] = FlagNames(record.Flags),
                    ["access"] = "0x" + record.Access.ToString("X"),
                    ["options"] = "0x" + record.Options.ToString("X"),
                    ["name"] = record.Name.Length == 0 ? null : record.Name,
                });
            }
            return new JsonObject
            {
                ["records"] = records,
                ["nextSequence"] = page.NextSequence,
                ["imageBase"] = Hex(page.ImageBase),
                ["gap"] = page.Gap,
            };
        });
    }

    private JsonObject WithPort(Func<FilterPort, JsonObject> query)
    {
        lock (_gate)
        {
            if (_port is null) throw new InvalidOperationException("The minifilter is not connected.");
            if (!_layoutVerified)
            {
                try
                {
                    DiagnosticsContract.Verify();
                }
                catch (InvalidOperationException ex)
                {
                    _layoutError = ex.Message;
                }
                _layoutVerified = true;
            }
            if (_layoutError is not null) throw new InvalidOperationException(_layoutError);
            return query(_port);
        }
    }

    private static string Hex(ulong value) => "0x" + value.ToString("X");

    internal static string StatusName(uint status) => status switch
    {
        0xC0000022 => "STATUS_ACCESS_DENIED",
        0xC000022D => "STATUS_RETRY",
        0xC0000043 => "STATUS_SHARING_VIOLATION",
        0xC0000056 => "STATUS_DELETE_PENDING",
        0xC000009A => "STATUS_INSUFFICIENT_RESOURCES",
        0xC0000904 => "STATUS_FILE_TOO_LARGE",
        0x80000011 => "STATUS_DEVICE_BUSY",
        0xC00000D4 => "STATUS_NOT_SAME_DEVICE",
        0xC00000BB => "STATUS_NOT_SUPPORTED",
        0xC000000D => "STATUS_INVALID_PARAMETER",
        0xC0000035 => "STATUS_OBJECT_NAME_COLLISION",
        0xC0000034 => "STATUS_OBJECT_NAME_NOT_FOUND",
        _ => "",
    };

    internal static string MajorName(uint major) => major switch
    {
        0 => "CREATE",
        2 => "CLOSE",
        3 => "READ",
        4 => "WRITE",
        5 => "QUERY_INFORMATION",
        6 => "SET_INFORMATION",
        7 => "QUERY_EA",
        8 => "SET_EA",
        9 => "FLUSH_BUFFERS",
        10 => "QUERY_VOLUME_INFORMATION",
        11 => "SET_VOLUME_INFORMATION",
        12 => "DIRECTORY_CONTROL",
        13 => "FILE_SYSTEM_CONTROL",
        14 => "DEVICE_CONTROL",
        15 => "INTERNAL_DEVICE_CONTROL",
        17 => "LOCK_CONTROL",
        18 => "CLEANUP",
        20 => "QUERY_SECURITY",
        21 => "SET_SECURITY",
        0xFF => "ACQUIRE_FOR_SECTION_SYNCHRONIZATION",
        0xFE => "RELEASE_FOR_SECTION_SYNCHRONIZATION",
        _ => major.ToString(),
    };

    internal static JsonArray FlagNames(uint flags)
    {
        var names = new JsonArray();
        (uint Bit, string Name)[] known =
        {
            (DiagnosticsContract.FlagTopLevelIrp, "topLevelIrp"),
            (DiagnosticsContract.FlagTransaction, "transaction"),
            (DiagnosticsContract.FlagPagingIo, "pagingIo"),
            (DiagnosticsContract.FlagFastIo, "fastIo"),
            (DiagnosticsContract.FlagPostOperation, "postOperation"),
            (DiagnosticsContract.FlagNameIsRenameTarget, "nameIsRenameTarget"),
            (DiagnosticsContract.FlagNameIsCreateName, "nameIsCreateName"),
            (DiagnosticsContract.FlagServiceProcess, "serviceProcess"),
            (DiagnosticsContract.FlagKernelMode, "kernelMode"),
            (DiagnosticsContract.FlagNameTruncated, "nameTruncated"),
        };
        foreach ((uint bit, string name) in known)
        {
            if ((flags & bit) != 0) names.Add(name);
        }
        return names;
    }
}
