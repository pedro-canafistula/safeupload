**ACCEPT WITH CONDITIONS** — reviewed design at `a00e7e14`. Required conditions are findings 2, 3 and 6. No files changed or runtime tests run.

1. **Informational — the published coverage value is not operation authority.** All production consumers found:

   | Consumer | Effect |
   |---|---|
   | [MinifilterInterceptor.cs:1585](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1585) | Maps the decision, announces first Ready, logs transitions and publishes notifications. |
   | [NotificationHub.cs:148](agente/SafeUpload.Agent.Service/Notifications/NotificationHub.cs:148), also `:174` | Retains, records and forwards status; replays current status to connecting clients. |
   | [NotificationRecord.cs:145](agente/SafeUpload.Agent.Service/Notifications/NotificationRecord.cs:145) | Records notification kind `Status`; does not use coverage to authorize anything. |
   | [NotificationPipeServer.cs:174](agente/SafeUpload.Agent.Service/Notifications/NotificationPipeServer.cs:174), [NotificationProtocol.cs:45](agente/SafeUpload.Agent.Core/Contracts/NotificationProtocol.cs:45), [PipeClient.cs:144](agente/SafeUpload.Agent.App/Notifications/PipeClient.cs:144) | Serializes, transports, deserializes and dispatches notifications. |
   | [App.xaml.cs:98](agente/SafeUpload.Agent.App/App.xaml.cs:98), [StatusViewModel.cs:106](agente/SafeUpload.Agent.App/ViewModels/StatusViewModel.cs:106) | Updates displayed connection, policy and coverage captions. No justification/admission gate. |
   | [ReadySignal.cs:34](agente/SafeUpload.Agent.Minifilter/ReadySignal.cs:34) | Sets an existing external readiness event. No service/kernel consumer waits on it; it is a one-time announcement, not current coverage. The [Probe caller:80](agente/SafeUpload.Minifilter.Probe/Program.cs:80) announces a separate event after policy installation. |

   Test references only assert evaluator, startup, serialization, hub and recording behavior. The feature [proof proxy:28](agente/SafeUpload.Agent.Minifilter/StagedProofProxy.cs:28) separately forwards raw command-24 diagnostics.

   Publication/hand-back and cleanup wait on **`_stagingReadySignal`**, populated by handshake/recovery at [MinifilterInterceptor.cs:460](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:460), consumed at `:1228` and `:1330`. Published coverage never sets it. Kernel coverage is a temporary output receipt, copied only on success: [Communication.c:2415](driver/SafeUpload.Minifilter/Communication.c:2415). **Required change:** none; preserve this separation.

2. **Medium — 70 ms is a delay budget, not a reporting-time bound.** [Design:23–28](driver/T18-COVERAGE-RETRY.md:23) understates elapsed time. Each attempt also waits on the uncancellable [send gate:108](agente/SafeUpload.Agent.Minifilter/FilterPort.cs:108) and synchronous [`FilterSendMessage`](https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filtersendmessage). The loop then waits another [500 ms:1618](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1618).

   A previous Ready remains displayed during retries; reporting can exceed existing poll granularity by 70 ms **plus three additional query/queue durations**. Cancellation bounds the delays, not an in-flight native query. **Required change:** state these limits explicitly and remove the hard “at most about 70 ms”/500-ms freshness claims.

3. **Medium — specify the exception field and limit attribution.** [AdmissionCoverage.cs:328](agente/SafeUpload.Agent.Minifilter/AdmissionCoverage.cs:328) constructs `Win32Exception(hr, message)`. The HRESULT is stored in **`NativeErrorCode`**; `Exception.HResult`/`ErrorCode` remains `E_FAIL`, as shown by the [.NET constructor](https://raw.githubusercontent.com/dotnet/dotnet/b0f34d51fccc69fd334253924abd8d6853fad7aa/src/runtime/src/libraries/System.Private.CoreLib/src/System/ComponentModel/Win32Exception.cs) and [base constructor](https://raw.githubusercontent.com/dotnet/runtime/main/src/libraries/System.Private.CoreLib/src/System/Runtime/InteropServices/ExternalException.cs).

   The sole explicit command-24 retry producer is [StageWriters.c:7801](driver/SafeUpload.Minifilter/StageWriters.c:7801), propagated at [StageAdmission.c:714](driver/SafeUpload.Minifilter/StageAdmission.c:714). Auth, allocation and rundown failures use different statuses. Other controls also return `STATUS_RETRY` (`StageWriters.c:7689,7743`); the HRESULT itself carries no return-edge provenance, and transport exclusivity is unproven.

   **Required change:** match only `Win32Exception.NativeErrorCode == unchecked((int)0x800704D5)` around this coverage query. Exact matching is appropriate for this read-only operation; do not generalize it to other controls or describe it as proof of harmless churn.

4. **Low — persistent failures cannot become Ready, but existing precedence can obscure their reason.** Stable receipts evaluate policy failure, Unknown and identity failures as Degraded: [AdmissionCoverage.cs:221–269](agente/SafeUpload.Agent.Minifilter/AdmissionCoverage.cs:221). Exhaustion also produces Degraded. Queries never clear Unknown.

   However, changing snapshots return Pending before those checks (`:131`), and [ApplyStageStartupReadiness:1627](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1627) preserves Pending/Degraded even when startup failed. This is existing behavior, explicitly tested at [StagedStartupReadinessTests.cs:39](agente/SafeUpload.Agent.Tests/StagedStartupReadinessTests.cs:39). **Required change:** document this limitation; sample current startup flags after retries and test failure arising during a retry delay.

5. **Low — four sequential attempts are reasonable, with measurable contention cost.** Each query walks the registry under a shared lock, taking brief resident entry spinlocks: [StageWriters.c:7769](driver/SafeUpload.Minifilter/StageWriters.c:7769), [snapshot:7573](driver/SafeUpload.Minifilter/StageWriters.c:7573). Capacity reaches 20,480 entries: [Protocol.h:527–530](driver/SafeUpload.Minifilter/Protocol.h:527). The entry point requires PASSIVE_LEVEL: [StageAdmission.c:529](driver/SafeUpload.Minifilter/StageAdmission.c:529).

   No new lock order, IRQL transition or registry mutation is introduced. Up to four walks increase writer/control contention; starvation is not demonstrated. **Required change:** keep retries sequential, release each send lease before delaying, and record actual latency during eventual authorized qualification.

6. **Medium — extend tests and preserve the VM stop.** Beyond [Design:41–45](driver/T18-COVERAGE-RETRY.md:41), require production-shaped exception-field tests; success on attempts 3/4; exact 10/20/40 delays; retry followed by terminal error/malformed receipt; cancellation before another query; retry followed by Unknown, policy failure, identity failure or generation mismatch; and Ready followed by current startup rejection. Verify repeated exhausted sequences increment counters despite warning suppression ([current suppression:1572](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1572)).

   No fail-closed, identity or sticky-Unknown invariant is violated by this scope. The proposed T4 qualification row remains deferred under [AGENTS.md:72](AGENTS.md:72); design acceptance does not authorize it.