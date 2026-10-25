using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.Service.Diagnostics;

internal enum CommunicationLogStage { DispatchCycle, Heartbeat, InitialPolicy, PolicyRefresh }

/// <summary>Keep transport-controlled text and exception objects out of integration log records.</summary>
internal static class CommunicationLog
{
    internal static void Warning(ILogger logger, CommunicationLogStage stage, Exception exception)
    {
        int? status = exception is HttpRequestException request && request.StatusCode is { } code ? (int)code : null;
        logger.LogWarning(new EventId(3201, "CommunicationFailure"),
            "Falha de integração do agente. Stage={Stage}; Failure={Failure}; HResult={HResult}; Status={Status}. Nova tentativa em segundo plano; consultar diagnósticos de comunicação/fila.",
            stage, Classify(exception), exception.HResult, status);
    }

    // A cycle can fail on local queue I/O as well as HTTP; do not label every IOException a network failure.
    private static string Classify(Exception exception) => exception switch
    {
        IOException => "IoError",
        UnauthorizedAccessException => "AccessDenied",
        _ => CommunicationObservation.Classify(exception).ToString()
    };
}
