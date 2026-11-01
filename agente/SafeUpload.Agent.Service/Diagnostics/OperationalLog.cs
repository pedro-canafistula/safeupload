using System.ComponentModel;
using System.Globalization;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Diagnostics;

/// <summary>Trusted, constant operation templates only. Never forward exception objects or arbitrary object formatting.</summary>
internal static class OperationalLog
{
    internal const string OmittedPath = "[caminho omitido]";
    internal const string OmittedValue = "[metadado omitido]";

    internal static void LogSafeWarning(this ILogger logger, Exception error, string template, params object?[] values) => Failure(logger, LogLevel.Warning, error, template, values);
    internal static void LogSafeError(this ILogger logger, Exception error, string template, params object?[] values) => Failure(logger, LogLevel.Error, error, template, values);
    internal static void LogSafeCritical(this ILogger logger, Exception error, string template, params object?[] values) => Failure(logger, LogLevel.Critical, error, template, values);
    internal static void LogSafeDebug(this ILogger logger, Exception error, string template, params object?[] values) => Failure(logger, LogLevel.Debug, error, template, values);
    internal static void LogSafeWarning(this ILogger logger, string template, params object?[] values) => Write(logger, LogLevel.Warning, template, values);
    internal static void LogSafeInformation(this ILogger logger, string template, params object?[] values) => Write(logger, LogLevel.Information, template, values);
    internal static void LogSafeDebug(this ILogger logger, string template, params object?[] values) => Write(logger, LogLevel.Debug, template, values);

    internal static string DescribeFailure(Exception error)
    {
        var (type, native, status) = Details(error);
        return string.Create(CultureInfo.InvariantCulture, $"Type={type}; HResult=0x{error.HResult:X8}; NativeError={native}; HttpStatus={status}");
    }

    private static void Failure(ILogger logger, LogLevel level, Exception error, string template, object?[] values)
    {
        if (!logger.IsEnabled(level)) return;
        var (type, native, status) = Details(error);
        // Sanitize before adding trusted diagnostic fields. No Message, StackTrace, Data or inner exception is emitted.
        var safe = Prepare(ref template, values);
        logger.Log(level, new EventId(3301, "AgentOperationalFailure"),
            template + " Type={FailureType}; HResult=0x{HResult:X8}; NativeError={NativeError}; HttpStatus={HttpStatus}.",
            [.. safe, type, error.HResult, native, status]);
    }

    private static void Write(ILogger logger, LogLevel level, string template, object?[] values)
    {
        if (!logger.IsEnabled(level)) return;
        var safe = Prepare(ref template, values);
        logger.Log(level, template, safe);
    }

    private static (string Type, int? Native, int? Status) Details(Exception error)
    {
        // Closed labels prevent custom exception names/ToString from becoming an uncontrolled field.
        string type = error switch
        {
            OperationCanceledException => "OperationCanceled", TimeoutException => "Timeout",
            UnauthorizedAccessException => "AccessDenied", Win32Exception => "Win32Error",
            FileNotFoundException => "FileNotFound", DirectoryNotFoundException => "DirectoryNotFound",
            PathTooLongException => "PathTooLong", InvalidDataException => "InvalidData",
            JsonException => "InvalidJson", HttpRequestException => "HttpRequest",
            IOException => "IoError", ArgumentException => "InvalidArgument",
            InvalidOperationException => "InvalidOperation", _ => "UnexpectedError"
        };
        int? native = null, status = null;
        Exception? item = error;
        // Follow at most eight links, retaining only numeric codes.
        for (int depth = 0; depth < 8 && item is not null; depth++, item = item.InnerException)
        {
            if (native is null && item is Win32Exception windows) native = windows.NativeErrorCode;
            if (status is null && item is HttpRequestException { StatusCode: { } code }) status = (int)code;
        }
        return (type, native, status);
    }

    private static object?[] Prepare(ref string template, object?[] values)
    {
        var fields = Fields(template);
        if (fields is null || fields.Count != values.Length || values.Length > 32)
        {
            template = "Operational log fields omitted: invalid template/argument count.";
            return [];
        }
        var safe = new object?[values.Length];
        for (int i = 0; i < values.Length; i++) safe[i] = Value(fields[i], values[i]);
        return safe;
    }

    private static List<string>? Fields(string template)
    {
        var fields = new List<string>();
        for (int i = 0; i < template.Length; i++)
        {
            char c = template[i];
            if (c is not ('{' or '}')) continue;
            if (i + 1 < template.Length && template[i + 1] == c) { i++; continue; }
            if (c == '}') return null;
            int end = template.IndexOf('}', i + 1);
            if (end < 0) return null;
            string field = template[(i + 1)..end];
            if (field.Length == 0 || field.Contains('{')) return null;
            fields.Add(field.Split(new[] { ':', ',' })[0].Trim());
            i = end;
        }
        return fields;
    }

    private static object? Value(string field, object? value)
    {
        if (value is null) return null;
        if (field is "Path" or "Arquivo" or "Pasta" or "FileName" or "Folder" or "HandbackPath" or "DestinationPath" or "NtPath") return OmittedPath;
        if (value is string text)
        {
            if (text.Length > AuditTextPrivacy.MaximumTextLength) return AuditTextPrivacy.Oversized;
            // A public certificate fingerprint is an identifier, not a free-text field.
            if (field == "Thumbprint" && text.Length is 40 or 64 && text.All(Uri.IsHexDigit)) return text;
            if (field == "Method" && text is not ("GET" or "HEAD" or "POST" or "PUT" or "PATCH" or "DELETE" or "OPTIONS" or "CONNECT" or "TRACE"))
                return OmittedValue;
            if (text.StartsWith('/') || text.Contains('\\') || text.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
                (text.Length > 1 && char.IsAsciiLetter(text[0]) && text[1] == ':')) return OmittedPath;
            if (Uri.TryCreate(text, UriKind.Absolute, out var uri))
                return uri.Scheme is "http" or "https"
                    ? AuditTextPrivacy.Sanitize(new UriBuilder(uri.Scheme, uri.Host, uri.Port).Uri.GetLeftPart(UriPartial.Authority))
                    : OmittedValue;
            return AuditTextPrivacy.Sanitize(text);
        }
        return value is bool or char or byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal
            or Guid or TimeSpan or DateTime or DateTimeOffset or Enum ? value : OmittedValue;
    }
}
