using System.ComponentModel;
namespace SafeUpload.Agent.Service.Interception;
internal static class StagedSpaceFailure
{
    internal static bool IsSpace(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is StagedSpaceException || current is Win32Exception { NativeErrorCode: 39 or 112 or 1295 or 1816 } ||
                current is IOException && (current.HResult & 0xffff) is 39 or 112 or 1295 or 1816) return true;
        return false;
    }
}
