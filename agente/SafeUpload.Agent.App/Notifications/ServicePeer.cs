using System.IO;
using System.IO.Pipes;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.App.Notifications;

internal static class ServicePeer
{
    internal static void Require(NamedPipeClientStream pipe) => ServicePipePeer.RequireConnectedService(pipe,
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "service", "SafeUpload.Agent.Service.exe")));
}
