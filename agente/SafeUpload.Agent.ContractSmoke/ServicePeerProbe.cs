using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Infrastructure;

internal static class ServicePeerProbe
{
    internal static async Task RunAsync(string expectedImage)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(expectedImage)) throw new InvalidOperationException("Windows service image required.");
        using var current = WindowsIdentity.GetCurrent();
        var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        byte[] sidBytes = new byte[admin.BinaryLength];
        admin.GetBinaryForm(sidBytes, 0);
        var pin = GCHandle.Alloc(sidBytes, GCHandleType.Pinned);
        SafeAccessTokenHandle restricted;
        try
        {
            var disabled = new SidAndAttributes { Sid = pin.AddrOfPinnedObject() };
            // Deny-only Administrators SID and disable all privileges except traverse.
            if (!CreateRestrictedToken(current.AccessToken, 1, 1, ref disabled, 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted))
                throw new InvalidOperationException("Could not create restricted test token.");
        }
        finally { pin.Free(); }
        using (restricted)
        {
            await WindowsIdentity.RunImpersonatedAsync(restricted, async () =>
            {
                using var effective = WindowsIdentity.GetCurrent();
                if (effective.IsSystem || new WindowsPrincipal(effective).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new InvalidOperationException("Probe must have no effective administrator membership.");
                using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                using var pipe = new NamedPipeClientStream(".", NotificationProtocol.PipeName, PipeDirection.In, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(budget.Token);
                ServicePipePeer.RequireConnectedService(pipe, expectedImage);
                bool wrongImageRejected = false;
                try { ServicePipePeer.RequireConnectedService(pipe, Path.Combine(Path.GetDirectoryName(expectedImage)!, "unrelated", "SafeUpload.Agent.Service.exe")); }
                catch (IOException) { wrongImageRejected = true; }
                if (!wrongImageRejected) throw new InvalidOperationException("Unrelated image was accepted.");
                using var reader = new StreamReader(pipe, NotificationProtocol.Encoding);
                var first = NotificationProtocol.Deserialize((await reader.ReadLineAsync(budget.Token))!);
                if (first is not StatusNotification) throw new InvalidOperationException("Verified service did not send status.");
                Console.WriteLine("PeerVerified=True;EffectiveAdministrator=False;WrongImageRejected=True;ContentSent=False");
            });
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateRestrictedToken(SafeAccessTokenHandle token, uint flags, uint disableSidCount,
        ref SidAndAttributes disabled, uint deletePrivilegeCount, IntPtr privileges,
        uint restrictedSidCount, IntPtr restrictedSids, out SafeAccessTokenHandle result);
}
