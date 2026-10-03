// Qualification fixture: open exactly one existing file after the parent permits it.
// Coordination uses events/stdout so the measured window creates no other file writers.
using System;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class SafeUploadWriterFixture
{
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
        byte[] information, uint bytes);

    public static int Main(string[] args)
    {
        if (args.Length != 4) return 2;
        try {
            using (EventWaitHandle start = EventWaitHandle.OpenExisting(args[1]))
            using (EventWaitHandle ready = EventWaitHandle.OpenExisting(args[2]))
            using (EventWaitHandle close = EventWaitHandle.OpenExisting(args[3])) {
                // Warm the identity buffer and console before injection starts.
                byte[] identity = new byte[24];
                using (SafeFileHandle warm = CreateFileW(args[0], 0x80, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
                    if (warm.IsInvalid || !GetFileInformationByHandleEx(warm, 18, identity, 24)) return 7;
                }
                Console.WriteLine("FixtureInitialized=True");
                Console.Out.Flush();
                if (!start.WaitOne(30000)) return 3;
                using (SafeFileHandle file = CreateFileW(args[0], 0xC0000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
                    int error = file.IsInvalid ? Marshal.GetLastWin32Error() : 0;
                    bool valid = !file.IsInvalid && GetFileInformationByHandleEx(file, 18, identity, 24);
                    if (!file.IsInvalid && !valid) error = Marshal.GetLastWin32Error();
                    Console.WriteLine("FixtureOpen=" + valid + ";Error=" + error + ";Identity=" + BitConverter.ToString(identity).Replace("-", ""));
                    Console.Out.Flush();
                    ready.Set();
                    if (!valid) return 4;
                    if (!close.WaitOne(30000)) return 5;
                }
                Console.WriteLine("FixtureClosed=True");
                return 0;
            }
        } catch (Exception error) {
            Console.Error.WriteLine(error.ToString());
            return 6;
        }
    }
}
