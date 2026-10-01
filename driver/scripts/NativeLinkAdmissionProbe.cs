// Standalone, unfiltered NTFS reproduction. No driver installation or internal API.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class NativeLinkAdmissionProbe {
    [StructLayout(LayoutKind.Sequential)]
    struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int cls, byte[] info, int size);
    [DllImport("ntdll.dll")]
    static extern int NtSetInformationFile(SafeFileHandle file, out IoStatus io,
        byte[] info, uint length, int cls);
    static SafeFileHandle Open(string path, uint access, uint share) {
        var file=CreateFile(path,access,share,IntPtr.Zero,3,0x80,IntPtr.Zero);
        if(file.IsInvalid) { int error=Marshal.GetLastWin32Error(); file.Dispose(); throw new Win32Exception(error); }
        return file;
    }
    static byte[] Id(SafeFileHandle file) {
        var info=new byte[24]; if(!GetFileInformationByHandleEx(file,18,info,info.Length))
            throw new Win32Exception(Marshal.GetLastWin32Error()); return info;
    }
    static int Link(SafeFileHandle file, string target) {
        byte[] name=Encoding.Unicode.GetBytes(@"\??\"+target);
        int header=IntPtr.Size==8 ? 20 : 12;
        var info=new byte[header+name.Length+2];
        BitConverter.GetBytes(name.Length).CopyTo(info,header-4); name.CopyTo(info,header);
        IoStatus io; return NtSetInformationFile(file,out io,info,(uint)info.Length,11);
    }
    public static void Run(string directory) {
        Directory.CreateDirectory(directory);
        uint[] guards={0x80,0x80000000}; // attributes-only versus read-data capability
        uint[] sources={0,0x80,0x80000000,0x40000000,0x10000};
        foreach(uint guardAccess in guards) foreach(uint sourceAccess in sources) {
            int expectedOpen=guardAccess==0x80000000 && sourceAccess==0x10000 ? 32 : 0;
            string tag=guardAccess.ToString("X8")+"-"+sourceAccess.ToString("X8");
            string original=Path.Combine(directory,tag+".txt"), alias=Path.Combine(directory,tag+"-alias.txt");
            File.WriteAllText(original,"disposable link admission fixture");
            try {
                using(var guard=Open(original,guardAccess,3)) { // deny FILE_SHARE_DELETE
                    Console.WriteLine("INPUT GuardAccess=0x{0:X8} GuardShare=3 SourceAccess=0x{1:X8} SourceShare=7 FileLinkInformation=11 Replace=False",guardAccess,sourceAccess);
                    try {
                        using(var source=Open(original,sourceAccess,7)) {
                            if(expectedOpen!=0) throw new Exception("Expected delete-sharing control was admitted");
                            int status=Link(source,alias);
                            bool same=false;
                            if(status==0) using(var linked=Open(alias,0x80,7))
                                same=Convert.ToBase64String(Id(source))==Convert.ToBase64String(Id(linked));
                            Console.WriteLine("RESULT SourceOpen=0 LinkNtStatus=0x{0:X8} SamePhysicalIdentity={1}",status,same);
                            if(status!=0 || !same) throw new Exception("Observed native link-admission contract changed");
                        }
                    } catch(Win32Exception error) {
                        Console.WriteLine("RESULT SourceOpen={0} LinkNotIssued=True",error.NativeErrorCode);
                        if(error.NativeErrorCode!=expectedOpen) throw;
                    }
                }
            } finally { if(File.Exists(alias)) File.Delete(alias); File.Delete(original); }
        }
    }
    public static int Main(string[] args) {
        if(args.Length!=1) return 2;
        try { Run(args[0]); return 0; } catch(Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
