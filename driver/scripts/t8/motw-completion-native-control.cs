// Unprotected native mechanism probe. Observations do not grant product authority.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.T8
{
    public sealed class MotwObserver : IDisposable
    {
        readonly string root;
        readonly Stopwatch clock;
        readonly Thread worker;
        readonly object gate = new object();
        readonly List<object> observations = new List<object>();
        readonly Dictionary<string, string> previous = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        volatile bool stopped;
        long polls;

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass,
            [Out] byte[] information, uint bytes);

        public MotwObserver(string root)
        {
            this.root = Path.GetFullPath(root);
            clock = Stopwatch.StartNew();
            worker = new Thread(Watch) { IsBackground = true };
            worker.Start();
        }

        public static string Identity(FileStream stream)
        {
            byte[] identity = new byte[24]; // FILE_ID_INFO: UINT64 volume + FILE_ID_128.
            if (!GetFileInformationByHandleEx(stream.SafeFileHandle, 18, identity, 24))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return Convert.ToBase64String(identity);
        }

        public static object State(string path)
        {
            try
            {
                using (FileStream file = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete))
                {
                    string identity = Identity(file), zone = null, zoneIdentity = null;
                    int zoneError = 0;
                    try
                    {
                        using (FileStream tag = new FileStream(path + ":Zone.Identifier", FileMode.Open,
                            FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                        {
                            zoneIdentity = Identity(tag);
                            if (tag.Length > 65536) throw new IOException("Probe tag capture bound exceeded.");
                            using (StreamReader reader = new StreamReader(tag, Encoding.UTF8, true)) zone = reader.ReadToEnd();
                        }
                    }
                    catch (IOException error) { zoneError = Marshal.GetHRForException(error) & 0xffff; }
                    using (FileStream after = new FileStream(path, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete))
                    {
                        return new { Identity = identity, SameObjectAfter = Identity(after) == identity,
                            Length = file.Length, Zone = zone, ZoneError = zoneError,
                            ZoneSameObject = zoneIdentity == null || zoneIdentity == identity, Error = 0 };
                    }
                }
            }
            catch (Exception error)
            {
                return new { Error = Marshal.GetHRForException(error) & 0xffff, Detail = error.Message };
            }
        }

        void Watch()
        {
            while (!stopped)
            {
                try
                {
                    foreach (string path in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
                    {
                        // The fresh Edge profile is outside this watched root.
                        string state = new JavaScriptSerializer().Serialize(State(path));
                        string old;
                        if (!previous.TryGetValue(path, out old) || old != state)
                        {
                            previous[path] = state;
                            lock (gate) observations.Add(new { Milliseconds = clock.Elapsed.TotalMilliseconds,
                                Event = "FileState", Path = path, State = state });
                        }
                    }
                    Interlocked.Increment(ref polls);
                }
                catch (Exception error) { Mark("ObserverError", error.Message); }
                Thread.Sleep(2);
            }
        }

        public void Mark(string name, object detail)
        {
            lock (gate) observations.Add(new { Milliseconds = clock.Elapsed.TotalMilliseconds, Event = name, Detail = detail });
        }
        public string Results()
        {
            lock (gate) return new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 }.Serialize(
                new { Polls = Interlocked.Read(ref polls), Frequency = Stopwatch.Frequency,
                    Timing = "observer receipt time; polling cannot prove first visibility or producer finality",
                    Observations = observations.ToArray() });
        }
        public void Dispose() { stopped = true; if (!worker.Join(10000)) throw new IOException("Observer did not stop."); }

        public static void SelfCheck()
        {
            var method = typeof(MotwObserver).GetMethod("GetFileInformationByHandleEx",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            if (method == null || method.ReturnType != typeof(bool) || method.GetParameters().Length != 4 ||
                method.GetParameters()[0].ParameterType != typeof(SafeFileHandle) ||
                method.GetParameters()[1].ParameterType != typeof(int) ||
                method.GetParameters()[2].ParameterType != typeof(byte[]) ||
                method.GetParameters()[3].ParameterType != typeof(uint)) throw new Exception("Native signature mismatch.");
            if (!Stopwatch.IsHighResolution || Stopwatch.Frequency <= 0) throw new Exception("Monotonic clock unavailable.");
            var map = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>("{\"id\":1,\"result\":{}}");
            if (Convert.ToInt32(map["id"]) != 1) throw new Exception("CDP JSON control failed.");
        }
    }

    public sealed class MotwDownload : IDisposable
    {
        readonly TcpListener listener;
        readonly Thread server;
        readonly List<string> failures = new List<string>();
        volatile bool stopped;
        public string Url { get; private set; }
        public long ServedBytes { get; private set; }
        public string[] Failures { get { lock (failures) return failures.ToArray(); } }
        public MotwDownload()
        {
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Url = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + "/artifact";
            server = new Thread(Serve) { IsBackground = true };
            server.Start();
        }
        void Serve()
        {
            while (!stopped)
            {
                try
                {
                    using (TcpClient client = listener.AcceptTcpClient())
                    using (NetworkStream stream = client.GetStream())
                    {
                        client.ReceiveTimeout = 10000; client.SendTimeout = 10000;
                        string request;
                        using (StreamReader reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true))
                        {
                            request = reader.ReadLine();
                            string line; do { line = reader.ReadLine(); } while (!String.IsNullOrEmpty(line));
                        }
                        if (request == null || !request.StartsWith("GET /artifact ", StringComparison.Ordinal))
                        {
                            byte[] missing = Encoding.ASCII.GetBytes("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                            stream.Write(missing, 0, missing.Length); continue;
                        }
                        const int length = 8 * 1024 * 1024;
                        byte[] header = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"edge-clean.txt\"\r\nContent-Length: " + length + "\r\nConnection: close\r\n\r\n");
                        stream.Write(header, 0, header.Length);
                        byte[] chunk = new byte[32768];
                        for (int i = 0; i < chunk.Length; ++i) chunk[i] = (byte)('a' + i % 26);
                        for (int offset = 0; offset < length; offset += chunk.Length)
                        {
                            stream.Write(chunk, 0, chunk.Length); ServedBytes += chunk.Length;
                            Thread.Sleep(2);
                        }
                    }
                }
                catch (Exception error) { if (!stopped) lock (failures) failures.Add(error.ToString()); }
            }
        }
        public void Dispose()
        {
            stopped = true; listener.Stop();
            if (!server.Join(15000)) throw new IOException("Loopback fixture server did not stop.");
        }
    }

    public sealed class MotwCdp : IDisposable
    {
        readonly ClientWebSocket socket = new ClientWebSocket();
        public MotwCdp(string address) { socket.ConnectAsync(new Uri(address), CancellationToken.None).GetAwaiter().GetResult(); }
        public void Send(string json)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            socket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true,
                CancellationToken.None).GetAwaiter().GetResult();
        }
        public string Receive(int milliseconds)
        {
            using (var deadline = new CancellationTokenSource(milliseconds))
            using (var text = new MemoryStream())
            {
                byte[] bytes = new byte[65536];
                WebSocketReceiveResult result;
                do
                {
                    result = socket.ReceiveAsync(new ArraySegment<byte>(bytes), deadline.Token).GetAwaiter().GetResult();
                    if (result.MessageType != WebSocketMessageType.Text) throw new IOException("Unexpected CDP message type.");
                    text.Write(bytes, 0, result.Count);
                    if (text.Length > 1024 * 1024) throw new IOException("CDP message bound exceeded.");
                } while (!result.EndOfMessage);
                return Encoding.UTF8.GetString(text.ToArray());
            }
        }
        public void Dispose() { socket.Dispose(); }
    }
}
