using System;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

// Independent notification observer. The real WPF process sends approval.
public sealed class StagedApprovalPipeProbe : IDisposable {
    readonly NamedPipeClientStream pipe;
    readonly StreamReader reader;
    readonly Task pump;
    readonly ConcurrentQueue<string> messages = new ConcurrentQueue<string>();
    volatile bool stopped;
    public StagedApprovalPipeProbe() {
        pipe = new NamedPipeClientStream(".","SafeUpload.Agent",PipeDirection.In,
            PipeOptions.Asynchronous);
        pipe.Connect(10000);
        reader = new StreamReader(pipe,new UTF8Encoding(false),false,1024,true);
        pump = Task.Run(async () => {
            try {
                for (;;) {
                    string line = await reader.ReadLineAsync();
                    if(line==null) break;
                    messages.Enqueue(line);
                }
            } catch(Exception) { if(!stopped) throw; }
        });
    }
    public string Next(int milliseconds) {
        var watch=System.Diagnostics.Stopwatch.StartNew();
        while(watch.ElapsedMilliseconds<milliseconds) {
            string line; if(messages.TryDequeue(out line)) return line;
            if(pump.IsFaulted) throw pump.Exception;
            Thread.Sleep(20);
        }
        return null;
    }
    public static string Justify(string transfer, string reason) {
        // Fixtures use ASCII, no embedded quotes or backslashes.
        if(transfer.IndexOfAny(new[]{'"','\\'})>=0 || reason.IndexOfAny(new[]{'"','\\','\r','\n'})>=0)
            throw new ArgumentException("Fixture escaping required");
        return Raw("{\"eventId\":\""+transfer+"\",\"justification\":\""+reason+"\"}\n");
    }
    public static string Raw(string request) {
        using(var client=new NamedPipeClientStream(".","SafeUpload.Agent.Justification",
            PipeDirection.InOut,PipeOptions.Asynchronous)) {
            client.Connect(3000);
            using(var output=new StreamWriter(client,new UTF8Encoding(false),1024,true)) {
                output.Write(request); output.Flush();
                using(var input=new StreamReader(client,new UTF8Encoding(false),false,1024,true)) {
                    var response=input.ReadLineAsync();
                    if(!response.Wait(5000)) throw new TimeoutException("Justification reply");
                    return response.Result;
                }
            }
        }
    }
    public sealed class IdleClients : IDisposable {
        readonly NamedPipeClientStream[] clients;
        public IdleClients(int count) {
            clients=new NamedPipeClientStream[count];
            try {
                for(int i=0;i<count;i++) {
                    clients[i]=new NamedPipeClientStream(".","SafeUpload.Agent.Justification",
                        PipeDirection.InOut,PipeOptions.Asynchronous);
                    clients[i].Connect(10000);
                }
            } catch { Dispose(); throw; }
        }
        public void Dispose() { foreach(var client in clients) if(client!=null) client.Dispose(); }
    }
    public void Dispose() {
        stopped=true; pipe.Dispose();
        try { pump.Wait(2000); } finally { reader.Dispose(); }
    }
}
