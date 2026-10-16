using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;
var root=Path.GetFullPath(args[0]); Directory.CreateDirectory(root);
string hot=Path.Combine(root,"journal"); var journal=new StagedTransferJournal(hot);
var sink=new LocalQueueAuditSink(Path.Combine(root,"queue.jsonl"));
var inspection=new InspectionService(new LocalPolicyStore(Path.Combine(root,"policy.json")),sink,ExtractorRegistry.CreateDefault(),new VerdictCache());
using var record=new NotificationRecord(Path.Combine(root,"notifications"),NullLogger.Instance,NotificationRecord.RetainedSegmentBytes,"fixture",true);
var hub=new NotificationHub(record,NullLogger<NotificationHub>.Instance,TimeProvider.System);
var publisher=new StagedTransferPublisher(inspection,hub,journal,root,new Gate());
string digest=new('A',64);
var times=new List<double[]>();
for(int i=1;i<=10000;i++) {
 var id=Guid.NewGuid();string path=Path.Combine(root,id.ToString("N")+".txt"); File.WriteAllText(path,"clean");
 var transfer=new StagedTransfer(id,path,Path.Combine(root,"destination-"+(i%8)+".txt"),DestinationKind.RemovableDrive,"fixture",1234,1);
 var timer=Stopwatch.StartNew();
 var created=await journal.CreateAsync(transfer,default);double create=timer.Elapsed.TotalMilliseconds;timer.Restart();
 await journal.SealAsync(id,transfer.ProcessId,path,default);double seal=timer.Elapsed.TotalMilliseconds;timer.Restart();
 await publisher.RecoverBoundReceiptsAsync(default);await publisher.RecoverJournalProgressAsync(default);await publisher.DisposeReleasedStagesAsync(default);await publisher.ArchiveCompletedTransfersAsync(default);await journal.ValidateArchivedSliceAsync(default);await journal.ReadPendingAsync(default);double maintenance=timer.Elapsed.TotalMilliseconds;timer.Restart();
 await journal.TransitionAsync(id,TransferJournalState.Sealed,TransferJournalState.Inspecting,null,default);
 await journal.TransitionAsync(id,TransferJournalState.Inspecting,TransferJournalState.Approved,digest,default);
 await journal.TransitionAsync(id,TransferJournalState.Approved,TransferJournalState.Publishing,digest,default);
 var intent=await journal.ReadAsync(id,default);await journal.CommitUnboundPublicationAsync(intent,()=>{},default);await journal.CompleteConfirmedPublicationAsync(intent,default);
 double publish=timer.Elapsed.TotalMilliseconds;timer.Restart();
 await sink.WriteAsync(new AuditEvent(id,DateTimeOffset.UtcNow,"fixture","fixture",path,".txt",5,Verdict.Approved,[],[],"fixture",1234,transfer.DestinationPath,null,1,1,false),default);
 hub.RecordOnly(new TransferNotification(id,Path.GetFileName(transfer.DestinationPath),TransferPhase.Released,PublishedSha256Hex:digest),1);
 File.Delete(path);await journal.CompleteReleasedStageDisposalAsync(StagedTransferJournal.VersionIdentity(intent),default);await journal.ArchiveCompletedAsync(await journal.ReadAsync(id,default),default);
 double finish=timer.Elapsed.TotalMilliseconds;timer.Restart();
 if(args.Length>1 && args[1]=="recent") {
  await sink.WriteAsync(new AuditEvent(Guid.NewGuid(),DateTimeOffset.UtcNow,"fixture","observer",path,".txt",5,Verdict.Approved,[],[],"powershell",2345,transfer.DestinationPath,null,1,1,false),default);
  await sink.ReadRecentAsync(5,default);
 }
 double announce=timer.Elapsed.TotalMilliseconds;times.Add([create,seal,maintenance,publish,finish,announce]);
 if(i%500==0)Console.WriteLine(JsonSerializer.Serialize(new{cycle=i,hot=Directory.GetFiles(hot,"*.json").Length,archived=journal.ArchivedTransfers,mean=Enumerable.Range(0,6).Select(c=>times.TakeLast(100).Average(t=>t[c])).ToArray()}));
}
class Gate:IStagedPublicationGate{public IDisposable Authorize(StagedTransfer t,string p,string d)=>throw new Exception();public bool DisposeStage(Guid id,uint outcome,uint renames)=>false;}
