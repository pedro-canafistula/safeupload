using SafeUpload.Agent.App.Notifications;

// Exercise the production application's client without an interactive desktop.
// This bridge neither inspects nor authorizes; the actual service decides.
if (args.Length != 2) return 2;
try
{
    await JustificationPipeClient.SendAsync(args[0], args[1]);
    Console.WriteLine("ActualApplicationJustificationClientAccepted=True");
    return 0;
}
catch (Exception ex)
{
    Console.WriteLine("ActualApplicationJustificationClientRejected=" + ex.GetType().Name);
    return 1;
}
