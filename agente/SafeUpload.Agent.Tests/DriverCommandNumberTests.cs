using System.Reflection;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

// M2 MVP row mvpACDord1: DiagnosticsCommand.StageStreams reused 29 (ControlCommand.StageDispose), so the driver answered
// every stage disposal as a malformed diagnostics query and no released version was ever deleted.
public sealed class DriverCommandNumberTests
{
    [Fact]
    public void Control_and_diagnostics_commands_never_share_a_number_across_different_commands()
    {
        var byNumber = new Dictionary<uint, HashSet<string>>();
        foreach (var type in new[] { typeof(ControlCommand), typeof(DiagnosticsCommand) })
            foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.Static)
                         .Where(f => f.IsLiteral && f.FieldType == typeof(uint)))
            {
                uint number = (uint)field.GetRawConstantValue()!;
                if (!byNumber.TryGetValue(number, out var names)) byNumber[number] = names = new HashSet<string>();
                names.Add(field.Name);
            }
        Assert.All(byNumber, entry => Assert.True(entry.Value.Count == 1,
            $"Command {entry.Key} is shared by {string.Join(", ", entry.Value)}"));
        Assert.Equal(29u, ControlCommand.StageDispose);
        Assert.NotEqual(ControlCommand.StageDispose, DiagnosticsCommand.StageStreams);
    }
}
