using PolicyContracts;
using PolicyService.Services;
using Xunit;

namespace PolicyService.Tests;

public sealed class PolicyProjectionTests
{
    [Fact]
    public void GetFirstExactExecutableByAction_Returns_First_Exact_Allow_Exe()
    {
        PolicyConfiguration policy = new()
        {
            FileRules =
            [
                new FilePolicyRule { Pattern = @"C:\Windows\System32\notepad.exe", Action = PolicyAction.Allow },
                new FilePolicyRule { Pattern = @"C:\Windows\System32\cmd.exe", Action = PolicyAction.Block }
            ],
            IpRules = []
        };

        string? result = PolicyProjection.GetFirstFilePatternByAction(policy, PolicyAction.Allow);
        Assert.Equal("notepad.exe", result);
    }

    [Fact]
    public void GetFirstExactExecutableByAction_Returns_First_Exact_Block_Exe()
    {
        PolicyConfiguration policy = new()
        {
            FileRules =
            [
                new FilePolicyRule { Pattern = @"C:\Windows\System32\notepad.exe", Action = PolicyAction.Allow },
                new FilePolicyRule { Pattern = @"C:\Windows\System32\cmd.exe", Action = PolicyAction.Block }
            ],
            IpRules = []
        };

        string? result = PolicyProjection.GetFirstFilePatternByAction(policy, PolicyAction.Block);
        Assert.Equal("cmd.exe", result);
    }

    [Fact]
    public void GetFirstExactExecutableByAction_Ignores_Wildcards()
    {
        PolicyConfiguration policy = new()
        {
            FileRules =
            [
                new FilePolicyRule { Pattern = @"C:\Temp\*.exe", Action = PolicyAction.Block },
                new FilePolicyRule { Pattern = @"C:\Windows\System32\cmd.exe", Action = PolicyAction.Block }
            ],
            IpRules = []
        };

        string? result = PolicyProjection.GetFirstFilePatternByAction(policy, PolicyAction.Block);
        Assert.Equal("cmd.exe", result);
    }

    [Fact]
    public void GetFirstExactExecutableByAction_Returns_Null_When_No_Exact_Exe_Match_Exists()
    {
        PolicyConfiguration policy = new()
        {
            FileRules =
            [
                new FilePolicyRule { Pattern = @"C:\Temp\*.exe", Action = PolicyAction.Block }
            ],
            IpRules = []
        };

        string? result = PolicyProjection.GetFirstFilePatternByAction(policy, PolicyAction.Block);

        Assert.Null(result);
    }
}