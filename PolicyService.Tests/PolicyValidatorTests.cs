using PolicyContracts;
using PolicyService.Services;

namespace PolicyService.Tests;

public sealed class PolicyValidatorTests
{
    private readonly PolicyValidator _validator = new();

    [Fact]
    public void Validate_Returns_Valid_For_Good_Policy()
    {
        PolicyConfiguration policy = new()
        {
            FileRules =
            [
                new FilePolicyRule { Pattern = @"C:\Windows\System32\notepad.exe", Action = PolicyAction.Allow },
                new FilePolicyRule { Pattern = @"C:\Windows\System32\cmd.exe", Action = PolicyAction.Block }
            ],
            IpRules =
            [
                new IpPolicyRule { CidrOrIp = "8.8.8.8", Action = PolicyAction.Block },
                new IpPolicyRule { CidrOrIp = "10.0.0.0/8", Action = PolicyAction.Allow }
            ]
        };

        var result = _validator.Validate(policy);
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Validate_Returns_Error_For_Empty_FileRule_Pattern()
    {
        PolicyConfiguration policy = new()
        {
            FileRules =
            [
                new FilePolicyRule { Pattern = "", Action = PolicyAction.Allow }
            ],
            IpRules = []
        };

        var result = _validator.Validate(policy);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("File rule pattern"));
    }

    [Fact]
    public void Validate_Returns_Error_For_Invalid_IpRule_Value()
    {
        PolicyConfiguration policy = new()
        {
            FileRules = [],
            IpRules =
            [
                new IpPolicyRule { CidrOrIp = "potato", Action = PolicyAction.Block }
            ]
        };

        var result = _validator.Validate(policy);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Invalid IP/CIDR format"));
    }
}
