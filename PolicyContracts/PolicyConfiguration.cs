namespace PolicyContracts;

public sealed class PolicyConfiguration
{
    public List<FilePolicyRule> FileRules { get; set; } = new();
    public List<IpPolicyRule> IpRules { get; set; } = new();
}
