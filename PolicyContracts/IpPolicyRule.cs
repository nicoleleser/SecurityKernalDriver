namespace PolicyContracts;

public sealed class IpPolicyRule
{
    public string CidrOrIp { get; set; } = string.Empty;
    public PolicyAction Action { get; set; }
}