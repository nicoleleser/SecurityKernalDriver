namespace PolicyContracts;

public sealed class FilePolicyRule
{
    public string Pattern { get; set; } = string.Empty;
    public PolicyAction Action { get; set; }
}