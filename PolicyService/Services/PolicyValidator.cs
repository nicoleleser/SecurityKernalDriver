using System.Net;
using PolicyContracts;

namespace PolicyService.Services;

public sealed class PolicyValidator
{
    public (bool IsValid, List<string> Errors) Validate(PolicyConfiguration policy)
    {
        List<string> errors = new();

        foreach (var rule in policy.FileRules)
        {
            if (string.IsNullOrWhiteSpace(rule.Pattern))
            {
                errors.Add("File rule pattern cannot be empty.");
                continue;
            }

            if (!Enum.IsDefined(typeof(PolicyAction), rule.Action))
            {
                errors.Add($"Invalid file rule action for pattern '{rule.Pattern}'.");
            }
        }

        foreach (var rule in policy.IpRules)
        {
            if (string.IsNullOrWhiteSpace(rule.CidrOrIp))
            {
                errors.Add("IP rule cannot be empty.");
                continue;
            }

            if (!Enum.IsDefined(typeof(PolicyAction), rule.Action))
            {
                errors.Add($"Invalid IP rule action for IP '{rule.CidrOrIp}'.");
            }

            if (!IsValidIpOrCidr(rule.CidrOrIp))
            {
                errors.Add($"Invalid IP/CIDR format: '{rule.CidrOrIp}'.");
            }
        }

        return (errors.Count == 0, errors);
    }

    private static bool IsValidIpOrCidr(string value)
    {
        if (IPAddress.TryParse(value, out _))
        {
            return true;
        }

        string[] parts = value.Split('/');
        if (parts.Length != 2)
        {
            return false;
        }

        if (!IPAddress.TryParse(parts[0], out _))
        {
            return false;
        }

        return int.TryParse(parts[1], out int prefix) && prefix >= 0 && prefix <= 32;
    }
}