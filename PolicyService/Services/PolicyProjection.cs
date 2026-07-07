using PolicyContracts;

namespace PolicyService.Services;

public static class PolicyProjection
{
    public static string? GetFirstFilePatternByAction(
        PolicyConfiguration policy,
        PolicyAction action)
    {
        foreach (var rule in policy.FileRules)
        {
            if (rule.Action != action)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(rule.Pattern))
            {
                continue;
            }

            string normalized = rule.Pattern.Replace('/', '\\');

            if (normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                normalized.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                normalized.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
            {
                return normalized;
            }
        }

        return null;
    }

    public static List<(string Pattern, PolicyAction Action)> GetAllFileRules(PolicyConfiguration policy)
    {
        return policy.FileRules
            .Where(r => !string.IsNullOrWhiteSpace(r.Pattern))
            .Select(r => (r.Pattern, r.Action))
            .ToList();
    }
}
