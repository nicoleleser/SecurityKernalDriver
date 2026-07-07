using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PolicyContracts;
using PolicyService.Models;

namespace PolicyService.Services;

public sealed class PolicyLoader(
    IOptions<PolicyFileOptions> policyOptions,
    IHostEnvironment hostEnvironment,
    ILogger<PolicyLoader> logger)
{
    private readonly string _resolvedPolicyFilePath =
        Path.Combine(hostEnvironment.ContentRootPath, policyOptions.Value.PolicyFilePath);

    public string PolicyFilePath => _resolvedPolicyFilePath;

    public async Task<PolicyConfiguration> LoadAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading policy from {PolicyFilePath}", _resolvedPolicyFilePath);

        if (!File.Exists(_resolvedPolicyFilePath))
        {
            throw new FileNotFoundException("Policy file not found", _resolvedPolicyFilePath);
        }

        string json = await File.ReadAllTextAsync(_resolvedPolicyFilePath, cancellationToken);

        PolicyConfiguration? policy = JsonSerializer.Deserialize<PolicyConfiguration>(
            json,
            new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

        if (policy is null)
        {
            throw new InvalidOperationException("Failed to deserialize policy file.");
        }

        logger.LogInformation(
            "Loaded policy: {FileRuleCount} file rules, {IpRuleCount} IP rules",
            policy.FileRules.Count,
            policy.IpRules.Count);

        return policy;
    }
}