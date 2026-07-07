using System.IO;
using PolicyContracts;
using PolicyService.Services;

namespace PolicyService;

public sealed class Worker(
    ILogger<Worker> logger,
    PolicyLoader policyLoader,
    PolicyValidator policyValidator,
    FileDriverClient fileDriverClient) : BackgroundService
{
    private FileSystemWatcher? _policyWatcher;
    private readonly SemaphoreSlim _reloadGate = new(1, 1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Policy service starting");

        try
        {
            fileDriverClient.Connect();
            logger.LogInformation("Driver connection established");

            await ApplyPolicyAsync(stoppingToken);

            StartPolicyWatcher();

            while (!stoppingToken.IsCancellationRequested)
            {
                logger.LogInformation("Policy service heartbeat at: {Time}", DateTimeOffset.UtcNow);
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            logger.LogInformation("Policy service stopping");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Fatal error while starting policy service");
            throw;
        }
        finally
        {
            _policyWatcher?.Dispose();
            _reloadGate.Dispose();
        }
    }

    private async Task ApplyPolicyAsync(CancellationToken cancellationToken)
    {
        var policy = await policyLoader.LoadAsync(cancellationToken);

        var validation = policyValidator.Validate(policy);

        if (!validation.IsValid)
        {
            foreach (string error in validation.Errors)
            {
                logger.LogError("Policy validation error: {Error}", error);
            }

            throw new InvalidOperationException("Policy validation failed.");
        }

        logger.LogInformation(
            "Policy loaded successfully with {FileRuleCount} file rules and {IpRuleCount} IP rules",
            policy.FileRules.Count,
            policy.IpRules.Count);

        string? allowedPattern =
            PolicyProjection.GetFirstFilePatternByAction(policy, PolicyAction.Allow);

        string? blockedPattern =
            PolicyProjection.GetFirstFilePatternByAction(policy, PolicyAction.Block);

        fileDriverClient.SendPolicySync(allowedPattern, blockedPattern);

        logger.LogInformation(
            "Sent policy sync to driver: allow={AllowPattern} block={BlockedPattern}",
            allowedPattern,
            blockedPattern);
    }

    private void StartPolicyWatcher()
    {
        string fullPath = policyLoader.PolicyFilePath;
        string directory = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("Policy file directory could not be resolved.");
        string fileName = Path.GetFileName(fullPath);

        _policyWatcher = new FileSystemWatcher(directory, fileName)
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
            IncludeSubdirectories = false,
            EnableRaisingEvents = true
        };

        _policyWatcher.Changed += OnPolicyFileChanged;
        _policyWatcher.Created += OnPolicyFileChanged;
        _policyWatcher.Renamed += OnPolicyFileChanged;
        _policyWatcher.Error += OnPolicyWatcherError;

        logger.LogInformation("Watching policy file for changes: {PolicyFilePath}", fullPath);
    }

    private void OnPolicyFileChanged(object sender, FileSystemEventArgs e)
    {
        _ = Task.Run(async () =>
        {
            if (!await _reloadGate.WaitAsync(0))
            {
                return;
            }

            try
            {
                await Task.Delay(500);

                logger.LogInformation(
                    "Policy file change detected: {ChangeType} {FullPath}",
                    e.ChangeType,
                    e.FullPath);

                await ApplyPolicyAsync(CancellationToken.None);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to hot-reload policy after file change");
            }
            finally
            {
                _reloadGate.Release();
            }
        });
    }

    private void OnPolicyWatcherError(object sender, ErrorEventArgs e)
    {
        logger.LogError(e.GetException(), "Policy watcher encountered an error");
    }
}