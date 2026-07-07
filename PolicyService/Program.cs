using PolicyService;
using PolicyService.Models;
using PolicyService.Services;
using Serilog;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();

builder.Logging.ClearProviders();
builder.Services.AddSerilog(Log.Logger, dispose: true);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "ThreatLockerAssessment Policy Service";
});

builder.Services.Configure<PolicyFileOptions>(options =>
{
    options.PolicyFilePath = "Policies\\policy.sample.allow.json";
});

builder.Services.AddSingleton<PolicyLoader>();
builder.Services.AddSingleton<FileDriverClient>();
builder.Services.AddSingleton<PolicyValidator>();
builder.Services.AddHostedService<Worker>();

IHost host = builder.Build();
host.Run();