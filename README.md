# ThreatLocker Assessment – File Policy MVP

This project implements a Windows file-policy MVP using a file system minifilter driver and a .NET Worker Service.

## What it does

- Intercepts executable file opens in a Windows minifilter
- Applies allow/block policy in kernel mode
- Sends runtime policy updates from user mode to kernel mode
- Sends file events from the driver back to the service
- Supports hot policy reload from JSON
- Logs activity in structured form
- Includes unit tests for user-space policy validation and projection logic

## Solution structure

- `FilePolicyFilter`  
  Windows minifilter driver for file interception and enforcement

- `PolicyService`  
  .NET Worker Service that loads policy, validates it, syncs it to the driver, and receives file events

- `PolicyService.Tests`  
  Unit tests for policy projection and validation logic

- `PolicyContracts`  
  Shared policy models

## Current behavior

The driver intercepts file create/open requests and checks executable targets against policy.

Policy is loaded in user mode from JSON and sent to the driver through a minifilter communication port.

The current MVP supports:
- exact executable-style rules
- wildcard-capable path/pattern matching in kernel
- allow-before-block behavior
- runtime policy updates without rebooting


## Build and run

### Driver
1. Build the `FilePolicyFilter` project
2. Copy the generated `.sys` to `C:\Windows\System32\drivers\`
3. Reload the minifilter with:

```cmd
fltmc unload FilePolicyFilter
fltmc load FilePolicyFilter
fltmc filters
```

### Service
Run the service from:

```cmd
PolicyService\bin\Debug\net10.0\PolicyService.exe
```

or use Visual Studio.

## Testing

Run unit tests with:

```cmd
dotnet test
```

## Status

File-policy MVP: **working**

Network/WFP filtering: **not yet implemented**
