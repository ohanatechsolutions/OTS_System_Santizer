using System.Diagnostics;
using System.Text;

namespace AegisPrime.Core;

/// <summary>Uses the installed Windows Defender cmdlets. A failed invocation is never reported as clean.</summary>
public static class DefenderIntegration
{
    public static async Task<string> RunScanAsync(ScanMode mode, CancellationToken ct)
    {
        var type = mode == ScanMode.Quick ? "QuickScan" : "FullScan";
        var command = "Start-MpScan -ScanType " + type + " -ErrorAction Stop";
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            }
        };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-Command", command })
            process.StartInfo.ArgumentList.Add(argument);
        try
        {
            if (!process.Start()) return "Defender was not started; antivirus coverage unverified.";
            using var registration = ct.Register(() =>
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            });
            var error = process.StandardError.ReadToEndAsync(ct);
            var output = process.StandardOutput.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);
            var stderr = await error;
            _ = await output;
            if (process.ExitCode == 0)
                return "Microsoft Defender " + type + " command completed successfully. Review Windows Security for remediation and threat history.";
            return "Microsoft Defender scan unavailable or failed (exit " + process.ExitCode + "): " +
                (stderr.Length > 350 ? stderr[..350] : stderr);
        }
        catch (OperationCanceledException)
        {
            return "Aegis Prime stopped waiting for Defender. Defender may continue scanning independently.";
        }
        catch (Exception ex)
        {
            return "Defender could not be launched (" + ex.GetType().Name + "). Local inspection is not antivirus protection.";
        }
    }
    /// <summary>Prior Defender detections are history, not proof of current compromise.</summary>
    public static async Task<IReadOnlyList<ThreatFinding>> GetDetectionHistoryAsync(CancellationToken ct)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo("powershell.exe")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true } };
        const string command = "Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | " +
            "Select-Object -First 40 ThreatID,InitialDetectionTime,Resources | ConvertTo-Json -Compress -Depth 4";
        foreach (var part in new[] { "-NoProfile", "-NonInteractive", "-Command", command })
            process.StartInfo.ArgumentList.Add(part);
        try
        {
            if (!process.Start()) return Array.Empty<ThreatFinding>();
            using var registration = ct.Register(() =>
            { try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { } });
            var output = process.StandardOutput.ReadToEndAsync(ct);
            var error = process.StandardError.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);
            var json = await output;
            _ = await error;
            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(json)) return Array.Empty<ThreatFinding>();
            using var document = System.Text.Json.JsonDocument.Parse(json);
            var root = document.RootElement;
            var data = root.ValueKind == System.Text.Json.JsonValueKind.Array
                ? root.EnumerateArray().ToArray() : new[] { root };
            var findings = new List<ThreatFinding>();
            foreach (var item in data)
            {
                if (item.ValueKind != System.Text.Json.JsonValueKind.Object) continue;
                var id = item.TryGetProperty("ThreatID", out var i) ? i.ToString() : "unknown";
                var resource = item.TryGetProperty("Resources", out var r) ? r.ToString() : "Not provided";
                if (resource.Length > 700) resource = resource[..700];
                findings.Add(new ThreatFinding(FindingSeverity.Information,
                    "Defender detection history (past event)", "Microsoft Defender history",
                    "Threat ID: " + id + "; resources: " + resource +
                    ". Check Windows Security / Protection history for its current disposition.",
                    "Windows Security / Protection history", DateTimeOffset.Now));
            }
            return findings;
        }
        catch (Exception) { return Array.Empty<ThreatFinding>(); }
    }

}
