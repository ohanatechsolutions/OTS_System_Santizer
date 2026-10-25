using System.Diagnostics;
using Microsoft.Win32;

namespace AegisPrime.Core;

/// <summary>Inventory of inspectable process and autorun references, not a rootkit detector.</summary>
public static class PersistenceInspector
{
    public static IReadOnlyList<ThreatFinding> Inspect()
    {
        var results = new List<ThreatFinding>();
        var keys = new[] { @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce" };
        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        foreach (var view in keys)
        {
            try
            {
                using var key = hive.OpenSubKey(view);
                if (key is null) continue;
                foreach (var name in key.GetValueNames())
                {
                    var command = key.GetValue(name)?.ToString() ?? "";
                    if (!IsUnusual(command)) continue;
                    results.Add(new ThreatFinding(FindingSeverity.Medium,
                        "Unusual startup command", "Windows startup registry",
                        name + ": " + command, hive.Name + "\\" + view, DateTimeOffset.Now));
                }
            }
            catch (Exception) { /* access-limited location; never claim complete coverage */ }
        }
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var file = process.MainModule?.FileName;
                    if (file is null || ThreatScanner.Heuristic(file) is not string why) continue;
                    results.Add(new ThreatFinding(FindingSeverity.Low, "Running file requires review",
                        "Process inventory (unverified)", why, file, DateTimeOffset.Now));
                }
                catch (Exception) { /* protected/inaccessible processes */ }
            }
        }
        return results.Take(300).ToArray();
    }

    private static bool IsUnusual(string command)
    {
        var lower = command.ToLowerInvariant();
        return (lower.Contains("\\temp\\") || lower.Contains("\\appdata\\local\\temp\\"))
            && (lower.Contains(".exe") || lower.Contains(".ps1") || lower.Contains(".vbs"));
    }
}
