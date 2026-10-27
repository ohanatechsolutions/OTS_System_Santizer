using System.Xml;
using System.Xml.Linq;
using System.Diagnostics;
using Microsoft.Win32;

namespace OTSSystemSanitizer.Core;

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
        results.AddRange(InspectServices());
        results.AddRange(InspectTasks());
        return results.DistinctBy(x => x.Title + "|" + x.Path + "|" + x.Evidence).Take(450).ToArray();
    }


    private static IReadOnlyList<ThreatFinding> InspectServices()
    {
        var results = new List<ThreatFinding>();
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (root is null) return results;
            foreach (var name in root.GetSubKeyNames())
            {
                try
                {
                    using var service = root.OpenSubKey(name);
                    var command = service?.GetValue("ImagePath")?.ToString() ?? "";
                    if (!IsUnusual(command)) continue;
                    results.Add(new ThreatFinding(FindingSeverity.Medium, "Unusual service command",
                        "Service registry (unverified)", name + ": " + command,
                        @"HKLM\SYSTEM\CurrentControlSet\Services\" + name, DateTimeOffset.Now));
                }
                catch { }
            }
        }
        catch { }
        return results;
    }

    private static IReadOnlyList<ThreatFinding> InspectTasks()
    {
        var results = new List<ThreatFinding>();
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        if (!Directory.Exists(root)) return results;
        try
        {
            foreach (var path in Directory.EnumerateFiles(root, "*", new EnumerationOptions
            { RecurseSubdirectories = true, IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint }).Take(7000))
            {
                try
                {
                    using var reader = XmlReader.Create(path, new XmlReaderSettings
                    {
                        DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
                        MaxCharactersInDocument = 1_000_000
                    });
                    var xml = XDocument.Load(reader);
                    foreach (var command in xml.Descendants().Where(x => x.Name.LocalName == "Command").Select(x => x.Value))
                    {
                        if (!IsUnusual(command)) continue;
                        results.Add(new ThreatFinding(FindingSeverity.Medium, "Unusual scheduled task command",
                            "Scheduled task XML (unverified)", command, path, DateTimeOffset.Now));
                    }
                }
                catch { }
            }
        }
        catch { }
        return results;
    }

    private static bool IsUnusual(string command)
    {
        var lower = command.ToLowerInvariant();
        return (lower.Contains("\\temp\\") || lower.Contains("\\appdata\\local\\temp\\"))
            && (lower.Contains(".exe") || lower.Contains(".ps1") || lower.Contains(".vbs"));
    }
}
