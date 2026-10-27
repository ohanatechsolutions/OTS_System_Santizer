using Microsoft.Win32;

namespace OTSSystemSanitizer.Core;

public sealed record InstalledApp(string Name, string Publisher, string Version, string InstallLocation,
    string UninstallCommand, long EstimatedBytes, string Status)
{
    public string Size => EstimatedBytes > 0 ? (EstimatedBytes / 1_048_576d).ToString("N1") + " MB" : "Unknown";
}

public static class InstalledAppsService
{
    public static IReadOnlyList<InstalledApp> Enumerate()
    {
        var apps = new List<InstalledApp>();
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var root = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (root is null) continue;
                foreach (var keyName in root.GetSubKeyNames())
                {
                    try
                    {
                        using var key = root.OpenSubKey(keyName);
                        var name = key?.GetValue("DisplayName")?.ToString()?.Trim();
                        if (string.IsNullOrWhiteSpace(name)) continue;
                        var publisher = key?.GetValue("Publisher")?.ToString() ?? "";
                        var version = key?.GetValue("DisplayVersion")?.ToString() ?? "";
                        var location = key?.GetValue("InstallLocation")?.ToString() ?? "";
                        var uninstall = key?.GetValue("UninstallString")?.ToString() ?? "";
                        var estimatedKb = key?.GetValue("EstimatedSize") is int n && n > 0 ? n : 0;
                        var status = "Registered installation";
                        if (uninstall.Length == 0) status = "No registered uninstaller";
                        if (location.Length > 0 && Path.IsPathRooted(location) && !Directory.Exists(location))
                            status = "Install location missing — review only";
                        apps.Add(new InstalledApp(name, publisher, version, location, uninstall,
                            (long)estimatedKb * 1024L, status));
                    }
                    catch { /* malformed entry */ }
                }
            }
            catch { /* inaccessible registry view */ }
        }
        return apps.GroupBy(a => (a.Name.ToUpperInvariant(), a.Publisher.ToUpperInvariant(), a.Version.ToUpperInvariant()))
            .Select(g => g.First()).OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
