namespace OTSSystemSanitizer.Core;

/// <summary>User-profile-only cleanup. Never directly deletes Windows servicing/cache directories.</summary>
public static class CleanupService
{
    public const string UserTemp = "Old user temp";
    public const string CrashDumps = "Old crash dumps";
    public const string BrowserCache = "Browser cache (opt-in)";

    public static IReadOnlyList<CleanupCandidate> Discover(bool includeBrowserCache = false, int limit = 20000)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roots = new List<(string Root, string Category, bool OptIn)>
        {
            (Path.GetTempPath(), UserTemp, false),
            (Path.Combine(local, "CrashDumps"), CrashDumps, false)
        };
        if (includeBrowserCache)
        {
            roots.Add((Path.Combine(local, "Google", "Chrome", "User Data", "Default", "Cache"), BrowserCache, true));
            roots.Add((Path.Combine(local, "Microsoft", "Edge", "User Data", "Default", "Cache"), BrowserCache, true));
        }
        var candidates = new List<CleanupCandidate>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (root, category, optIn) in roots)
        {
            if (!Directory.Exists(root) || PathPolicy.IsReparsePoint(root)) continue;
            try
            {
                foreach (var path in Directory.EnumerateFiles(root, "*",
                    new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true,
                        AttributesToSkip = FileAttributes.ReparsePoint }))
                {
                    if (candidates.Count >= limit) return candidates;
                    if (!visited.Add(path) || !PathPolicy.IsWithin(path, root)) continue;
                    try
                    {
                        var file = new FileInfo(path);
                        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0
                            || file.LastWriteTimeUtc > DateTime.UtcNow.AddDays(-7)) continue;
                        candidates.Add(new CleanupCandidate(path, category, file.Length, file.LastWriteTimeUtc, optIn));
                    }
                    catch (Exception) { /* deleted or unavailable during enumeration */ }
                }
            }
            catch (Exception) { /* locked directory; leave untouched */ }
        }
        return candidates.OrderByDescending(x => x.SizeBytes).ToArray();
    }

    public static bool IsEligible(CleanupCandidate candidate)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var root = candidate.Category switch
        {
            UserTemp => Path.GetTempPath(),
            CrashDumps => Path.Combine(local, "CrashDumps"),
            BrowserCache when candidate.OptInRequired =>
                PathPolicy.IsWithin(candidate.Path, Path.Combine(local, "Google", "Chrome", "User Data", "Default", "Cache"))
                    ? Path.Combine(local, "Google", "Chrome", "User Data", "Default", "Cache")
                    : Path.Combine(local, "Microsoft", "Edge", "User Data", "Default", "Cache"),
            _ => ""
        };
        return root.Length > 0 && PathPolicy.IsWithin(candidate.Path, root)
            && !PathPolicy.IsReparsePoint(candidate.Path);
    }

    public static CleanupResult RemoveSelected(IEnumerable<CleanupCandidate> selected)
    {
        var failures = new List<string>();
        long bytes = 0;
        int count = 0;
        foreach (var candidate in selected)
        {
            try
            {
                if (!IsEligible(candidate)) throw new InvalidOperationException("Protected or unexpected path.");
                var info = new FileInfo(candidate.Path);
                if (!info.Exists || info.Length != candidate.SizeBytes ||
                    info.LastWriteTimeUtc != candidate.LastWriteUtc)
                    throw new InvalidOperationException("File changed since review; rescan first.");
                if (info.LastWriteTimeUtc > DateTime.UtcNow.AddDays(-7))
                    throw new InvalidOperationException("File is no longer old enough.");
                File.Delete(candidate.Path);
                bytes += info.Length;
                count++;
            }
            catch (Exception ex) { failures.Add(candidate.Path + ": " + ex.Message); }
        }
        return new CleanupResult(count, bytes, failures);
    }
}
