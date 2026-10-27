namespace OTSSystemSanitizer.Core;

/// <summary>Conservative path rules. These checks are not a privileged security boundary.</summary>
public static class PathPolicy
{
    private static readonly StringComparison Cmp = StringComparison.OrdinalIgnoreCase;

    public static bool IsWithin(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(root)) return false;
        try
        {
            var p = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
            var r = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
            return p.StartsWith(r + Path.DirectorySeparatorChar, Cmp);
        }
        catch (Exception) { return false; }
    }

    public static bool IsReparsePoint(string path)
    {
        try
        {
            for (var current = Path.GetFullPath(path); !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current) ?? "")
            {
                if (!File.Exists(current) && !Directory.Exists(current)) return true;
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return true;
                var parent = Path.GetDirectoryName(current);
                if (parent == current || parent is null) break;
            }
            return false;
        }
        catch { return true; }
    }

    public static bool CanQuarantine(string path)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (IsWithin(path, windows) || IsWithin(path, programFiles) || IsWithin(path, programFilesX86)) return false;
        if (IsWithin(path, Path.Combine(appData, "OTSSystemSanitizer")) ||
            IsWithin(path, Path.Combine(appData, "AegisPrime"))) return false; // Legacy vault protection
        return IsWithin(path, profile) && File.Exists(path) && !IsReparsePoint(path);
    }
}
