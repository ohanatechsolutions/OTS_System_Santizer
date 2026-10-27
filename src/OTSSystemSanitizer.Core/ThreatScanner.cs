using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.Channels;

namespace OTSSystemSanitizer.Core;

/// <summary>Bounded, read-only filesystem analysis; findings are heuristics, never AV verdicts.</summary>
public static class ThreatScanner
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".scr", ".com", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".dll" };
    private static readonly string[] DoubleExtensions = { ".pdf.exe", ".jpg.exe", ".png.exe", ".doc.exe", ".txt.exe", ".zip.exe", ".pdf.scr", ".jpg.scr" };

    public static string? Heuristic(string path)
    {
        var name = Path.GetFileName(path);
        if (DoubleExtensions.Any(x => name.EndsWith(x, StringComparison.OrdinalIgnoreCase)))
            return "Executable uses a deceptive double extension; investigate before opening.";
        if (!ExecutableExtensions.Contains(Path.GetExtension(path))) return null;
        var temp = Path.GetTempPath();
        if (PathPolicy.IsWithin(path, temp))
            return "Executable or script located in a user-writable temporary directory.";
        return null;
    }

    public static async Task<ScanReport> RunAsync(ScanMode mode, IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.Now;
        long files = 0, bytes = 0;
        int skipped = 0, recorded = 0;
        var findings = new ConcurrentQueue<ThreatFinding>();
        var roots = GetRoots(mode);
        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(512)
        { FullMode = BoundedChannelFullMode.Wait, SingleWriter = true, SingleReader = false });
        var options = new EnumerationOptions
        { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        var producer = Task.Run(async () =>
        {
            try
            {
                foreach (var root in roots)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!Directory.Exists(root)) continue;
                    try
                    {
                        foreach (var path in Directory.EnumerateFiles(root, "*", options))
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            await channel.Writer.WriteAsync(path, cancellationToken);
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception) { Interlocked.Increment(ref skipped); }
                }
            }
            finally { channel.Writer.TryComplete(); }
        }, cancellationToken);

        var workerCount = Math.Clamp(Environment.ProcessorCount / 2, 2, 6);
        var workers = Enumerable.Range(0, workerCount).Select(_ => Task.Run(async () =>
        {
            await foreach (var path in channel.Reader.ReadAllAsync(cancellationToken))
            {
                try
                {
                    var info = new FileInfo(path);
                    if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    Interlocked.Add(ref bytes, info.Length);
                    var reason = Heuristic(path);
                    if (reason is not null && Interlocked.Increment(ref recorded) <= 750)
                    {
                        var evidence = reason;
                        if (info.Length <= 100 * 1024 * 1024)
                        {
                            try
                            {
                                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                                    FileShare.ReadWrite | FileShare.Delete, 65_536, FileOptions.SequentialScan);
                                var hash = await SHA256.HashDataAsync(stream, cancellationToken);
                                evidence += " SHA-256: " + Convert.ToHexString(hash);
                            }
                            catch (OperationCanceledException) { throw; }
                            catch { evidence += " Hash unavailable."; }
                        }
                        findings.Enqueue(new ThreatFinding(
                            path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && reason.Contains("double extension")
                                ? FindingSeverity.Medium : FindingSeverity.Low,
                            "File requires review", "Local heuristic (unverified)", evidence, path, DateTimeOffset.Now));
                    }
                    var n = Interlocked.Increment(ref files);
                    if (n % 256 == 0)
                        progress?.Report(new ScanProgress(n, Interlocked.Read(ref bytes), Volatile.Read(ref skipped), path, "Inspecting files"));
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception) { Interlocked.Increment(ref skipped); }
            }
        }, cancellationToken)).ToArray();

        bool cancelled = false;
        try { await Task.WhenAll(workers.Prepend(producer)); }
        catch (OperationCanceledException) { cancelled = true; }
        progress?.Report(new ScanProgress(Interlocked.Read(ref files), Interlocked.Read(ref bytes),
            skipped, "", cancelled ? "Cancelled" : "Complete"));
        return new ScanReport(mode, started, DateTimeOffset.Now, files, bytes, skipped, cancelled,
            findings.OrderByDescending(x => x.Severity).ToArray(), "Not requested");
    }

    public static IReadOnlyList<string> GetRoots(ScanMode mode)
    {
        if (mode == ScanMode.Deep)
            return DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
                .Select(d => d.RootDirectory.FullName).ToArray();

        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        return new[] { Path.GetTempPath(), Path.Combine(local, "Temp"),
            Path.Combine(roaming, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            downloads }.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
