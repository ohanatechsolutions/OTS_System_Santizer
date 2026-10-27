namespace OTSSystemSanitizer.Core;

public enum ScanMode { Quick, Deep }
public enum FindingSeverity { High, Medium, Low, Information }

public sealed record ThreatFinding(
    FindingSeverity Severity,
    string Title,
    string Source,
    string Evidence,
    string Path,
    DateTimeOffset ObservedAt)
{
    public string Level => Severity.ToString();
}

public sealed record ScanProgress(long Files, long Bytes, int Skipped, string CurrentPath, string Phase);
public sealed record ScanReport(
    ScanMode Mode, DateTimeOffset Started, DateTimeOffset Finished,
    long Files, long Bytes, int Skipped, bool Cancelled,
    IReadOnlyList<ThreatFinding> Findings, string AntivirusResult)
{
    public TimeSpan Elapsed => Finished - Started;
}

public sealed record CleanupCandidate(string Path, string Category, long SizeBytes,
    DateTime LastWriteUtc, bool OptInRequired)
{
    public string SizeLabel => SizeBytes >= 1_073_741_824 ? (SizeBytes / 1_073_741_824d).ToString("N2") + " GB" :
        SizeBytes >= 1_048_576 ? (SizeBytes / 1_048_576d).ToString("N2") + " MB" :
        (SizeBytes / 1024d).ToString("N1") + " KB";
}

public sealed record CleanupResult(int Removed, long BytesRemoved, IReadOnlyList<string> Failures);
public sealed record QuarantinedFile(string Id, string OriginalPath, string VaultFile,
    string Sha256, DateTimeOffset QuarantinedAt, string ProtectedKey,
    DateTime LastWriteUtc, FileAttributes OriginalAttributes, string? Investigation = null);
