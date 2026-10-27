using OTSSystemSanitizer.Core;
using System.Text;

static void Check(bool result, string message)
{
    if (!result) throw new Exception("FAIL: " + message);
    Console.WriteLine("PASS: " + message);
}

Console.WriteLine("OTS System Sanitizer local policy and recovery smoke tests.");
var temp = Path.Combine(Path.GetTempPath(), "OTSSystemSanitizerTest-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temp);
try
{
    var fake = Path.Combine(temp, "invoice.pdf.exe");
    File.WriteAllText(fake, "test fixture, not executable");
    Check(ThreatScanner.Heuristic(fake)?.Contains("double extension") == true, "Deceptive extension detection");
    Check(ThreatScanner.Heuristic(Path.Combine(temp, "notes.txt")) is null, "Ordinary text not flagged");
    var explanation = ThreatInvestigator.Explain(new ThreatFinding(FindingSeverity.Medium,
        "File requires review", "Local heuristic (unverified)",
        "Executable uses a deceptive double extension", fake, DateTimeOffset.UtcNow));
    Check(explanation.Contains("Windows uses the final extension"),
        "Investigation describes the exact evidence without claiming a confirmed infection");
    Check(PathPolicy.IsWithin(fake, temp), "Contained path accepted");
    Check(!PathPolicy.IsWithin(temp + "-other\x5cfile.exe", temp), "Sibling prefix traversal rejected");

    var cleanup = Path.Combine(temp, "old.tmp");
    File.WriteAllText(cleanup, "cleanup test");
    File.SetLastWriteTimeUtc(cleanup, DateTime.UtcNow.AddDays(-10));
    // PathPolicy only allows actual user temp roots; no Windows servicing locations.
    var candidate = new CleanupCandidate(cleanup, CleanupService.UserTemp, new FileInfo(cleanup).Length,
        new FileInfo(cleanup).LastWriteTimeUtc, false);
    Check(PathPolicy.IsWithin(cleanup, Path.GetTempPath()), "Cleanup test under user temp root");
    Check(CleanupService.IsEligible(candidate), "Old user-temp file eligible");
    Check(!CleanupService.IsEligible(candidate with { Category = "Windows component store" }),
        "System cleanup category is never eligible");

    var changed = candidate with { SizeBytes = candidate.SizeBytes + 1 };
    Check(CleanupService.RemoveSelected(new[] { changed }).Removed == 0,
        "Changed file never deleted");
    var removed = CleanupService.RemoveSelected(new[] { candidate });
    Check(removed.Removed == 1 && !File.Exists(cleanup), "Reviewed temp file can be removed");

    var vault = new QuarantineService(Path.Combine(temp, "vault"));
    Check(PathPolicy.CanQuarantine(fake), "User-profile file eligible for limited quarantine");
    var record = vault.Quarantine(fake);
    Check(!File.Exists(fake) && File.Exists(record.VaultFile), "Encrypted quarantine created");
    Check(!System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(record.VaultFile)).Contains("test fixture, not executable"),
        "Vault does not contain source plaintext");
    Check(!string.IsNullOrWhiteSpace(record.ProtectedKey), "Vault key is DPAPI-protected");
    Check(vault.List().Any(x => x.Id == record.Id), "Quarantine manifest discovered");
    vault.Restore(record);
    Check(File.Exists(fake) && !File.Exists(record.VaultFile), "Restore round-trip succeeds");

    var toDestroy = vault.Quarantine(fake, explanation);
    Check(vault.List().Single(x => x.Id == toDestroy.Id).Investigation == explanation,
        "Investigation evidence preserved in vault manifest");
    Check(ThreatInvestigator.QuarantineReport(toDestroy).Contains(toDestroy.Sha256),
        "Investigation view includes immutable source SHA-256");
    vault.Destroy(toDestroy);
    Check(!File.Exists(fake) && !File.Exists(toDestroy.VaultFile) && !vault.List().Any(),
        "Encrypted vault item and manifest removed by explicit destruction");


    Console.WriteLine("All smoke tests passed.");
}
finally
{
    try { Directory.Delete(temp, recursive: true); } catch { }
}
