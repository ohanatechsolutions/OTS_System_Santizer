using System.Security.Cryptography;
using System.Text.Json;

namespace AegisPrime.Core;

/// <summary>
/// Basic user-scoped quarantine: rename/move into private app folder, preserve manifest and hash.
/// This is not an encrypted or kernel-enforced malware isolation system.
/// </summary>
public sealed class QuarantineService
{
    private readonly string _root;
    public QuarantineService(string? root = null)
    {
        _root = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisPrime", "Quarantine");
        Directory.CreateDirectory(_root);
    }

    public IReadOnlyList<QuarantinedFile> List()
    {
        var result = new List<QuarantinedFile>();
        foreach (var path in Directory.EnumerateFiles(_root, "*.json"))
        {
            try
            {
                var item = JsonSerializer.Deserialize<QuarantinedFile>(File.ReadAllText(path));
                if (item is not null && PathPolicy.IsWithin(item.VaultFile, _root)) result.Add(item);
            }
            catch { }
        }
        return result.OrderByDescending(i => i.QuarantinedAt).ToArray();
    }

    public QuarantinedFile Quarantine(string original)
    {
        if (!PathPolicy.CanQuarantine(original))
            throw new InvalidOperationException("Only accessible, user-profile files outside protected locations may be quarantined.");
        var id = Guid.NewGuid().ToString("N");
        var destination = Path.Combine(_root, id + ".blocked");
        string sha;
        using (var stream = File.Open(original, FileMode.Open, FileAccess.Read, FileShare.Read))
            sha = Convert.ToHexString(SHA256.HashData(stream));
        // Revalidate immediately before moving; untrusted elevated operations are not implemented.
        if (!PathPolicy.CanQuarantine(original)) throw new IOException("Source changed.");
        File.Move(original, destination);
        var record = new QuarantinedFile(id, original, destination, sha, DateTimeOffset.Now);
        try
        {
            File.WriteAllText(Path.Combine(_root, id + ".json"), JsonSerializer.Serialize(record));
            File.SetAttributes(destination, FileAttributes.Hidden);
        }
        catch
        {
            try { File.Move(destination, original); } catch { }
            throw;
        }
        return record;
    }

    public void Restore(QuarantinedFile record)
    {
        if (!PathPolicy.IsWithin(record.VaultFile, _root) || !File.Exists(record.VaultFile))
            throw new IOException("Quarantine item is missing or outside the vault.");
        if (File.Exists(record.OriginalPath))
            throw new IOException("Original path is occupied; cannot overwrite.");
        if (!PathPolicy.IsWithin(record.OriginalPath, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)))
            throw new IOException("Restore target is outside user profile.");
        if (PathPolicy.IsReparsePoint(Path.GetDirectoryName(record.OriginalPath) ?? ""))
            throw new IOException("Restore destination traverses a symbolic link or reparse point.");
        using (var stream = File.OpenRead(record.VaultFile))
        {
            var current = Convert.ToHexString(SHA256.HashData(stream));
            if (!current.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Quarantine content failed integrity check.");
        }
        File.SetAttributes(record.VaultFile, FileAttributes.Normal);
        Directory.CreateDirectory(Path.GetDirectoryName(record.OriginalPath)!);
        File.Move(record.VaultFile, record.OriginalPath);
        File.Delete(Path.Combine(_root, record.Id + ".json"));
    }
}
