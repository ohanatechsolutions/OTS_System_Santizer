using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OTSSystemSanitizer.Core;

/// <summary>
/// User-scoped, AES-256-GCM encrypted vault. Per-item keys are wrapped with Windows DPAPI
/// for the current user. This is NOT a substitute for antivirus isolation or kernel protection.
/// </summary>
public sealed class QuarantineService
{
    private const int ChunkSize = 1024 * 1024;
    // Existing encrypted quarantine files use this permanent on-disk magic; do not change it for a rebrand.
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("AEGISQ2!");
    private readonly string _root;

    public QuarantineService(string? root = null)
    {
        var dataRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var current = Path.Combine(dataRoot, "OTSSystemSanitizer", "Quarantine");
        var legacy = Path.Combine(dataRoot, "AegisPrime", "Quarantine");
        // Absolute vault paths are stored in old encrypted manifests. Keep the old vault
        // in place for existing installations rather than breaking restore during a rebrand.
        _root = root ?? (Directory.Exists(legacy) ? legacy : current);
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
                if (item is not null && PathPolicy.IsWithin(item.VaultFile, _root) &&
                    File.Exists(item.VaultFile) && !string.IsNullOrWhiteSpace(item.ProtectedKey))
                    result.Add(item);
            }
            catch { /* malformed or inaccessible manifest; cannot trust it */ }
        }
        return result.OrderByDescending(x => x.QuarantinedAt).ToArray();
    }

    public QuarantinedFile Quarantine(string original)
    {
        if (!PathPolicy.CanQuarantine(original))
            throw new InvalidOperationException("Only accessible, non-reparse user-profile files can be quarantined.");
        var id = Guid.NewGuid().ToString("N");
        var stage = Path.Combine(_root, id + ".stage");
        var vault = Path.Combine(_root, id + ".aegq");
        var manifest = Path.Combine(_root, id + ".json");
        var info = new FileInfo(original);
        var lastWrite = info.LastWriteTimeUtc;
        var attributes = info.Attributes;
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            if (!PathPolicy.CanQuarantine(original)) throw new IOException("Source path changed.");
            File.Move(original, stage);
            var hash = EncryptFile(stage, vault, key);
            var protectedKey = Convert.ToBase64String(Dpapi.Protect(key));
            var entry = new QuarantinedFile(id, original, vault, hash, DateTimeOffset.UtcNow,
                protectedKey, lastWrite, attributes);
            File.WriteAllText(manifest, JsonSerializer.Serialize(entry));
            // Do not remove the plaintext original until encrypted contents and manifest exist.
            File.Delete(stage);
            return entry;
        }
        catch
        {
            try { if (File.Exists(stage) && !File.Exists(original)) File.Move(stage, original); } catch { }
            try { if (File.Exists(vault) && File.Exists(original)) File.Delete(vault); } catch { }
            try { if (File.Exists(manifest) && File.Exists(original)) File.Delete(manifest); } catch { }
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public void Restore(QuarantinedFile record)
    {
        if (record.Id.Length != 32 || record.Id.Any(c => !Uri.IsHexDigit(c)))
            throw new IOException("Invalid item ID.");
        var vault = Path.Combine(_root, record.Id + ".aegq");
        var manifest = Path.Combine(_root, record.Id + ".json");
        if (!Path.GetFullPath(vault).Equals(Path.GetFullPath(record.VaultFile), StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(vault) || !File.Exists(manifest) || PathPolicy.IsReparsePoint(vault))
            throw new IOException("Vault item not found or tampered with.");
        if (File.Exists(record.OriginalPath) ||
            !PathPolicy.IsWithin(record.OriginalPath, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)))
            throw new IOException("Original path is occupied or outside user scope.");
        var parent = Path.GetDirectoryName(record.OriginalPath) ??
            throw new IOException("Missing parent directory.");
        if (!Directory.Exists(parent) || PathPolicy.IsReparsePoint(parent))
            throw new IOException("Restore directory is missing or uses reparse points.");

        var key = Dpapi.Unprotect(Convert.FromBase64String(record.ProtectedKey));
        var temp = Path.Combine(parent, ".aegis-restore-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            DecryptFile(vault, temp, key, record.Sha256);
            if (File.Exists(record.OriginalPath) || PathPolicy.IsReparsePoint(parent))
                throw new IOException("Restore target changed.");
            File.SetLastWriteTimeUtc(temp, record.LastWriteUtc);
            File.Move(temp, record.OriginalPath);
            File.SetAttributes(record.OriginalPath, record.OriginalAttributes);
            File.Delete(vault);
            File.Delete(manifest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    private static string EncryptFile(string plaintextPath, string vaultPath, byte[] key)
    {
        var noncePrefix = RandomNumberGenerator.GetBytes(8);
        using var input = new FileStream(plaintextPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            ChunkSize, FileOptions.SequentialScan);
        using var output = new FileStream(vaultPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            ChunkSize, FileOptions.WriteThrough);
        using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        using var cipher = new AesGcm(key, 16);
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        writer.Write(Magic);
        writer.Write(noncePrefix);
        var block = new byte[ChunkSize];
        uint index = 0;
        int read;
        while ((read = input.Read(block, 0, block.Length)) > 0)
        {
            if (index == uint.MaxValue) throw new IOException("Vault nonce limit reached.");
            digest.AppendData(block, 0, read);
            var ciphertext = new byte[read];
            var tag = new byte[16];
            var nonce = MakeNonce(noncePrefix, index++);
            cipher.Encrypt(nonce, block.AsSpan(0, read), ciphertext, tag);
            writer.Write(read);
            writer.Write(ciphertext);
            writer.Write(tag);
        }
        writer.Flush();
        output.Flush(flushToDisk: true);
        CryptographicOperations.ZeroMemory(block);
        return Convert.ToHexString(digest.GetHashAndReset());
    }

    private static void DecryptFile(string vault, string outputPath, byte[] key, string expectedHash)
    {
        using var input = new FileStream(vault, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var reader = new BinaryReader(input, Encoding.UTF8, leaveOpen: true);
        if (!reader.ReadBytes(Magic.Length).SequenceEqual(Magic))
            throw new CryptographicException("Invalid quarantine format.");
        var prefix = reader.ReadBytes(8);
        if (prefix.Length != 8) throw new EndOfStreamException();
        using var output = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var cipher = new AesGcm(key, 16);
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        uint index = 0;
        while (input.Position < input.Length)
        {
            if (input.Length - input.Position < 4) throw new EndOfStreamException();
            int length = reader.ReadInt32();
            if (length < 1 || length > ChunkSize || index == uint.MaxValue)
                throw new CryptographicException("Invalid encrypted chunk length.");
            var ciphertext = reader.ReadBytes(length);
            var tag = reader.ReadBytes(16);
            if (ciphertext.Length != length || tag.Length != 16) throw new EndOfStreamException();
            var plaintext = new byte[length];
            cipher.Decrypt(MakeNonce(prefix, index++), ciphertext, tag, plaintext);
            digest.AppendData(plaintext);
            output.Write(plaintext);
            CryptographicOperations.ZeroMemory(plaintext);
        }
        output.Flush(flushToDisk: true);
        if (!Convert.ToHexString(digest.GetHashAndReset()).Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("Quarantine SHA-256 verification failed.");
    }

    private static byte[] MakeNonce(byte[] prefix, uint index)
    {
        var nonce = new byte[12];
        Buffer.BlockCopy(prefix, 0, nonce, 0, 8);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(nonce.AsSpan(8), index);
        return nonce;
    }
}

internal static class Dpapi
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Blob { public int Length; public IntPtr Data; }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptProtectData(ref Blob input, string? description,
        IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptUnprotectData(ref Blob input, IntPtr description,
        IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr handle);

    public static byte[] Protect(byte[] data) => Invoke(data, protect: true);
    public static byte[] Unprotect(byte[] data) => Invoke(data, protect: false);

    private static byte[] Invoke(byte[] data, bool protect)
    {
        var input = new Blob { Length = data.Length, Data = Marshal.AllocHGlobal(data.Length) };
        var output = new Blob();
        try
        {
            Marshal.Copy(data, 0, input.Data, data.Length);
            var ok = protect
                ? CryptProtectData(ref input, "OTS System Sanitizer quarantine key", IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows DPAPI operation failed.");
            var result = new byte[output.Length];
            Marshal.Copy(output.Data, result, 0, result.Length);
            return result;
        }
        finally
        {
            if (input.Data != IntPtr.Zero)
            {
                for (var i = 0; i < data.Length; i++) Marshal.WriteByte(input.Data, i, 0);
                Marshal.FreeHGlobal(input.Data);
            }
            if (output.Data != IntPtr.Zero) LocalFree(output.Data);
        }
    }
}
