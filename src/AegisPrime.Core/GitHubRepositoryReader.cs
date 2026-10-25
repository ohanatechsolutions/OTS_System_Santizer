using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AegisPrime.Core;

/// <summary>
/// Multiple independent GitHub credentials, encrypted using Windows DPAPI for the current
/// Windows user. No credentials are sent anywhere except api.github.com over HTTPS.
/// </summary>
public sealed class GitHubAccountStore
{
    private readonly string _file;

    public GitHubAccountStore(string? path = null)
    {
        _file = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisPrime", "github-accounts.json");
    }

    public IReadOnlyList<string> Accounts => Load().Keys.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();

    public bool Contains(string login) => Load().ContainsKey(login);

    public void Save(string login, string token)
    {
        if (string.IsNullOrWhiteSpace(login) || login.Length > 100 ||
            string.IsNullOrWhiteSpace(token) || token.Length > 4096)
            throw new ArgumentException("Invalid GitHub account or credential.");

        var data = Load();
        var plaintext = Encoding.UTF8.GetBytes(token);
        try
        {
            data[login] = Convert.ToBase64String(Dpapi.Protect(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
        Persist(data);
    }

    public string GetToken(string login)
    {
        if (!Load().TryGetValue(login, out var protectedToken))
            throw new InvalidOperationException("GitHub account not connected.");
        var plaintext = Dpapi.Unprotect(Convert.FromBase64String(protectedToken));
        try { return Encoding.UTF8.GetString(plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public bool Remove(string login)
    {
        var data = Load();
        if (!data.Remove(login)) return false;
        Persist(data);
        return true;
    }

    private Dictionary<string, string> Load()
    {
        if (!File.Exists(_file)) return new(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (new FileInfo(_file).Length > 1024 * 1024)
                throw new InvalidDataException("Unexpectedly large credential store.");
            var loaded = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(_file))
                ?? throw new InvalidDataException("Empty credential store.");
            return new Dictionary<string, string>(loaded, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException)
        {
            throw new IOException("Could not read GitHub account storage. It may be damaged.", ex);
        }
    }

    private void Persist(Dictionary<string, string> data)
    {
        var directory = Path.GetDirectoryName(_file) ?? throw new IOException("Invalid credential path.");
        Directory.CreateDirectory(directory);
        var temporary = _file + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(data));
            File.Move(temporary, _file, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }
}

public sealed record GitHubRepository(string Account, string FullName, string Owner, string Name,
    bool Private, string DefaultBranch)
{
    public string Visibility => Private ? "Private" : "Public";
}

public sealed record GitHubDirectoryEntry(string Name, string Path, string Type, long Size)
{
    public string Kind => Type == "dir" ? "Folder" : Type == "file" ? "File" : Type;
    public string SizeLabel => Type == "file" ? (Size / 1024d).ToString("N1") + " KB" : "";
}

/// <summary>Read-only GitHub REST operations. Every URL is anchored to api.github.com.</summary>
public static class GitHubRepositoryReader
{
    private static readonly HttpClient Client = new(new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = TimeSpan.FromSeconds(35)
    };

    public static async Task<string> VerifyAccountAsync(string token, CancellationToken cancellationToken = default)
    {
        using var json = await RequestAsync("user", token, cancellationToken);
        var login = json.RootElement.GetProperty("login").GetString();
        if (string.IsNullOrWhiteSpace(login))
            throw new InvalidOperationException("GitHub did not return an account name.");
        return login;
    }

    public static async Task<IReadOnlyList<GitHubRepository>> ListRepositoriesAsync(
        string account, string token, CancellationToken cancellationToken = default)
    {
        var list = new List<GitHubRepository>();
        for (int page = 1; page <= 50; page++)
        {
            using var json = await RequestAsync(
                "user/repos?affiliation=owner%2Ccollaborator%2Corganization_member&per_page=100&page=" + page,
                token, cancellationToken);
            var array = json.RootElement;
            if (array.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Unexpected GitHub repository response.");
            foreach (var item in array.EnumerateArray())
            {
                var owner = item.GetProperty("owner").GetProperty("login").GetString() ?? "";
                var name = item.GetProperty("name").GetString() ?? "";
                var branch = item.GetProperty("default_branch").GetString() ?? "main";
                if (owner.Length == 0 || name.Length == 0) continue;
                list.Add(new GitHubRepository(account, item.GetProperty("full_name").GetString() ?? owner + "/" + name,
                    owner, name, item.GetProperty("private").GetBoolean(), branch));
            }
            if (array.GetArrayLength() < 100) return list;
        }
        throw new InvalidOperationException("This account exceeds the 5,000-repository browsing limit.");
    }

    public static async Task<IReadOnlyList<GitHubDirectoryEntry>> ListContentsAsync(
        GitHubRepository repo, string path, string token, CancellationToken cancellationToken = default)
    {
        var endpoint = ContentsEndpoint(repo, path);
        using var json = await RequestAsync(endpoint, token, cancellationToken);
        if (json.RootElement.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException("The selected location is not a folder.");
        var list = new List<GitHubDirectoryEntry>();
        foreach (var item in json.RootElement.EnumerateArray())
        {
            var type = item.GetProperty("type").GetString() ?? "";
            if (type is not ("dir" or "file")) continue; // do not follow symlinks or submodules
            var entryPath = item.GetProperty("path").GetString() ?? "";
            list.Add(new GitHubDirectoryEntry(item.GetProperty("name").GetString() ?? "",
                entryPath, type, item.GetProperty("size").GetInt64()));
        }
        return list.OrderBy(x => x.Type == "dir" ? 0 : 1)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static async Task<string> ReadTextFileAsync(
        GitHubRepository repo, string path, string token, CancellationToken cancellationToken = default)
    {
        using var json = await RequestAsync(ContentsEndpoint(repo, path), token, cancellationToken);
        var root = json.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.GetProperty("type").GetString() != "file")
            throw new InvalidOperationException("Select a file to read.");
        var size = root.GetProperty("size").GetInt64();
        if (size > 1024 * 1024)
            throw new InvalidOperationException("File is over the 1 MB preview limit.");
        if (root.GetProperty("encoding").GetString() != "base64")
            throw new InvalidOperationException("GitHub did not provide text-preview content.");
        var encoded = root.GetProperty("content").GetString() ?? "";
        var bytes = Convert.FromBase64String(encoded);
        if (Array.IndexOf(bytes, (byte)0) >= 0)
            throw new InvalidOperationException("Binary files cannot be previewed.");
        return Encoding.UTF8.GetString(bytes);
    }

    private static string ContentsEndpoint(GitHubRepository repo, string path)
    {
        // Only use GitHub-provided owner/repository/path identifiers and escape each segment.
        static string Encode(string value) => Uri.EscapeDataString(value);
        var endpoint = "repos/" + Encode(repo.Owner) + "/" + Encode(repo.Name) + "/contents";
        if (!string.IsNullOrEmpty(path))
        {
            var parts = path.Split('/');
            if (parts.Any(part => part.Length == 0 || part is "." or ".."))
                throw new ArgumentException("Invalid repository path.");
            endpoint += "/" + string.Join("/", parts.Select(Encode));
        }
        return endpoint + "?ref=" + Encode(repo.DefaultBranch);
    }

    private static async Task<JsonDocument> RequestAsync(string endpoint, string token, CancellationToken cancel)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("https://api.github.com/" + endpoint));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
        request.Headers.UserAgent.ParseAdd("AegisPrime/0.1");
        using var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancel);
        if (!response.IsSuccessStatusCode)
        {
            var reason = response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => "Credential expired, revoked, or invalid.",
                HttpStatusCode.Forbidden => "Access denied, organization SSO required, or rate limit exceeded.",
                HttpStatusCode.NotFound => "Repository or file not accessible to this account.",
                HttpStatusCode.TooManyRequests => "GitHub rate limit exceeded.",
                _ => "Please check GitHub availability and account permissions."
            };
            throw new InvalidOperationException("GitHub returned HTTP " +
                (int)response.StatusCode + ". " + reason);
        }
        await using var stream = await response.Content.ReadAsStreamAsync(cancel);
        return await JsonDocument.ParseAsync(stream, cancellationToken: cancel);
    }
}
