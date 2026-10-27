using System.Diagnostics;
using System.IO;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using OTSSystemSanitizer.Core;

namespace OTSSystemSanitizer.Desktop;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ThreatFinding> _findings = new();
    private readonly ObservableCollection<CleanupRow> _cleanup = new();
    private readonly ObservableCollection<QuarantinedFile> _quarantine = new();
    private readonly ObservableCollection<InstalledApp> _apps = new();
    private readonly QuarantineService _vault = new();
    private CancellationTokenSource? _scanCancellation;
    private bool _busy;
    private bool _batchSelectingCleanup;
    private readonly GitHubAccountStore _gitHubStore = new();
    private readonly ObservableCollection<GitHubRepository> _gitHubRepos = new();
    private readonly ObservableCollection<GitHubDirectoryEntry> _gitHubContents = new();
    private readonly List<GitHubRepository> _gitHubRepoCache = new();
    private GitHubRepository? _gitHubCurrentRepo;
    private string _gitHubCurrentPath = "";
    private bool _gitHubBusy;

    public MainWindow()
    {
        InitializeComponent();
        ThreatList.ItemsSource = _findings;
        CleanupList.ItemsSource = _cleanup;
        QuarantineList.ItemsSource = _quarantine;
        InstalledAppList.ItemsSource = _apps;
        GitHubRepoList.ItemsSource = _gitHubRepos;
        GitHubContentsList.ItemsSource = _gitHubContents;
        try { LoadGitHubAccounts(); }
        catch (Exception ex) { GitHubStatus.Text = "Account store error: " + ex.Message; }
        RefreshVault();
        Log("Application started; no threats assumed absent until relevant scans complete.");
    }

    private void Log(string message)
    {
        ActivityLog.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + message + Environment.NewLine);
        ActivityLog.ScrollToEnd();
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        QuickButton.IsEnabled = !busy;
        DeepButton.IsEnabled = !busy;
        CancelButton.IsEnabled = busy;
        CleanAndSecureButton.IsEnabled = !busy;
    }

    private async void Quick_Click(object sender, RoutedEventArgs e) => await ScanAsync(ScanMode.Quick);
    private async void Deep_Click(object sender, RoutedEventArgs e) => await ScanAsync(ScanMode.Deep);

    private async Task ScanAsync(ScanMode mode)
    {
        if (_busy) return;
        SetBusy(true);
        _findings.Clear();
        FindingCount.Text = "0";
        FilesCount.Text = "0";
        ScanBar.IsIndeterminate = true;
        _scanCancellation = new CancellationTokenSource();
        var token = _scanCancellation.Token;
        var progress = new Progress<ScanProgress>(p =>
        {
            FilesCount.Text = p.Files.ToString("N0");
            ScanStatus.Text = p.Phase + " — " + p.Files.ToString("N0") + " files; " +
                p.Skipped.ToString("N0") + " access/scan errors";
        });
        Log("Started " + mode + " system inspection.");
        try
        {
            var fileTask = ThreatScanner.RunAsync(mode, progress, token);
            var persistenceTask = Task.Run(PersistenceInspector.Inspect, token);
            var defenderTask = DefenderIntegration.RunScanAsync(mode, token);
            var report = await fileTask;
            foreach (var finding in report.Findings) _findings.Add(finding);
            try
            {
                var persistence = await persistenceTask;
                foreach (var finding in persistence) _findings.Add(finding);
            }
            catch (OperationCanceledException) { }
            var antivirus = await defenderTask;
            foreach (var pastDetection in await DefenderIntegration.GetDetectionHistoryAsync(token))
                _findings.Add(pastDetection);
            FindingCount.Text = _findings.Count.ToString("N0");
            ScanStatus.Text = report.Cancelled ? "Inspection cancelled: report is partial."
                : "Inspection finished. Review findings and antivirus coverage.";
            CoverageStatus.Text = antivirus + (report.Skipped > 0 ? " Some files were inaccessible." : "");
            Log("Inspected " + report.Files.ToString("N0") + " files. " + _findings.Count +
                " review items. " + antivirus);
        }
        catch (OperationCanceledException)
        {
            ScanStatus.Text = "Scan cancelled; coverage incomplete.";
            Log("Scan cancelled.");
        }
        catch (Exception ex)
        {
            ScanStatus.Text = "Scan failed; coverage incomplete.";
            Log("Scan error: " + ex.Message);
        }
        finally
        {
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            ScanBar.IsIndeterminate = false;
            ScanBar.Value = 0;
            SetBusy(false);
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _scanCancellation?.Cancel();
        Log("Cancellation requested.");
    }

    private async void Analyze_Click(object sender, RoutedEventArgs e) => await AnalyzeAsync();

    private async Task AnalyzeAsync()
    {
        if (_busy) return;
        ScanStatus.Text = "Analyzing eligible storage. No files will be removed.";
        Log("Beginning storage analysis.");
        try
        {
            var includeBrowser = BrowserCacheCheck.IsChecked == true;
            var items = await Task.Run(() => CleanupService.Discover(includeBrowser));
            foreach (var row in _cleanup) row.PropertyChanged -= CleanupRow_PropertyChanged;
            _cleanup.Clear();
            foreach (var item in items)
            {
                var row = new CleanupRow(item);
                row.PropertyChanged += CleanupRow_PropertyChanged;
                _cleanup.Add(row);
            }
            var total = items.Sum(x => x.SizeBytes);
            SpaceCount.Text = ToSize(total);
            UpdateCleanupSelection();
            Log(items.Count + " eligible files totaling " + ToSize(total) +
                ". Reported bytes are not guaranteed space reclaimed.");
        }
        catch (Exception ex) { Log("Cleanup analysis failed: " + ex.Message); }
    }

    private async void CleanAndSecure_Click(object sender, RoutedEventArgs e)
    {
        await ScanAsync(ScanMode.Quick);
        await AnalyzeAsync();
        if (_cleanup.Count > 0)
        {
            MainTabs.SelectedIndex = 1;
            MessageBox.Show(this, "Review the cleanup list and check specific files before using Delete checked files. " +
                "OTS System Sanitizer never deletes items merely because you clicked Clean & Secure.",
                "Review required", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void SelectAllCleanup_Click(object sender, RoutedEventArgs e)
    {
        var selectAll = SelectAllCleanupCheck.IsChecked == true;
        _batchSelectingCleanup = true;
        try
        {
            foreach (var row in _cleanup) row.Selected = selectAll;
        }
        finally
        {
            _batchSelectingCleanup = false;
        }
        UpdateCleanupSelection();
    }

    private void CleanupRow_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(CleanupRow.Selected) && !_batchSelectingCleanup)
            UpdateCleanupSelection();
    }

    private void UpdateCleanupSelection()
    {
        var count = _cleanup.Count;
        var selected = _cleanup.Count(row => row.Selected);
        SelectAllCleanupCheck.IsEnabled = count > 0;
        // Show an indeterminate state when only some files have been checked manually.
        SelectAllCleanupCheck.IsChecked = selected == 0 ? false : selected == count ? true : null;
        CleanupSelection.Text = $"{selected:N0} of {count:N0} selected";
    }

    private void DeleteChecked_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var selected = _cleanup.Where(x => x.Selected).Select(x => x.Candidate).ToArray();
        if (selected.Length == 0) { MessageBox.Show(this, "Check files to delete first."); return; }
        var bytes = selected.Sum(x => x.SizeBytes);
        if (MessageBox.Show(this,
            "Permanently delete " + selected.Length + " reviewed files (up to " + ToSize(bytes) +
            ")? This action does not use the Recycle Bin and cannot be undone.",
            "Confirm permanent deletion", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        var result = CleanupService.RemoveSelected(selected);
        foreach (var row in _cleanup.Where(x => x.Selected && !File.Exists(x.Path)).ToArray())
        {
            row.PropertyChanged -= CleanupRow_PropertyChanged;
            _cleanup.Remove(row);
        }
        UpdateCleanupSelection();
        SpaceCount.Text = ToSize(_cleanup.Sum(x => x.Candidate.SizeBytes));
        Log("Deleted " + result.Removed + " files; nominal sizes " + ToSize(result.BytesRemoved) +
            "; errors: " + result.Failures.Count);
        if (result.Failures.Count > 0)
            MessageBox.Show(this, string.Join(Environment.NewLine, result.Failures.Take(8)),
                "Some files could not be removed", MessageBoxButton.OK, MessageBoxImage.Warning);
    }



    private void LoadGitHubAccounts(string? desired = null)
    {
        var chosen = desired ?? GitHubAccountSelector.SelectedItem as string ?? "All accounts";
        GitHubAccountSelector.ItemsSource = null;
        var items = new List<string> { "All accounts" };
        items.AddRange(_gitHubStore.Accounts);
        GitHubAccountSelector.ItemsSource = items;
        GitHubAccountSelector.SelectedItem = items.Contains(chosen) ? chosen : "All accounts";
        GitHubStatus.Text = _gitHubStore.Accounts.Count + " connected GitHub account(s).";
    }

    private void GitHubAccountSelector_SelectionChanged(object sender,
        System.Windows.Controls.SelectionChangedEventArgs e) => FilterGitHubRepositories();

    private void FilterGitHubRepositories()
    {
        if (GitHubRepoList is null) return;
        var filter = GitHubAccountSelector.SelectedItem as string;
        _gitHubRepos.Clear();
        foreach (var item in _gitHubRepoCache.Where(repo =>
            filter is null or "All accounts" ||
            repo.Account.Equals(filter, StringComparison.OrdinalIgnoreCase)))
            _gitHubRepos.Add(item);
        _gitHubContents.Clear();
        _gitHubCurrentRepo = null;
        _gitHubCurrentPath = "";
        GitHubFilePreview.Clear();
        GitHubFilePath.Text = "FILE PREVIEW (READ ONLY)";
    }

    private void SetGitHubBusy(bool busy)
    {
        _gitHubBusy = busy;
        GitHubConnectButton.IsEnabled = !busy;
        GitHubRemoveButton.IsEnabled = !busy;
        GitHubRefreshButton.IsEnabled = !busy;
        GitHubOpenRepoButton.IsEnabled = !busy;
        GitHubOpenItemButton.IsEnabled = !busy;
        GitHubUpButton.IsEnabled = !busy;
    }

    private async void GitHubConnect_Click(object sender, RoutedEventArgs e)
    {
        if (_gitHubBusy) return;
        var token = GitHubToken.Password.Trim();
        GitHubToken.Clear();
        if (token.Length == 0)
        {
            MessageBox.Show(this, "Create a fine-grained GitHub token with repository Metadata and Contents read permissions, then paste it here.");
            return;
        }
        SetGitHubBusy(true);
        GitHubStatus.Text = "Verifying GitHub credential...";
        try
        {
            var login = await GitHubRepositoryReader.VerifyAccountAsync(token);
            if (_gitHubStore.Contains(login) && MessageBox.Show(this,
                "Replace the stored credential for GitHub account " + login + "?",
                "Replace account credential", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;
            _gitHubStore.Save(login, token);
            LoadGitHubAccounts(login);
            GitHubStatus.Text = "Connected @" + login + ". Refresh repositories to load access.";
            Log("GitHub account connected: @" + login + ". Credential stored encrypted locally.");
        }
        catch (Exception ex)
        {
            GitHubStatus.Text = "Could not connect account: " + ex.Message;
        }
        finally { SetGitHubBusy(false); }
    }

    private void GitHubRemove_Click(object sender, RoutedEventArgs e)
    {
        if (_gitHubBusy) return;
        var login = GitHubAccountSelector.SelectedItem as string;
        if (string.IsNullOrEmpty(login) || login == "All accounts")
        {
            MessageBox.Show(this, "Choose one account from the Account menu first.");
            return;
        }
        if (MessageBox.Show(this, "Disconnect @" + login +
            " from this PC? This removes its locally saved credential. It does not revoke the token on GitHub.",
            "Disconnect GitHub account", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        try
        {
            _gitHubStore.Remove(login);
            _gitHubRepoCache.RemoveAll(x => x.Account.Equals(login, StringComparison.OrdinalIgnoreCase));
            LoadGitHubAccounts();
            FilterGitHubRepositories();
            Log("Removed locally stored GitHub credential for @" + login + ".");
        }
        catch (Exception ex) { GitHubStatus.Text = "Could not disconnect: " + ex.Message; }
    }

    private async void GitHubRefresh_Click(object sender, RoutedEventArgs e)
    {
        if (_gitHubBusy) return;
        SetGitHubBusy(true);
        try
        {
            var connected = _gitHubStore.Accounts;
            var fetched = new List<GitHubRepository>();
            var errors = new List<string>();
            foreach (var account in connected)
            {
                GitHubStatus.Text = "Loading repositories for @" + account + "...";
                try
                {
                    var token = _gitHubStore.GetToken(account);
                    fetched.AddRange(await GitHubRepositoryReader.ListRepositoriesAsync(account, token));
                }
                catch (Exception ex) { errors.Add("@" + account + ": " + ex.Message); }
            }
            _gitHubRepoCache.Clear();
            _gitHubRepoCache.AddRange(fetched.OrderBy(x => x.FullName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Account));
            FilterGitHubRepositories();
            GitHubStatus.Text = fetched.Count + " repositories across " + connected.Count +
                " account(s)." + (errors.Count > 0 ? " Errors: " + string.Join(" | ", errors) : "");
        }
        finally { SetGitHubBusy(false); }
    }

    private async void GitHubOpenRepo_Click(object sender, RoutedEventArgs e)
    {
        if (_gitHubBusy || GitHubRepoList.SelectedItem is not GitHubRepository repo) return;
        _gitHubCurrentRepo = repo;
        await OpenGitHubFolderAsync("");
    }

    private async void GitHubOpenItem_Click(object sender, RoutedEventArgs e)
    {
        if (_gitHubBusy || _gitHubCurrentRepo is null ||
            GitHubContentsList.SelectedItem is not GitHubDirectoryEntry entry) return;
        if (entry.Type == "dir")
        {
            await OpenGitHubFolderAsync(entry.Path);
            return;
        }
        SetGitHubBusy(true);
        try
        {
            GitHubFilePath.Text = _gitHubCurrentRepo.FullName + "/" + entry.Path + " (read only)";
            GitHubFilePreview.Text = await GitHubRepositoryReader.ReadTextFileAsync(_gitHubCurrentRepo,
                entry.Path, _gitHubStore.GetToken(_gitHubCurrentRepo.Account));
        }
        catch (Exception ex)
        {
            GitHubFilePreview.Text = "Cannot preview file: " + ex.Message;
        }
        finally { SetGitHubBusy(false); }
    }

    private async void GitHubUp_Click(object sender, RoutedEventArgs e)
    {
        if (_gitHubBusy || _gitHubCurrentRepo is null || _gitHubCurrentPath.Length == 0) return;
        var index = _gitHubCurrentPath.LastIndexOf('/');
        await OpenGitHubFolderAsync(index < 0 ? "" : _gitHubCurrentPath[..index]);
    }

    private async Task OpenGitHubFolderAsync(string path)
    {
        if (_gitHubBusy || _gitHubCurrentRepo is null) return;
        SetGitHubBusy(true);
        try
        {
            var contents = await GitHubRepositoryReader.ListContentsAsync(_gitHubCurrentRepo, path,
                _gitHubStore.GetToken(_gitHubCurrentRepo.Account));
            _gitHubCurrentPath = path;
            _gitHubContents.Clear();
            foreach (var item in contents) _gitHubContents.Add(item);
            GitHubFilePath.Text = _gitHubCurrentRepo.FullName + "/" + path + " — Select a file to preview";
            GitHubFilePreview.Clear();
            GitHubStatus.Text = "Browsing @" + _gitHubCurrentRepo.Account + ": " +
                _gitHubCurrentRepo.FullName + " (" + contents.Count + " items).";
        }
        catch (Exception ex) { GitHubStatus.Text = "Cannot browse repository: " + ex.Message; }
        finally { SetGitHubBusy(false); }
    }

    private async void RefreshApps_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        try
        {
            var apps = await Task.Run(InstalledAppsService.Enumerate);
            _apps.Clear();
            foreach (var app in apps) _apps.Add(app);
            Log("Inspected " + apps.Count + " installed app registry entries. No changes made.");
        }
        catch (Exception ex) { Log("Application inventory error: " + ex.Message); }
    }

    private void OpenApps_Click(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo("ms-settings:appsfeatures") { UseShellExecute = true }); }
        catch (Exception ex) { Log("Windows Settings could not open: " + ex.Message); }
    }

    private void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if (ThreatList.SelectedItem is not ThreatFinding item || !File.Exists(item.Path))
        {
            MessageBox.Show(this, "Choose a finding that points to an accessible file.");
            return;
        }
        if (MessageBox.Show(this, "Move this file into user-profile quarantine?\n" + item.Path +
            "\n\nHeuristic findings are unverified. Moving legitimate software can disrupt applications.",
            "Quarantine file", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            var record = _vault.Quarantine(item.Path);
            Log("Quarantined: " + record.OriginalPath + " [" + record.Id + "]");
            RefreshVault();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Quarantine refused"); }
    }

    private void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineList.SelectedItem is not QuarantinedFile selected) return;
        if (MessageBox.Show(this, "Restoring an unsafe file may reintroduce a threat. Restore now?\n" +
            selected.OriginalPath, "Confirm restore", MessageBoxButton.YesNo,
            MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            _vault.Restore(selected);
            RefreshVault();
            Log("Restored: " + selected.OriginalPath);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Restore failed"); }
    }

    private void RefreshVault()
    {
        _quarantine.Clear();
        foreach (var file in _vault.List()) _quarantine.Add(file);
    }

    private static string ToSize(long bytes) => bytes >= 1_073_741_824
        ? (bytes / 1_073_741_824d).ToString("N2") + " GB"
        : (bytes / 1_048_576d).ToString("N2") + " MB";

    protected override void OnClosing(CancelEventArgs e)
    {
        _scanCancellation?.Cancel();
        base.OnClosing(e);
    }
}

public sealed class CleanupRow : INotifyPropertyChanged
{
    public CleanupCandidate Candidate { get; }
    private bool _selected;
    public CleanupRow(CleanupCandidate item) => Candidate = item;
    public bool Selected
    {
        get => _selected;
        set { if (_selected == value) return; _selected = value; PropertyChanged?.Invoke(this,
            new PropertyChangedEventArgs(nameof(Selected))); }
    }
    public string Path => Candidate.Path;
    public string Category => Candidate.Category;
    public string Size => Candidate.SizeLabel;
    public event PropertyChangedEventHandler? PropertyChanged;
}
