using System.IO;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using AegisPrime.Core;

namespace AegisPrime.Desktop;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ThreatFinding> _findings = new();
    private readonly ObservableCollection<CleanupRow> _cleanup = new();
    private readonly ObservableCollection<QuarantinedFile> _quarantine = new();
    private readonly QuarantineService _vault = new();
    private CancellationTokenSource? _scanCancellation;
    private bool _busy;

    public MainWindow()
    {
        InitializeComponent();
        ThreatList.ItemsSource = _findings;
        CleanupList.ItemsSource = _cleanup;
        QuarantineList.ItemsSource = _quarantine;
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
            _cleanup.Clear();
            foreach (var item in items) _cleanup.Add(new CleanupRow(item));
            var total = items.Sum(x => x.SizeBytes);
            SpaceCount.Text = ToSize(total);
            CleanupSelection.Text = items.Count.ToString("N0") + " candidates";
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
                "Aegis Prime never deletes items merely because you clicked Clean & Secure.",
                "Review required", MessageBoxButton.OK, MessageBoxImage.Information);
        }
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
            _cleanup.Remove(row);
        SpaceCount.Text = ToSize(_cleanup.Sum(x => x.Candidate.SizeBytes));
        Log("Deleted " + result.Removed + " files; nominal sizes " + ToSize(result.BytesRemoved) +
            "; errors: " + result.Failures.Count);
        if (result.Failures.Count > 0)
            MessageBox.Show(this, string.Join(Environment.NewLine, result.Failures.Take(8)),
                "Some files could not be removed", MessageBoxButton.OK, MessageBoxImage.Warning);
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
