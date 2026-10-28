using System.Diagnostics;
using System.Windows.Threading;
using System.IO;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Runtime.InteropServices;
using System.Windows.Data;
using OTSSystemSanitizer.Core;

namespace OTSSystemSanitizer.Desktop;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ThreatRow> _findings = new();
    private readonly ObservableCollection<CleanupRow> _cleanup = new();
    private readonly ObservableCollection<QuarantinedFile> _quarantine = new();
    private readonly ObservableCollection<InstalledApp> _apps = new();
    private readonly QuarantineService _vault = new();
    private CancellationTokenSource? _scanCancellation;
    private bool _busy;
    private bool _batchSelectingCleanup;
    private bool _batchSelectingThreats;
    private bool _remediating;
    private string? _investigatedId;
    private readonly Stopwatch _searchStopwatch = new();
    private readonly DispatcherTimer _searchTimer = new() { Interval = TimeSpan.FromSeconds(1) };

    public MainWindow()
    {
        InitializeComponent();
        ThreatList.ItemsSource = _findings;
        _searchTimer.Tick += (_, _) => UpdateSearchTimer();
        UpdateThreatSelection();
        CleanupList.ItemsSource = _cleanup;
        QuarantineList.ItemsSource = _quarantine;
        InstalledAppList.ItemsSource = _apps;
        RefreshVault();
        Log("Application started; no threats assumed absent until relevant searches complete.");
    }

    // Native monitor work-area rectangles are physical pixels; WPF uses DPI-independent units.
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        public int Size;
        public NativeRect Monitor;
        public NativeRect Work;
        public uint Flags;
    }

    [DllImport("user32.dll")]
    private static extern nint MonitorFromWindow(nint hwnd, uint flags);

    [DllImport("user32.dll", EntryPoint = "GetMonitorInfoW", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfoW(nint monitor, ref MonitorInfo info);

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        FitToMonitorWorkArea();
    }

    private void FitToMonitorWorkArea()
    {
        // Default to the primary work area if native monitor enumeration is unavailable.
        var area = SystemParameters.WorkArea;
        var monitor = MonitorFromWindow(new WindowInteropHelper(this).Handle, 2); // nearest
        if (monitor != nint.Zero)
        {
            var info = new MonitorInfo { Size = Marshal.SizeOf<MonitorInfo>() };
            if (GetMonitorInfoW(monitor, ref info))
            {
                var transform = PresentationSource.FromVisual(this)?.CompositionTarget?
                    .TransformFromDevice ?? Matrix.Identity;
                var topLeft = transform.Transform(new Point(info.Work.Left, info.Work.Top));
                var bottomRight = transform.Transform(new Point(info.Work.Right, info.Work.Bottom));
                if (bottomRight.X > topLeft.X && bottomRight.Y > topLeft.Y)
                    area = new Rect(topLeft, bottomRight);
            }
        }

        // Fit within usable monitor space, keeping some breathing room on all sides.
        var width = Math.Min(1280, Math.Max(1, area.Width * 0.94));
        var height = Math.Min(780, Math.Max(1, area.Height * 0.94));
        MinWidth = Math.Min(760, width);
        MinHeight = Math.Min(540, height);
        Width = width;
        Height = height;
        Left = area.Left + (area.Width - width) / 2;
        Top = area.Top + (area.Height - height) / 2;
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
        UpdateThreatSelection();
        CleanAndSecureButton.IsEnabled = !busy;
    }

    private void FindingSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        // Only filter local, already-loaded findings. No new search is initiated.
        if (ThreatList is null || ThreatList.ItemsSource is null) return;
        var query = FindingSearchBox.Text.Trim();
        var view = CollectionViewSource.GetDefaultView(_findings);
        view.Filter = item =>
        {
            if (item is not ThreatRow row) return false;
            if (query.Length == 0) return true;
            return row.Title.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Level.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Source.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Path.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Evidence.Contains(query, StringComparison.OrdinalIgnoreCase);
        };
        view.Refresh();
    }

    private void UpdateSearchTimer() =>
        ElapsedSearchTime.Text = "Search duration: " + _searchStopwatch.Elapsed.ToString(@"hh\:mm\:ss");

    private void AddFinding(ThreatFinding finding)
    {
        var row = new ThreatRow(finding);
        row.PropertyChanged += ThreatRow_PropertyChanged;
        _findings.Add(row);
    }

    private void ThreatRow_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ThreatRow.Selected) && !_batchSelectingThreats)
            UpdateThreatSelection();
    }

    private void SelectAllThreats_Click(object sender, RoutedEventArgs e)
    {
        var selecting = SelectAllThreatsCheck.IsChecked != false;
        _batchSelectingThreats = true;
        try { foreach (var row in _findings) row.Selected = selecting && row.CanQuarantine; }
        finally { _batchSelectingThreats = false; }
        UpdateThreatSelection();
    }

    private void UpdateThreatSelection()
    {
        var eligible = _findings.Count(x => x.CanQuarantine);
        var chosen = _findings.Count(x => x.Selected && x.CanQuarantine);
        SelectAllThreatsCheck.IsEnabled = eligible > 0 && !_busy && !_remediating;
        SelectAllThreatsCheck.IsChecked = chosen == 0 ? false : chosen == eligible ? true : null;
        ThreatSelection.Text = $"{chosen:N0} of {eligible:N0} eligible selected";
        QuarantineButton.IsEnabled = chosen > 0 && !_busy && !_remediating;
    }

    private async void Quick_Click(object sender, RoutedEventArgs e) => await ScanAsync(ScanMode.Quick);
    private async void Deep_Click(object sender, RoutedEventArgs e) => await ScanAsync(ScanMode.Deep);

    private async Task ScanAsync(ScanMode mode)
    {
        if (_busy) return;
        SetBusy(true);
        foreach (var row in _findings) row.PropertyChanged -= ThreatRow_PropertyChanged;
        _findings.Clear();
        UpdateThreatSelection();
        FindingCount.Text = "0";
        FilesCount.Text = "0";
        ScanBar.IsIndeterminate = true;
        _searchStopwatch.Restart();
        _searchTimer.Start();
        UpdateSearchTimer();
        _scanCancellation = new CancellationTokenSource();
        var token = _scanCancellation.Token;
        var progress = new Progress<ScanProgress>(p =>
        {
            FilesCount.Text = p.Files.ToString("N0");
            ScanStatus.Text = p.Phase + " — " + p.Files.ToString("N0") + " files; " +
                p.Skipped.ToString("N0") + " inaccessible or skipped items";
        });
        Log("Started " + mode + " system search.");
        try
        {
            var fileTask = ThreatScanner.RunAsync(mode, progress, token);
            var persistenceTask = Task.Run(PersistenceInspector.Inspect, token);
            var defenderTask = DefenderIntegration.RunScanAsync(mode, token);
            var report = await fileTask;
            foreach (var finding in report.Findings) AddFinding(finding);
            try
            {
                var persistence = await persistenceTask;
                foreach (var finding in persistence) AddFinding(finding);
            }
            catch (OperationCanceledException) { }
            var antivirus = await defenderTask;
            foreach (var pastDetection in await DefenderIntegration.GetDetectionHistoryAsync(token))
                AddFinding(pastDetection);
            FindingCount.Text = _findings.Count.ToString("N0");
            UpdateThreatSelection();
            ScanStatus.Text = report.Cancelled ? "Search cancelled: results are partial."
                : "Search finished. Review possible threats and antivirus coverage.";
            CoverageStatus.Text = antivirus + (report.Skipped > 0 ? " Some files were inaccessible." : "");
            Log("Searched " + report.Files.ToString("N0") + " files in " +
                _searchStopwatch.Elapsed.ToString(@"hh\:mm\:ss") + ". " + _findings.Count +
                " review items. " + antivirus);
        }
        catch (OperationCanceledException)
        {
            ScanStatus.Text = "Search cancelled; coverage incomplete.";
            Log("Search cancelled.");
        }
        catch (Exception ex)
        {
            ScanStatus.Text = "Search failed; coverage incomplete.";
            Log("Search error: " + ex.Message);
        }
        finally
        {
            _searchTimer.Stop();
            _searchStopwatch.Stop();
            UpdateSearchTimer();
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
            MessageBox.Show(this, "Review the cleanup list and check specific files before using Destroy checked cleanup files. " +
                "OTS System Sanitizer never destroys items merely because you clicked Clean & Secure.",
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
        if (selected.Length == 0) { MessageBox.Show(this, "Check cleanup files to destroy first."); return; }
        var bytes = selected.Sum(x => x.SizeBytes);
        if (MessageBox.Show(this,
            "Permanently destroy " + selected.Length + " reviewed cleanup files (up to " + ToSize(bytes) +
            ")? This removes files without the Recycle Bin. It is not a secure overwrite and cannot be undone.",
            "Confirm cleanup destruction", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        var result = CleanupService.RemoveSelected(selected);
        foreach (var row in _cleanup.Where(x => x.Selected && !File.Exists(x.Path)).ToArray())
        {
            row.PropertyChanged -= CleanupRow_PropertyChanged;
            _cleanup.Remove(row);
        }
        UpdateCleanupSelection();
        SpaceCount.Text = ToSize(_cleanup.Sum(x => x.Candidate.SizeBytes));
        Log("Destroyed " + result.Removed + " cleanup files; nominal sizes " + ToSize(result.BytesRemoved) +
            "; errors: " + result.Failures.Count);
        if (result.Failures.Count > 0)
            MessageBox.Show(this, string.Join(Environment.NewLine, result.Failures.Take(8)),
                "Some files could not be removed", MessageBoxButton.OK, MessageBoxImage.Warning);
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

    private async void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _remediating) return;
        var selected = _findings.Where(x => x.Selected && x.CanQuarantine)
            .GroupBy(x => x.Path, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First()).ToArray();
        if (selected.Length == 0)
        {
            MessageBox.Show(this, "Check eligible findings. Protected paths and Defender history records cannot be moved.");
            return;
        }
        if (MessageBox.Show(this,
            "Quarantine " + selected.Length + " selected file(s)?\n\n" +
            "These indicators are UNVERIFIED. Moving legitimate software can disrupt it. " +
            "Each file will be available for investigation, restoration or explicit destruction.",
            "Confirm quarantine and investigation", MessageBoxButton.YesNo,
            MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        _remediating = true;
        QuarantineButton.Content = "Quarantining...";
        UpdateThreatSelection();
        var quarantinedIds = new List<string>();
        var failures = new List<string>();
        try
        {
            foreach (var row in selected)
            {
                try
                {
                    var investigation = ThreatInvestigator.Explain(row.Finding);
                    var record = await Task.Run(() => _vault.Quarantine(row.Path, investigation));
                    quarantinedIds.Add(record.Id);
                    Log("Quarantined for investigation: " + record.OriginalPath + " [" + record.Id + "]");
                    foreach (var old in _findings.Where(x => x.Path.Equals(row.Path,
                                 StringComparison.OrdinalIgnoreCase)).ToArray())
                    {
                        old.PropertyChanged -= ThreatRow_PropertyChanged;
                        _findings.Remove(old);
                    }
                }
                catch (Exception ex) { failures.Add(row.Path + ": " + ex.Message); }
            }
            FindingCount.Text = _findings.Count.ToString("N0");
            RefreshVault();
            if (quarantinedIds.Count > 0)
            {
                MainTabs.SelectedIndex = 3;
                QuarantineList.SelectedItem = _quarantine.FirstOrDefault(x => x.Id == quarantinedIds[0]);
                QuarantineList.ScrollIntoView(QuarantineList.SelectedItem);
                MessageBox.Show(this,
                    quarantinedIds.Count + " file(s) quarantined. Select each item and click Investigate selected " +
                    "to see why it was flagged. Then choose Restore or Destroy reviewed file.\n\n" +
                    (failures.Count > 0 ? failures.Count + " additional item(s) failed; see Activity." : ""),
                    "Quarantine complete — investigate before destroying", MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            foreach (var failure in failures) Log("Quarantine refused: " + failure);
            if (quarantinedIds.Count == 0 && failures.Count > 0)
                MessageBox.Show(this, string.Join(Environment.NewLine, failures.Take(6)),
                    "No files quarantined", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _remediating = false;
            QuarantineButton.Content = "Quarantine & investigate checked";
            UpdateThreatSelection();
        }
    }

    private void QuarantineList_SelectionChanged(object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        _investigatedId = null;
        if (DestroyButton is null || InvestigationDetails is null) return;
        DestroyButton.IsEnabled = false;
        InvestigationDetails.Text = QuarantineList.SelectedItem is QuarantinedFile item
            ? "Selected: " + item.OriginalPath + Environment.NewLine +
              "Quarantined: not a confirmed infection." + Environment.NewLine +
              "Click Investigate selected to see evidence and enable the Destroy decision."
            : "Select a quarantined file, then choose Investigate selected to review the evidence.";
    }

    private void Investigate_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineList.SelectedItem is not QuarantinedFile item)
        {
            MessageBox.Show(this, "Select a quarantined item to investigate.");
            return;
        }
        InvestigationDetails.Text = ThreatInvestigator.QuarantineReport(item);
        _investigatedId = item.Id;
        DestroyButton.IsEnabled = !_remediating;
        Log("Viewed evidence for quarantine item [" + item.Id + "].");
    }

    private void Destroy_Click(object sender, RoutedEventArgs e)
    {
        if (_remediating || QuarantineList.SelectedItem is not QuarantinedFile item ||
            _investigatedId != item.Id)
        {
            MessageBox.Show(this, "Investigate the selected item before destroying it.");
            return;
        }
        if (MessageBox.Show(this, "PERMANENTLY DESTROY this quarantined encrypted item?\n" +
            item.OriginalPath + "\n\nThe vault copy and manifest will be removed. " +
            "This is not a forensic secure erase of disk blocks, and cannot be undone.",
            "Confirm irreversible destruction", MessageBoxButton.YesNo,
            MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            _vault.Destroy(item);
            Log("Destroyed quarantined item [" + item.Id + "]: " + item.OriginalPath);
            RefreshVault();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Destruction refused"); }
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
        _investigatedId = null;
        DestroyButton.IsEnabled = false;
        InvestigationDetails.Text = "Select a quarantined file, then choose Investigate selected to review the evidence.";
        _quarantine.Clear();
        foreach (var file in _vault.List()) _quarantine.Add(file);
    }

    private static string ToSize(long bytes) => bytes >= 1_073_741_824
        ? (bytes / 1_073_741_824d).ToString("N2") + " GB"
        : (bytes / 1_048_576d).ToString("N2") + " MB";

    protected override void OnClosing(CancelEventArgs e)
    {
        _scanCancellation?.Cancel();
        _searchTimer.Stop();
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

public sealed class ThreatRow : INotifyPropertyChanged
{
    public ThreatFinding Finding { get; }
    public ThreatRow(ThreatFinding finding) => Finding = finding;
    private bool _selected;
    public bool Selected
    {
        get => _selected;
        set
        {
            if (_selected == value || (value && !CanQuarantine)) return;
            _selected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Selected)));
        }
    }
    public bool CanQuarantine => PathPolicy.CanQuarantine(Path);
    public string SelectionHint => CanQuarantine ? "Eligible user file; review before quarantine." :
        "Not an accessible user-profile file; check Windows Security or investigate manually.";
    public string Level => Finding.Level;
    public string Title => Finding.Title;
    public string Source => Finding.Source;
    public string Path => Finding.Path;
    public string Evidence => Finding.Evidence;
    public event PropertyChangedEventHandler? PropertyChanged;
}
