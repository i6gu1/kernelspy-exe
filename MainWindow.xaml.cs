using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using Microsoft.Win32;
using KernelSpyScanner.Engine;
using KernelSpyScanner.Models;
using KernelSpyScanner.Reporting;

namespace KernelSpyScanner
{
    public partial class MainWindow : Window
    {
        private readonly Scanner _scanner = new();
        private CancellationTokenSource? _cts;
        private ObservableCollection<Finding> _results = new();
        private List<Finding> _lastFindings = new();

        public MainWindow()
        {
            InitializeComponent();

            // Keep the whole window (including the title bar) inside the usable
            // desktop area. On a 1280x720 display the designed 820px height would
            // otherwise center the title bar off-screen.
            var workArea = SystemParameters.WorkArea;
            MaxWidth = workArea.Width;
            MaxHeight = workArea.Height;
            if (Width > workArea.Width) Width = workArea.Width;
            if (Height > workArea.Height) Height = workArea.Height;

            ResultsGrid.ItemsSource = _results;
            SourceInitialized += (_, _) => ForceDarkTitleBar();
        }

        // The window content is styled dark by Themes/DarkTheme.xaml, but the
        // title bar normally follows the Windows theme (light on a light
        // system). Force it dark so the app never shows up in light mode.
        private void ForceDarkTitleBar()
        {
            try
            {
                var hwnd = new WindowInteropHelper(this).Handle;
                if (hwnd == IntPtr.Zero) return;

                var dark = 1;
                // 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 10 2004+)
                // 19 = same attribute as used by earlier Windows 10 builds
                if (DwmSetWindowAttribute(hwnd, 20, ref dark, sizeof(int)) != 0)
                    DwmSetWindowAttribute(hwnd, 19, ref dark, sizeof(int));
            }
            catch
            {
                // DWM unavailable: the content stays dark regardless.
            }
        }

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int valueSize);

        private void Nav_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button btn || btn.Tag is not string tag) return;
            ShowPage(tag);
        }

        private void ShowPage(string name)
        {
            PageHome.Visibility = name == "Home" ? Visibility.Visible : Visibility.Collapsed;
            PageScan.Visibility = name == "Scan" ? Visibility.Visible : Visibility.Collapsed;
            PageResults.Visibility = name == "Results" ? Visibility.Visible : Visibility.Collapsed;
            PageReports.Visibility = name == "Reports" ? Visibility.Visible : Visibility.Collapsed;
            PageSettings.Visibility = name == "Settings" ? Visibility.Visible : Visibility.Collapsed;
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFolderDialog { Title = "Select folder to scan" };
            if (dlg.ShowDialog() == true)
                FolderTextBox.Text = dlg.FolderName;
        }

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            var folder = FolderTextBox.Text?.Trim();
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
            {
                MessageBox.Show("Please select a valid folder.", "KernelSpy", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            StartButton.IsEnabled = false;
            CancelButton.IsEnabled = true;
            _cts = new CancellationTokenSource();
            _results.Clear();
            _lastFindings.Clear();
            ResultsCount.Text = "0 findings";
            StatusText.Text = "Starting scan...";
            ScanProgress.Value = 0;

            var progress = new Progress<ScanProgress>(p =>
            {
                ScanProgress.Value = p.Percent;
                StatusText.Text = p.Message;
            });

            try
            {
                var findings = await _scanner.ScanAsync(folder, progress, _cts.Token).ConfigureAwait(true);
                _lastFindings = findings;
                foreach (var f in findings) _results.Add(f);
                ResultsCount.Text = $"{findings.Count} findings";
                StatusText.Text = $"Scan complete. {findings.Count} findings.";
                ShowPage("Results");
            }
            catch (OperationCanceledException)
            {
                StatusText.Text = "Scan cancelled.";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Error: {ex.Message}";
                MessageBox.Show(ex.Message, "Scan failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                StartButton.IsEnabled = true;
                CancelButton.IsEnabled = false;
                _cts?.Dispose();
                _cts = null;
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
        }

        private void ExportHtml_Click(object sender, RoutedEventArgs e)
        {
            if (_lastFindings.Count == 0)
            {
                MessageBox.Show("No results to export. Run a scan first.", "KernelSpy", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var dlg = new SaveFileDialog
            {
                Filter = "HTML files (*.html)|*.html",
                FileName = "KernelSpy_Report.html"
            };
            if (dlg.ShowDialog() == true)
            {
                bool ok = HtmlReport.Export(dlg.FileName, _lastFindings);
                ReportStatus.Text = ok ? $"Saved: {dlg.FileName}" : "Export failed.";
            }
        }

        private void ExportJson_Click(object sender, RoutedEventArgs e)
        {
            if (_lastFindings.Count == 0)
            {
                MessageBox.Show("No results to export. Run a scan first.", "KernelSpy", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var dlg = new SaveFileDialog
            {
                Filter = "JSON files (*.json)|*.json",
                FileName = "KernelSpy_Report.json"
            };
            if (dlg.ShowDialog() == true)
            {
                bool ok = JsonReport.Export(dlg.FileName, _lastFindings);
                ReportStatus.Text = ok ? $"Saved: {dlg.FileName}" : "Export failed.";
            }
        }
    }
}
