using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using KernelSpyScanner.Engine;

namespace KernelSpyScanner
{
    /// <summary>
    /// Application entry point with global crash protection. All unhandled
    /// exceptions are written to a log file and surfaced to the user instead of
    /// terminating the process abruptly.
    /// </summary>
    public partial class App : Application
    {
        private static readonly string LogDir =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KernelSpyScanner", "logs");

        public App()
        {
            // Register handlers before any XAML is loaded or any window is
            // created. This also captures failures in App.xaml resources.
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            try
            {
                LogStartupInfo();

                var window = new MainWindow();
                MainWindow = window;
                window.Show();
            }
            catch (Exception ex)
            {
                Log(ex, "startup");
                MessageBox.Show(
                    "KernelSpy Scanner could not start.\n\n" +
                    ex.Message +
                    "\n\nA diagnostic log was written to:\n" + LogDir,
                    "KernelSpy Scanner",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                Shutdown(1);
            }
        }

        private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            Log(e.Exception);
            MessageBox.Show("An unexpected error occurred. The details were written to the log file.\n\n" + e.Exception.Message,
                "KernelSpy Scanner", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }

        private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex) Log(ex, "appdomain");
        }

        private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            Log(e.Exception, "task");
            e.SetObserved();
        }

        private static void LogStartupInfo()
        {
            try
            {
                Directory.CreateDirectory(LogDir);
                string tools = AppPaths.ToolsDirectory ?? "<not found>";
                string line = $"{DateTime.Now:O} | exe={Environment.ProcessPath} | base={AppPaths.BaseDirectory} | tools={tools}{Environment.NewLine}";
                File.AppendAllText(Path.Combine(LogDir, "startup.log"), line);
            }
            catch
            {
                // Diagnostics must never prevent startup.
            }
        }

        private static void Log(Exception ex, string context = "unhandled")
        {
            try
            {
                Directory.CreateDirectory(LogDir);
                var path = Path.Combine(LogDir, $"error_{DateTime.Now:yyyyMMdd_HHmmss}.log");
                File.WriteAllText(path, $"{DateTime.Now:O} [{context}]{Environment.NewLine}{ex}");
            }
            catch
            {
                // Logging must never throw.
            }
        }
    }
}
