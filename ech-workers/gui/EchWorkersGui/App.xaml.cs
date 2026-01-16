using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace EchWorkersGui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // 全局异常处理
        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            LogException("AppDomain.UnhandledException", args.ExceptionObject as Exception);
        };

        DispatcherUnhandledException += (s, args) =>
        {
            LogException("DispatcherUnhandledException", args.Exception);
            args.Handled = true;
        };

        TaskScheduler.UnobservedTaskException += (s, args) =>
        {
            LogException("TaskScheduler.UnobservedTaskException", args.Exception);
            args.SetObserved();
        };

        base.OnStartup(e);
    }

    private static void LogException(string source, Exception? ex)
    {
        try
        {
            var logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);
            var logFile = Path.Combine(logDir, "crash.log");
            var msg = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {source}\n{ex}\n\n";
            
            // 使用 FileStream 追加，避免文件锁冲突
            using (var fs = new FileStream(logFile, FileMode.Append, FileAccess.Write, FileShare.Read))
            using (var writer = new StreamWriter(fs))
            {
                writer.Write(msg);
            }
            
            MessageBox.Show($"发生错误，已记录到:\n{logFile}\n\n{ex?.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch
        {
            // ignore
        }
    }
}
