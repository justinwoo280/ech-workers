using System;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Principal;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace EchWorkersGui.Services;

public sealed class CoreProcessService
{
    private Process? _process;
    private string? _controlAddr;
    private bool _isElevated;
    private string? _logFilePath;
    private CancellationTokenSource? _logTailCts;
    private Task? _logTailTask;

    public bool IsRunning => _process is { HasExited: false };

    public event Action<string>? OnLogLine;
    public event Action? OnExited;

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public bool Start(ProcessStartInfo psi)
    {
        if (IsRunning) return false;

        _controlAddr = null;
        _isElevated = false;
        _logFilePath = null;
        StopTailing();

        _process = new Process
        {
            StartInfo = psi,
            EnableRaisingEvents = true
        };

        _process.Exited += (_, _) =>
        {
            OnLogLine?.Invoke("[GUI] 内核进程已退出");
            OnExited?.Invoke();
        };

        _process.OutputDataReceived += (_, e) =>
        {
            if (e.Data == null) return;
            HandleLogLine(e.Data);
        };
        _process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data == null) return;
            HandleLogLine(e.Data);
        };

        if (!_process.Start())
        {
            _process = null;
            return false;
        }

        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        return true;
    }

    public bool StartElevated(string exePath, string arguments, string logFilePath)
    {
        if (IsRunning) return false;

        _controlAddr = null;
        _isElevated = true;
        _logFilePath = logFilePath;
        StopTailing();

        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            Arguments = arguments,
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden
        };

        try
        {
            _process = Process.Start(psi);
            if (_process == null) return false;

            StartTailing(logFilePath);
            OnLogLine?.Invoke("[GUI] 已以管理员权限启动内核（日志通过 logfile 回传）");

            Task.Run(async () =>
            {
                try
                {
                    await _process.WaitForExitAsync();
                }
                catch
                {
                    // ignored
                }
                OnLogLine?.Invoke("[GUI] 内核进程已退出");
                OnExited?.Invoke();
            });

            return true;
        }
        catch (Exception ex)
        {
            OnLogLine?.Invoke("[GUI] 提权启动失败: " + ex.Message);
            _process = null;
            return false;
        }
    }

    private void HandleLogLine(string line)
    {
        if (line.StartsWith("CONTROL_ADDR=", StringComparison.OrdinalIgnoreCase))
        {
            _controlAddr = line.Substring("CONTROL_ADDR=".Length).Trim();
        }

        OnLogLine?.Invoke(line);
    }

    public async Task StopAsync()
    {
        if (!IsRunning) return;

        if (!string.IsNullOrWhiteSpace(_controlAddr))
        {
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(1) };
                var url = $"http://{_controlAddr}/quit";
                _ = await client.PostAsync(url, new StringContent(""));

                // 等待进程优雅退出（最多 3 秒）
                var maxWait = 30; // 30 * 100ms = 3s
                for (var i = 0; i < maxWait && IsRunning; i++)
                {
                    await Task.Delay(100);
                }
            }
            catch
            {
                // 忽略，走兜底强杀
            }
        }

        try
        {
            if (IsRunning)
            {
                _process!.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            if (_isElevated)
            {
                OnLogLine?.Invoke("[GUI] 无法强制结束管理员内核进程（请确认 /quit 是否生效，或以管理员运行 GUI 再强制结束）");
            }
        }

        _process = null;
        _controlAddr = null;
        StopTailing();
    }

    private void StartTailing(string logFilePath)
    {
        _logTailCts = new CancellationTokenSource();
        var token = _logTailCts.Token;

        _logTailTask = Task.Run(async () =>
        {
            // 等待文件出现（最多 5 秒）
            for (var i = 0; i < 50 && !File.Exists(logFilePath) && !token.IsCancellationRequested; i++)
            {
                await Task.Delay(100, token);
            }

            if (!File.Exists(logFilePath) || token.IsCancellationRequested) return;

            using var fs = new FileStream(logFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs, Encoding.UTF8);

            // 从文件末尾开始跟随（避免读到历史日志）
            fs.Seek(0, SeekOrigin.End);

            while (!token.IsCancellationRequested)
            {
                string? line;
                while ((line = await reader.ReadLineAsync()) != null)
                {
                    HandleLogLine(line);
                    if (token.IsCancellationRequested) return;
                }

                // 只有在没有新数据时才等待
                await Task.Delay(50, token);
            }
        }, token);
    }

    private void StopTailing()
    {
        try
        {
            _logTailCts?.Cancel();
        }
        catch
        {
            // ignored
        }
        _logTailCts = null;
        _logTailTask = null;
    }

    public static string BuildArguments(
        string listenAddr,
        bool enableSysProxy,
        bool enableTun,
        string tunIp,
        string tunGateway,
        string tunMask,
        string tunDns,
        int tunMtu,
        string serverAddr,
        string serverIp,
        string token,
        string protoMode,
        int numConns,
        bool enableYamux,
        bool enableEch,
        string echDomain,
        string dnsServer,
        string? logFilePath)
    {
        static string Q(string s) => "\"" + s.Replace("\"", "\\\"") + "\"";
        var sb = new StringBuilder();

        void Add(string name, string? value = null)
        {
            if (sb.Length > 0) sb.Append(' ');
            sb.Append(name);
            if (value != null)
            {
                sb.Append(' ');
                sb.Append(Q(value));
            }
        }

        Add("-control", "127.0.0.1:0");
        if (!string.IsNullOrWhiteSpace(logFilePath))
        {
            Add("-logfile", logFilePath);
        }

        Add("-l", listenAddr);
        Add("-f", serverAddr);

        if (!string.IsNullOrWhiteSpace(serverIp)) Add("-ip", serverIp);
        if (!string.IsNullOrWhiteSpace(token)) Add("-token", token);
        if (!string.IsNullOrWhiteSpace(protoMode)) Add("-mode", protoMode);
        if (numConns > 1) Add("-n", numConns.ToString());

        // Yamux 默认启用，如果禁用则传 -yamux=false
        if (!enableYamux) Add("-yamux=false");

        if (!enableEch)
        {
            Add("-fallback");
        }
        else
        {
            if (!string.IsNullOrWhiteSpace(dnsServer)) Add("-dns", dnsServer);
            if (!string.IsNullOrWhiteSpace(echDomain)) Add("-ech", echDomain);
        }

        if (enableTun)
        {
            Add("-tun");
            Add("-tun-ip", tunIp);
            Add("-tun-gateway", tunGateway);
            Add("-tun-mask", tunMask);
            Add("-tun-dns", tunDns);
            if (tunMtu > 0) Add("-tun-mtu", tunMtu.ToString());
        }
        else
        {
            if (enableSysProxy) Add("-sysproxy");
        }

        return sb.ToString();
    }

    public static ProcessStartInfo BuildStartInfo(
        string coreExePath,
        string listenAddr,
        bool enableSysProxy,
        bool enableTun,
        string tunIp,
        string tunGateway,
        string tunMask,
        string tunDns,
        int tunMtu,
        string serverAddr,
        string serverIp,
        string token,
        string protoMode,
        int numConns,
        bool enableYamux,
        bool enableEch,
        string echDomain,
        string dnsServer,
        string? logFilePath)
    {
        var psi = new ProcessStartInfo
        {
            FileName = coreExePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        void Add(string arg)
        {
            psi.ArgumentList.Add(arg);
        }

        Add("-control");
        Add("127.0.0.1:0");

        if (!string.IsNullOrWhiteSpace(logFilePath))
        {
            Add("-logfile");
            Add(logFilePath!);
        }

        Add("-l");
        Add(listenAddr);

        Add("-f");
        Add(serverAddr);

        if (!string.IsNullOrWhiteSpace(serverIp))
        {
            Add("-ip");
            Add(serverIp);
        }

        if (!string.IsNullOrWhiteSpace(token))
        {
            Add("-token");
            Add(token);
        }

        if (!string.IsNullOrWhiteSpace(protoMode))
        {
            Add("-mode");
            Add(protoMode);
        }

        if (numConns > 1)
        {
            Add("-n");
            Add(numConns.ToString());
        }

        // Yamux 默认启用，如果禁用则传 -yamux=false
        if (!enableYamux)
        {
            Add("-yamux=false");
        }

        if (!enableEch)
        {
            Add("-fallback");
        }
        else
        {
            if (!string.IsNullOrWhiteSpace(dnsServer))
            {
                Add("-dns");
                Add(dnsServer);
            }
            if (!string.IsNullOrWhiteSpace(echDomain))
            {
                Add("-ech");
                Add(echDomain);
            }
        }

        if (enableTun)
        {
            Add("-tun");

            Add("-tun-ip");
            Add(tunIp);

            Add("-tun-gateway");
            Add(tunGateway);

            Add("-tun-mask");
            Add(tunMask);

            Add("-tun-dns");
            Add(tunDns);

            if (tunMtu > 0)
            {
                Add("-tun-mtu");
                Add(tunMtu.ToString());
            }
        }
        else
        {
            if (enableSysProxy)
            {
                Add("-sysproxy");
            }
        }

        return psi;
    }
}
