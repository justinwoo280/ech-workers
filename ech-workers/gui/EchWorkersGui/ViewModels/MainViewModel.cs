using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using System.Net.Http;
using EchWorkersGui.Infrastructure;
using EchWorkersGui.Models;
using EchWorkersGui.Services;

namespace EchWorkersGui.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly ConfigService _configService = new();
    private readonly CoreProcessService _core = new();

    private readonly ConcurrentQueue<string> _pendingLogs = new();
    private readonly Queue<string> _logLines = new();
    private readonly DispatcherTimer _logUpdateTimer;
    private readonly StringBuilder _logBuilder = new();
    private const int MaxLogLines = 1500;

    public GlobalConfig Global { get; }

    public ObservableCollection<NodeConfig> Nodes { get; }

    private NodeConfig? _selectedNode;
    public NodeConfig? SelectedNode
    {
        get => _selectedNode;
        set
        {
            if (SetProperty(ref _selectedNode, value))
            {
                OnPropertyChanged(nameof(HasSelectedNode));
                RaiseCommandStates();
            }
        }
    }

    public bool HasSelectedNode => SelectedNode != null;

    private bool _isRunning;
    public bool CanStart => !_isRunning && SelectedNode != null;
    public bool CanStop => _isRunning;

    private string _statusText = "未运行";
    public string StatusText { get => _statusText; private set => SetProperty(ref _statusText, value); }

    private string _logText = "";
    public string LogText { get => _logText; private set => SetProperty(ref _logText, value); }

    public RelayCommand AddNodeCommand { get; }
    public RelayCommand DeleteNodeCommand { get; }
    public RelayCommand SaveAllCommand { get; }
    public RelayCommand StartCoreCommand { get; }
    public RelayCommand StopCoreCommand { get; }
    public RelayCommand BrowseCorePathCommand { get; }

    public MainViewModel()
    {
        // 先初始化 Commands（必须在设置 SelectedNode 之前，否则 RaiseCommandStates 会空引用）
        AddNodeCommand = new RelayCommand(AddNode);
        DeleteNodeCommand = new RelayCommand(DeleteSelectedNode, () => HasSelectedNode && !_isRunning);
        SaveAllCommand = new RelayCommand(SaveAll);
        StartCoreCommand = new RelayCommand(async () => await StartCoreAsync(), () => CanStart);
        StopCoreCommand = new RelayCommand(async () => await StopCoreInternalAsync(), () => CanStop);
        BrowseCorePathCommand = new RelayCommand(BrowseCorePath);

        var cfg = _configService.Load();
        Global = cfg.Global;

        Nodes = new ObservableCollection<NodeConfig>(cfg.Nodes);
        SelectedNode = Nodes.FirstOrDefault(n => n.Id == cfg.SelectedNodeId) ?? Nodes.FirstOrDefault();

        // 优化：使用异步调度 + 批量更新日志（避免UI线程阻塞）
        _core.OnLogLine += line => _pendingLogs.Enqueue(line);
        _core.OnExited += () => Application.Current.Dispatcher.InvokeAsync(() =>
        {
            _isRunning = false;
            StatusText = "未运行";
            RaiseCommandStates();
        });

        // 定时器：每100ms批量处理日志（降低UI更新频率）
        _logUpdateTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(100)
        };
        _logUpdateTimer.Tick += (_, _) => ProcessPendingLogs();
        _logUpdateTimer.Start();

        AppendLog("[GUI] 配置文件: " + _configService.ConfigFilePath);
    }

    private void RaiseCommandStates()
    {
        DeleteNodeCommand.RaiseCanExecuteChanged();
        StartCoreCommand.RaiseCanExecuteChanged();
        StopCoreCommand.RaiseCanExecuteChanged();
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(CanStop));
    }

    private void ProcessPendingLogs()
    {
        if (_pendingLogs.IsEmpty) return;

        var batchCount = 0;
        var needsRebuild = false;

        // 批量处理待处理日志（最多200条/次，避免单次处理时间过长）
        while (batchCount < 200 && _pendingLogs.TryDequeue(out var line))
        {
            _logLines.Enqueue(line);
            batchCount++;

            // 超过最大行数时需要重建
            if (_logLines.Count > MaxLogLines)
            {
                _logLines.Dequeue();
                needsRebuild = true;
            }
        }

        if (batchCount == 0) return;

        // 优化：仅在需要时重建完整日志，否则增量追加
        if (needsRebuild || _logBuilder.Length == 0)
        {
            _logBuilder.Clear();
            foreach (var line in _logLines)
            {
                if (_logBuilder.Length > 0) _logBuilder.AppendLine();
                _logBuilder.Append(line);
            }
        }
        else
        {
            // 增量追加新行
            var newLines = _logLines.Skip(_logLines.Count - batchCount);
            foreach (var line in newLines)
            {
                if (_logBuilder.Length > 0) _logBuilder.AppendLine();
                _logBuilder.Append(line);
            }
        }

        LogText = _logBuilder.ToString();
    }

    private void AppendLog(string line)
    {
        _pendingLogs.Enqueue(line);
    }

    private void AddNode()
    {
        if (_isRunning)
        {
            AppendLog("[GUI] 请先停止内核再编辑节点");
            return;
        }

        var node = new NodeConfig();
        Nodes.Add(node);
        SelectedNode = node;
        SaveAll();
    }

    private void BrowseCorePath()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择内核程序",
            Filter = "可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*",
            FileName = "ech-workers-core.exe"
        };

        if (dialog.ShowDialog() == true)
        {
            Global.CorePath = dialog.FileName;
            SaveAll();
        }
    }

    private void DeleteSelectedNode()
    {
        if (_isRunning)
        {
            AppendLog("[GUI] 运行中无法删除节点");
            return;
        }

        if (SelectedNode == null) return;
        if (Nodes.Count <= 1)
        {
            AppendLog("[GUI] 至少保留一个节点");
            return;
        }

        var target = SelectedNode;
        Nodes.Remove(target);
        SelectedNode = Nodes.FirstOrDefault();
        SaveAll();
    }

    private void SaveAll()
    {
        var cfg = new AppConfig
        {
            Global = Global,
            Nodes = Nodes.ToList(),
            SelectedNodeId = SelectedNode?.Id
        };

        _configService.Save(cfg);
        AppendLog("[GUI] 配置已保存");
        RaiseCommandStates();
    }

    private async Task StartCoreAsync()
    {
        if (SelectedNode == null) return;

        if (string.IsNullOrWhiteSpace(SelectedNode.ServerAddr))
        {
            AppendLog("[GUI] 服务器地址不能为空");
            return;
        }

        if (string.IsNullOrWhiteSpace(Global.ListenAddr))
        {
            AppendLog("[GUI] 监听地址不能为空");
            return;
        }

        var corePath = Global.CorePath;
        if (string.IsNullOrWhiteSpace(corePath))
        {
            // 默认尝试同目录的 ech-workers-core.exe
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            corePath = Path.Combine(baseDir, "ech-workers-core.exe");
        }

        if (!File.Exists(corePath))
        {
            AppendLog("[GUI] 找不到内核: " + corePath);
            AppendLog("[GUI] 请在全局配置里填写 CorePath（内核 exe 路径）");
            return;
        }

        SaveAll();

        bool ok;

        if (Global.EnableTun && !CoreProcessService.IsAdministrator())
        {
            var logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);
            var logFile = Path.Combine(logDir, "core.log");

            try
            {
                File.WriteAllText(logFile, "");
            }
            catch
            {
                // ignore
            }

            var args = CoreProcessService.BuildArguments(
                listenAddr: Global.ListenAddr,
                enableSysProxy: Global.EnableSysProxy,
                enableTun: Global.EnableTun,
                tunIp: Global.TunIp,
                tunGateway: Global.TunGateway,
                tunMask: Global.TunMask,
                tunDns: Global.TunDns,
                tunMtu: Global.TunMtu,
                serverAddr: SelectedNode.ServerAddr,
                serverIp: SelectedNode.ServerIp,
                token: SelectedNode.Token,
                protoMode: SelectedNode.ProtoMode,
                numConns: SelectedNode.NumConns,
                enableYamux: SelectedNode.EnableYamux,
                enableEch: SelectedNode.EnableEch,
                echDomain: SelectedNode.EchDomain,
                dnsServer: SelectedNode.DnsServer,
                logFilePath: logFile);

            AppendLog("[GUI] 启用 TUN：将请求 UAC 管理员权限启动内核");
            ok = _core.StartElevated(corePath, args, logFile);
        }
        else
        {
            var psi = CoreProcessService.BuildStartInfo(
                coreExePath: corePath,
                listenAddr: Global.ListenAddr,
                enableSysProxy: Global.EnableSysProxy,
                enableTun: Global.EnableTun,
                tunIp: Global.TunIp,
                tunGateway: Global.TunGateway,
                tunMask: Global.TunMask,
                tunDns: Global.TunDns,
                tunMtu: Global.TunMtu,
                serverAddr: SelectedNode.ServerAddr,
                serverIp: SelectedNode.ServerIp,
                token: SelectedNode.Token,
                protoMode: SelectedNode.ProtoMode,
                numConns: SelectedNode.NumConns,
                enableYamux: SelectedNode.EnableYamux,
                enableEch: SelectedNode.EnableEch,
                echDomain: SelectedNode.EchDomain,
                dnsServer: SelectedNode.DnsServer,
                logFilePath: null);

            AppendLog("[GUI] 启动内核: " + corePath);
            ok = _core.Start(psi);
        }

        if (!ok)
        {
            AppendLog("[GUI] 启动失败：进程未能启动");
            return;
        }

        _isRunning = true;
        StatusText = "运行中";
        RaiseCommandStates();
    }

    private async Task StopCoreInternalAsync()
    {
        AppendLog("[GUI] 正在停止内核...");
        await _core.StopAsync();
        _isRunning = false;
        StatusText = "未运行";
        RaiseCommandStates();
    }

    public async Task StopCoreAsync()
    {
        await StopCoreInternalAsync();
    }
}
