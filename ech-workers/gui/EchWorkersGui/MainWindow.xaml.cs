using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows;
using EchWorkersGui.ViewModels;
using Hardcodet.Wpf.TaskbarNotification;

namespace EchWorkersGui;

public partial class MainWindow : Window
{
    private TaskbarIcon? _trayIcon;
    private readonly MainViewModel _viewModel;
    private bool _isExiting;

    public MainWindow()
    {
        InitializeComponent();
        _viewModel = new MainViewModel();
        DataContext = _viewModel;

        InitializeTrayIcon();

        // 窗口状态改变时处理最小化
        StateChanged += OnStateChanged;
    }

    private void InitializeTrayIcon()
    {
        // 创建托盘图标
        _trayIcon = new TaskbarIcon
        {
            ToolTipText = "ECH Workers",
            Visibility = Visibility.Visible
        };

        // 使用资源中的图标
        try
        {
            var iconUri = new Uri("pack://application:,,,/Resources/app.ico", UriKind.Absolute);
            var iconStream = Application.GetResourceStream(iconUri)?.Stream;
            if (iconStream != null)
            {
                _trayIcon.Icon = new System.Drawing.Icon(iconStream);
            }
            else
            {
                _trayIcon.Icon = System.Drawing.Icon.ExtractAssociatedIcon(
                    System.Reflection.Assembly.GetExecutingAssembly().Location);
            }
        }
        catch
        {
            // 如果无法获取图标，使用系统默认图标
            _trayIcon.Icon = SystemIcons.Application;
        }

        // 双击托盘图标显示主窗口
        _trayIcon.TrayMouseDoubleClick += (_, _) => ShowMainWindow();

        // 创建右键菜单
        var contextMenu = new System.Windows.Controls.ContextMenu();

        var showItem = new System.Windows.Controls.MenuItem { Header = "打开主界面" };
        showItem.Click += (_, _) => ShowMainWindow();
        contextMenu.Items.Add(showItem);

        contextMenu.Items.Add(new System.Windows.Controls.Separator());

        var sysProxyItem = new System.Windows.Controls.MenuItem { Header = "开启系统代理" };
        sysProxyItem.Click += (_, _) =>
        {
            _viewModel.Global.EnableSysProxy = true;
            _viewModel.Global.EnableTun = false;
            if (_viewModel.CanStart && _viewModel.SelectedNode != null)
            {
                _viewModel.StartCoreCommand.Execute(null);
            }
        };
        contextMenu.Items.Add(sysProxyItem);

        var tunItem = new System.Windows.Controls.MenuItem { Header = "开启 TUN 模式" };
        tunItem.Click += (_, _) =>
        {
            _viewModel.Global.EnableTun = true;
            _viewModel.Global.EnableSysProxy = false;
            if (_viewModel.CanStart && _viewModel.SelectedNode != null)
            {
                _viewModel.StartCoreCommand.Execute(null);
            }
        };
        contextMenu.Items.Add(tunItem);

        var stopItem = new System.Windows.Controls.MenuItem { Header = "停止" };
        stopItem.Click += (_, _) =>
        {
            if (_viewModel.CanStop)
            {
                _viewModel.StopCoreCommand.Execute(null);
            }
        };
        contextMenu.Items.Add(stopItem);

        contextMenu.Items.Add(new System.Windows.Controls.Separator());

        var exitItem = new System.Windows.Controls.MenuItem { Header = "退出" };
        exitItem.Click += (_, _) => ExitApplication();
        contextMenu.Items.Add(exitItem);

        _trayIcon.ContextMenu = contextMenu;
    }

    private void ShowMainWindow()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void OnStateChanged(object? sender, EventArgs e)
    {
        // 最小化时隐藏到托盘
        if (WindowState == WindowState.Minimized)
        {
            Hide();
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_isExiting)
        {
            // 点击 X 时隐藏到托盘而不是退出
            e.Cancel = true;
            Hide();
            return;
        }

        base.OnClosing(e);
    }

    private async void ExitApplication()
    {
        _isExiting = true;

        // 停止内核进程
        if (_viewModel.CanStop)
        {
            await _viewModel.StopCoreAsync();
        }

        CleanupTrayIcon();
        Application.Current.Shutdown();
    }

    protected override void OnClosed(EventArgs e)
    {
        CleanupTrayIcon();
        base.OnClosed(e);
    }

    private void CleanupTrayIcon()
    {
        if (_trayIcon == null) return;
        _trayIcon.Dispose();
        _trayIcon = null;
    }
}
