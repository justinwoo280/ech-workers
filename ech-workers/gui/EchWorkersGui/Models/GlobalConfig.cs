using EchWorkersGui.Infrastructure;

namespace EchWorkersGui.Models;

public sealed class GlobalConfig : ObservableObject
{
    private string _listenAddr = "127.0.0.1:30000";
    private bool _enableSysProxy = false;

    private bool _enableTun = false;
    private string _tunIp = "10.0.85.2";
    private string _tunGateway = "10.0.85.1";
    private string _tunMask = "255.255.255.0";
    private string _tunDns = "1.1.1.1";
    private int _tunMtu = 1380;

    private string _corePath = "";

    public string ListenAddr { get => _listenAddr; set => SetProperty(ref _listenAddr, value); }
    public bool EnableSysProxy { get => _enableSysProxy; set => SetProperty(ref _enableSysProxy, value); }

    public bool EnableTun { get => _enableTun; set => SetProperty(ref _enableTun, value); }
    public string TunIp { get => _tunIp; set => SetProperty(ref _tunIp, value); }
    public string TunGateway { get => _tunGateway; set => SetProperty(ref _tunGateway, value); }
    public string TunMask { get => _tunMask; set => SetProperty(ref _tunMask, value); }
    public string TunDns { get => _tunDns; set => SetProperty(ref _tunDns, value); }
    public int TunMtu { get => _tunMtu; set => SetProperty(ref _tunMtu, value); }

    public string CorePath { get => _corePath; set => SetProperty(ref _corePath, value); }
}
