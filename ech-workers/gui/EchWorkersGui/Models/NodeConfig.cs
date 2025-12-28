using System;
using EchWorkersGui.Infrastructure;

namespace EchWorkersGui.Models;

public sealed class NodeConfig : ObservableObject
{
    private string _id = Guid.NewGuid().ToString("N");
    private string _name = "新节点";
    private string _serverAddr = "";
    private string _serverIp = "";
    private string _token = "";
    private string _protoMode = "ws";
    private int _numConns = 1;

    private bool _enableEch = true;
    private string _echDomain = "cloudflare-ech.com";
    private string _dnsServer = "dns.alidns.com/dns-query";
    private bool _enableYamux = true;

    public string Id { get => _id; set => SetProperty(ref _id, value); }
    public string Name { get => _name; set => SetProperty(ref _name, value); }
    public string ServerAddr { get => _serverAddr; set => SetProperty(ref _serverAddr, value); }
    public string ServerIp { get => _serverIp; set => SetProperty(ref _serverIp, value); }
    public string Token { get => _token; set => SetProperty(ref _token, value); }

    public string ProtoMode { get => _protoMode; set => SetProperty(ref _protoMode, value); }
    public int NumConns { get => _numConns; set => SetProperty(ref _numConns, value); }

    public bool EnableEch { get => _enableEch; set => SetProperty(ref _enableEch, value); }
    public string EchDomain { get => _echDomain; set => SetProperty(ref _echDomain, value); }
    public string DnsServer { get => _dnsServer; set => SetProperty(ref _dnsServer, value); }
    public bool EnableYamux { get => _enableYamux; set => SetProperty(ref _enableYamux, value); }
}
