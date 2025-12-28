using System.Collections.Generic;

namespace EchWorkersGui.Models;

public sealed class AppConfig
{
    public GlobalConfig Global { get; set; } = new();
    public List<NodeConfig> Nodes { get; set; } = new();
    public string? SelectedNodeId { get; set; }
}
