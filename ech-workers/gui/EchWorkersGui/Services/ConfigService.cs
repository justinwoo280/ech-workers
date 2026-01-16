using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using EchWorkersGui.Models;

namespace EchWorkersGui.Services;

public sealed class ConfigService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public string ConfigFilePath { get; }

    public ConfigService()
    {
        // 配置文件放在程序根目录的 config 文件夹下
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var dir = Path.Combine(baseDir, "config");
        Directory.CreateDirectory(dir);
        ConfigFilePath = Path.Combine(dir, "config.json");
    }

    public AppConfig Load()
    {
        if (!File.Exists(ConfigFilePath))
        {
            var cfg = new AppConfig();
            if (cfg.Nodes.Count == 0)
            {
                cfg.Nodes.Add(new NodeConfig());
                cfg.SelectedNodeId = cfg.Nodes[0].Id;
            }
            return cfg;
        }

        var json = File.ReadAllText(ConfigFilePath);
        var cfgLoaded = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions) ?? new AppConfig();

        if (cfgLoaded.Nodes.Count == 0)
        {
            cfgLoaded.Nodes.Add(new NodeConfig());
            cfgLoaded.SelectedNodeId = cfgLoaded.Nodes[0].Id;
        }

        if (string.IsNullOrWhiteSpace(cfgLoaded.SelectedNodeId) || cfgLoaded.Nodes.All(n => n.Id != cfgLoaded.SelectedNodeId))
        {
            cfgLoaded.SelectedNodeId = cfgLoaded.Nodes[0].Id;
        }

        return cfgLoaded;
    }

    public void Save(AppConfig config)
    {
        var json = JsonSerializer.Serialize(config, JsonOptions);
        
        // 原子性写入：先写临时文件，成功后替换原文件
        var tempPath = ConfigFilePath + ".tmp";
        File.WriteAllText(tempPath, json);
        File.Move(tempPath, ConfigFilePath, overwrite: true);
    }
}
