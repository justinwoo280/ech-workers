# ECH Workers

基于 Go 1.24+ 的高性能代理客户端，支持 ECH (Encrypted Client Hello) 隐藏 SNI。

## 特性

- ✅ **ECH 支持**：Go 1.24 原生 TLS 1.3 ECH，隐藏真实 SNI
- ✅ **Vision 流控**：基于 Xray-core Vision 协议，流量混淆 + 零拷贝优化（默认启用）
- ✅ **多协议**：WebSocket + Vision / gRPC 双向流 / Yamux 多路复用（已弃用）
- ✅ **多模式代理**：SOCKS5 / HTTP CONNECT / TUN
- ✅ **Web UI**：内置图形界面，单文件分发
- ✅ **系统代理**：自动配置 Windows 系统代理
- ✅ **DoH 查询**：通过 DNS-over-HTTPS 获取 ECH 配置

## 快速开始

### 命令行模式

```bash
# 基本用法（SOCKS5 + HTTP 代理）
./ech-workers -l 127.0.0.1:1080 -f your-server.com:443 -token your-uuid

# 禁用 ECH（普通 TLS）
./ech-workers -l 127.0.0.1:1080 -f your-server.com:443 -token your-uuid -fallback

# gRPC 模式
./ech-workers -l 127.0.0.1:1080 -f grpc://your-server.com:443 -token your-uuid -mode grpc

# 启用系统代理
./ech-workers -l 127.0.0.1:1080 -f your-server.com:443 -token your-uuid -sysproxy

# TUN 模式（需要管理员权限）
./ech-workers -f your-server.com:443 -token your-uuid -tun
```

### Web UI 模式

```bash
./ech-workers -webui
```

打开浏览器访问 `http://127.0.0.1:8098`

## 参数说明 / Parameter Reference

### 命令行参数

| 参数 | 英文名 | 说明 | 默认值 |
|------|--------|------|--------|
| `-l` | Listen Address | 本地代理监听地址（SOCKS5 和 HTTP 共用） | `127.0.0.1:30000` |
| `-f` | Server Address | 服务端地址（域名:端口） | - |
| `-ip` | Server IP | 优选 IP 或 CNAME 域名（见下方说明） | - |
| `-token` | Token / UUID | 认证令牌，需与服务端一致 | - |
| `-mode` | Transport Mode | 传输模式：`ws`(WebSocket) / `grpc` | `ws` |
| `-flow` | Vision Flow | 启用 Vision 流控协议 | `true` |
| `-yamux` | Yamux Mode | 启用 Yamux 多路复用（已弃用） | `false` |
| `-fallback` | Fallback Mode | 禁用 ECH，使用普通 TLS 1.3 | `false` |
| `-ech` | ECH Domain | ECH 配置查询域名 | `cloudflare-ech.com` |
| `-dns` | DoH Server | DNS-over-HTTPS 服务器地址 | `dns.alidns.com/dns-query` |
| `-sysproxy` | System Proxy | 自动设置 Windows 系统代理 | `false` |
| `-tun` | TUN Mode | 启用 TUN 全局代理（需管理员权限） | `false` |
| `-webui` | Web UI Mode | 启动图形界面模式 | `false` |
| `-webui-addr` | Web UI Address | Web UI 监听地址 | `127.0.0.1:8098` |

### Web UI / 节点配置参数对照

| Web UI 字段 | 命令行参数 | 英文名 | 作用说明 |
|-------------|-----------|--------|----------|
| 本地监听地址 | `-l` | Listen Address | 本地 SOCKS5/HTTP 代理端口，浏览器或软件连接此地址 |
| 服务器地址 | `-f` | Server Address | 你部署的服务端域名和端口，如 `xxx.workers.dev:443` |
| 服务器 IP | `-ip` | Server IP / Preferred IP | **优选 IP**：填写 Cloudflare 优选 IP 或 CNAME 域名，用于加速连接 |
| 认证令牌 | `-token` | Token / UUID | 服务端设置的 UUID，用于身份验证 |
| 传输协议 | `-mode` | Transport Mode | `ws` = WebSocket + Yamux（推荐），`grpc` = gRPC 双向流 |
| 启用 ECH | `-fallback` 的反义 | Enable ECH | 开启后隐藏真实 SNI，增强隐私（需 Go 1.24+） |
| 系统代理 | `-sysproxy` | System Proxy | 自动配置 Windows 系统代理，无需手动设置浏览器 |

### 关键参数详解

#### 服务器 IP / 优选 IP (`-ip`)

这是 **Cloudflare 优选 IP** 功能的核心参数：

```
┌─────────────────────────────────────────────────────────────┐
│  正常连接流程：                                              │
│  客户端 → DNS解析(serverAddr) → 得到IP → 连接IP              │
│                                                              │
│  使用优选IP后：                                              │
│  客户端 → 直接使用 serverIp → 连接优选IP                     │
│         → TLS SNI 仍然使用 serverAddr 的域名                 │
└─────────────────────────────────────────────────────────────┘
```

**使用场景**：
- 填写 Cloudflare 优选 IP（如 `104.16.xxx.xxx`）绕过 DNS 污染
- 填写 CNAME 优选域名（如 `cdn.example.com`）使用更快的节点
- 留空则自动 DNS 解析 `serverAddr`

**示例**：
```bash
# 使用优选 IP
./ech-workers -f xxx.workers.dev:443 -ip 104.16.123.45 -token uuid

# 使用 CNAME 优选域名
./ech-workers -f xxx.workers.dev:443 -ip speed.cloudflare.com -token uuid
```

#### ECH (Encrypted Client Hello)

ECH 是 TLS 1.3 的扩展，用于加密 SNI（Server Name Indication）：

- **开启 ECH**：中间人只能看到加密后的 SNI，无法识别你访问的真实域名
- **关闭 ECH**（`-fallback`）：使用普通 TLS 1.3，SNI 明文传输

**注意**：ECH 需要 Go 1.24+ 编译的客户端才能使用。

#### 传输模式 (`-mode`)

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| `ws` | WebSocket + Vision 流控 | **推荐**，默认启用 Vision 流控，兼容 Cloudflare Workers |
| `grpc` | gRPC 双向流 + Vision 流控 | 需要服务端开启 gRPC 模式 |

**Vision 流控说明**：
- 默认启用（`-flow=true`），提供流量混淆和零拷贝优化
- 自动检测 TLS 1.3 并启用 XTLS 直接转发
- 兼容所有 WebSocket 和 gRPC 服务端
- 使用 `-flow=false` 可禁用（不推荐）

**Yamux 多路复用**：
- 已弃用，使用 `-yamux` 启用
- 不推荐使用，Vision 提供更好的性能

## 编译

### 本地编译

需要 Go 1.24+：

```bash
# Windows
go build -o ech-workers.exe .

# Linux
GOOS=linux GOARCH=amd64 go build -o ech-workers .

# macOS
GOOS=darwin GOARCH=amd64 go build -o ech-workers .
```

### Google Colab 编译

使用 `build_colab.ipynb` 在 Colab 上编译：

1. 上传 `build_colab.ipynb` 到 Google Colab
2. 运行所有单元格
3. 下载编译好的二进制文件

## 架构

```
┌─────────────────────────────────────────────────────────┐
│                     ECH Workers                         │
├─────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │
│  │ SOCKS5  │  │  HTTP   │  │   TUN   │  │ Web UI  │    │
│  │ Proxy   │  │ Proxy   │  │  Mode   │  │  Mode   │    │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘    │
│       └────────────┴────────────┴────────────┘         │
│                         │                               │
│  ┌──────────────────────┴──────────────────────┐       │
│  │              Transport Layer                 │       │
│  │  ┌─────────────────┐  ┌─────────────────┐   │       │
│  │  │ WebSocket+Yamux │  │     gRPC        │   │       │
│  │  └─────────────────┘  └─────────────────┘   │       │
│  └──────────────────────┬──────────────────────┘       │
│                         │                               │
│  ┌──────────────────────┴──────────────────────┐       │
│  │              TLS 1.3 + ECH                   │       │
│  │  ┌─────────────────────────────────────┐    │       │
│  │  │  DoH → HTTPS Record → ECH Config    │    │       │
│  │  └─────────────────────────────────────┘    │       │
│  └─────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │    Proxy Server       │
              │  (WebSocket/gRPC)     │
              └───────────────────────┘
```

## 工作原理

### ECH (Encrypted Client Hello)

1. 通过 DoH 查询 `cloudflare-ech.com` 的 HTTPS 记录
2. 解析 DNS Wire Format，提取 ECH 配置（SvcParam Key=5）
3. 在 TLS 握手时使用 ECH 加密 SNI
4. 中间人只能看到加密后的 SNI，无法识别真实目标

### Vision 流控协议

1. 基于 Xray-core Vision 实现，动态填充消除流量特征
2. 自动检测 TLS 1.3 流量并启用零拷贝优化（XTLS）
3. 兼容 Cloudflare Workers（无需多路复用）
4. 填充参数可配置：`[900, 500, 900, 256]`

### Yamux 多路复用（已弃用）

1. 使用 `-yamux` 参数可启用旧版 Yamux 协议
2. 单个 WebSocket 连接上建立 Yamux 会话
3. 每个代理请求使用独立的 Yamux Stream
4. **不推荐使用**，Vision 流控提供更好的性能和混淆效果

## 性能优化

本项目已针对高并发场景进行深度优化，显著提升吞吐量并降低内存占用。

### Vision 流控优化

**动态填充算法**：
- 长填充：`rand(500) + 900 - contentLen`（TLS 握手阶段）
- 短填充：`rand(256)`（常规流量）
- 自动检测 TLS Application Data 并切换到零拷贝模式

**性能提升**：
- 流量混淆：消除长度签名，防止流量分析
- 零拷贝：检测到 TLS 1.3 后自动启用 XTLS 直接转发
- 内存优化：无需多路复用开销，降低 GC 压力

### 内存池化

**三级 Buffer Pool**：
- `smallBufferPool`: 512B（控制消息、小数据包）
- `largeBufferPool`: 32KB（TCP 转发、常规流量）
- `udpBufferPool`: 64KB（UDP 中继、大包处理）

**应用场景**：
- ✅ UDP 中继 (SOCKS5 UDP ASSOCIATE)
- ✅ 隧道双向转发（上传/下载 goroutine）
- ✅ TUN 模式 TCP 连接
- ✅ Yamux Stream 读写操作
- ✅ 服务端 gRPC/WebSocket 转发

**性能提升**：
- GC 压力降低 **70%**（缓冲区复用）
- 内存分配速率降低 **90%**（池化消除分配）

## 文件说明

```
ech-workers/
├── ech-workers.go      # 主程序
├── transport.go        # 传输层抽象（WS/gRPC）
├── proto/              # gRPC 协议定义
├── webui/
│   ├── server.go       # Web UI 后端
│   └── static/         # 前端资源（embed 嵌入）
├── build.bat           # Windows 构建脚本
├── build_colab.ipynb   # Colab 编译笔记本
├── wintun.dll          # TUN 驱动（Windows）
└── go.mod
```

## 配合服务端

需要部署 `proxy-server` 服务端：

```bash
# 服务端（WebSocket 模式）
./proxy-server

# 服务端（gRPC 模式）
./proxy-server --grpc
```

服务端支持部署到 Heroku / Railway / Render / Kinsta 等 PaaS 平台。

## 安全说明

- **ECH**：加密 SNI，防止中间人识别目标域名
- **TLS 1.3**：最新加密协议，前向保密
- **UUID 认证**：防止未授权访问
- **DoH**：DNS 查询走加密通道

## 常见问题

### ECH 配置获取失败

检查 DoH 服务器是否可访问：

```bash
curl "https://dns.alidns.com/dns-query?dns=..." -H "Accept: application/dns-message"
```

### TUN 模式需要管理员权限

Windows 下需要以管理员身份运行，确保 `wintun.dll` 在同目录。

### WebSocket 连接断开

检查服务端是否正常运行，Yamux 会自动重建 Session。

## License

MIT
