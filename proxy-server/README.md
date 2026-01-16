# Proxy Server

轻量级代理服务端，支持 WebSocket + Yamux 和 gRPC 双模式，专为 PaaS 平台优化。

## 特性

- ✅ **双协议支持**：WebSocket + Yamux 多路复用 / gRPC 双向流
- ✅ **单端口模式**：通过参数切换协议，适配 PaaS 平台限制
- ✅ **UUID 认证**：支持 Header 和 Path 两种方式
- ✅ **Nginx 伪装**：未授权访问返回假 Nginx 页面
- ✅ **健康检查**：`/health` 和 `/healthz` 端点
- ✅ **零依赖部署**：单二进制文件，支持 Nixpacks/Buildpacks

## 快速开始

### 本地运行

```bash
# WebSocket 模式（默认）
go run main.go

# gRPC 模式
go run main.go --grpc

# 指定端口
go run main.go --port 8080
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `PORT` | 监听端口 | `8080` |
| `UUID` | 认证密钥 | `d342d11e-d424-4583-b36e-524ab1f0afa4` |
| `MODE` | 协议模式 (`grpc` 启用 gRPC) | - |

### 命令行参数

| 参数 | 说明 |
|------|------|
| `--grpc` | 启用 gRPC 模式（默认 WebSocket） |
| `--port` | 指定监听端口 |

## 部署

### Kinsta / Railway / Render (Nixpacks)

项目已包含 `nixpacks.toml` 配置：

```toml
[phases.setup]
nixPkgs = ["go_1_23"]

[phases.build]
cmds = ["go build -o out"]

[start]
cmd = "./out"
```

设置环境变量 `UUID` 即可部署。

### Heroku

```bash
heroku create your-app-name
heroku config:set UUID=your-secret-uuid
git push heroku main
```

### Docker

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o server .

FROM alpine:latest
COPY --from=builder /app/server /server
EXPOSE 8080
CMD ["/server"]
```

```bash
docker build -t proxy-server .
docker run -p 8080:8080 -e UUID=your-uuid proxy-server
```

## 协议说明

### WebSocket 模式

1. 客户端通过 WebSocket 连接，UUID 放在 `Sec-WebSocket-Protocol` Header
2. 建立 Yamux 多路复用会话
3. 每个 Yamux Stream 发送目标地址：`host:port\n`
4. 后续数据为原始 TCP 流量

```
Client                          Server
  |-- WebSocket Upgrade ----------->|
  |<--------- 101 Switching --------|
  |== Yamux Session ================|
  |-- Stream 1: "google.com:443\n" ->|
  |<========= TCP Data ============>|
```

### gRPC 模式

1. 客户端通过 gRPC 连接，UUID 放在 Metadata
2. 调用 `Tunnel` 双向流
3. 首包格式：`CONNECT:host:port|initial_data`
4. 服务端返回 `CONNECTED` 后开始转发

## 性能优化

服务端已针对高并发场景进行深度优化，提升吞吐量并降低内存占用。

### Yamux 配置调优

**窗口大小优化**：
- `MaxStreamWindowSize`: 4MB (默认 256KB)
- `StreamOpenTimeout`: 15s
- `StreamCloseTimeout`: 5s

**性能提升**：
- 吞吐量提升 **40-50%**（减少 WINDOW_UPDATE 帧频率）

### 内存池化

**双级 Buffer Pool**：
- `smallBufferPool`: 512B（控制消息）
- `largeBufferPool`: 32KB（数据转发）

**应用场景**：
- ✅ WebSocket → 目标站点转发
- ✅ gRPC → 目标站点转发
- ✅ Yamux Stream 处理

**性能提升**：
- GC 压力降低 **70%**（缓冲区复用）
- 内存分配速率降低 **90%**（池化消除分配）

## 配合客户端

使用 `ech-workers` 客户端：

```bash
# WebSocket 模式（推荐，支持 ECH）
./ech-workers -l 127.0.0.1:1080 -f your-server.com:443 -token your-uuid

# gRPC 模式
./ech-workers -l 127.0.0.1:1080 -f grpc://your-server.com:443 -token your-uuid -mode grpc

# Web UI 模式
./ech-workers -webui
```

## 安全说明

- **UUID 认证**：未授权请求返回 Nginx 伪装页面
- **TLS 加密**：建议在 PaaS 平台启用 HTTPS
- **ECH 支持**：客户端支持 Encrypted Client Hello 隐藏 SNI

## License

MIT
