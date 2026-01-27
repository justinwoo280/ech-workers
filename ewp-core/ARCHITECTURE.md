# ECH Workers Client - 新架构设计

本文档描述了参考 sing-box 风格重构后的架构。

## 目录结构

```
ech-workers/
├── cmd/
│   └── ech-workers/
│       └── main.go                    # 入口文件
│
├── constant/                          # 常量定义
│   └── constant.go                    # 传输模式、默认值等
│
├── log/                               # 日志模块
│   └── log.go                         # 日志封装（支持 verbose 模式）
│
├── option/                            # 配置管理
│   └── config.go                      # 配置结构和参数解析
│
├── dns/                               # DNS 模块
│   ├── query.go                       # DNS 协议构建和解析
│   └── doh.go                         # DoH 客户端
│
├── common/                            # 通用工具
│   ├── tls/                           # TLS 配置
│   │   ├── config.go                  # TLS 配置构建（支持 PQC）
│   │   └── ech.go                     # ECH 管理器
│   └── bufferpool/                    # Buffer 池
│       └── pool.go                    # 内存池管理
│
├── protocol/                          # 应用层协议
│   ├── ewp/                           # EWP 协议（从 ewp/ 移动）
│   │   ├── address.go
│   │   ├── flow.go
│   │   ├── flow_state.go
│   │   ├── flow_writer.go
│   │   ├── protocol.go
│   │   ├── security.go
│   │   └── udp.go
│   ├── socks5/                        # SOCKS5 协议（待实现）
│   │   ├── server.go
│   │   └── handler.go
│   └── http/                          # HTTP 代理协议（待实现）
│       ├── server.go
│       └── handler.go
│
├── transport/                         # 传输层
│   ├── transport.go                   # 接口定义
│   ├── websocket/                     # WebSocket 传输
│   │   ├── transport.go               # WebSocket Transport
│   │   ├── conn_simple.go             # 简单模式连接
│   │   └── conn_flow.go               # Flow 模式连接
│   ├── grpc/                          # gRPC 传输（待实现）
│   │   ├── transport.go
│   │   └── conn.go
│   └── xhttp/                         # XHTTP 传输（待实现）
│       ├── transport.go
│       └── conn.go
│
├── tun/                               # TUN 模式（待实现）
│   ├── tun.go                         # TUN 设备管理
│   ├── stack.go                       # gVisor 网络栈
│   ├── handler_tcp.go                 # TCP 处理
│   └── handler_udp.go                 # UDP 处理
│
└── proto/                             # Protobuf 定义（保持不变）
    ├── tunnel.proto
    ├── tunnel.pb.go
    └── tunnel_grpc.pb.go
```

## 模块职责

### 核心模块（已完成）

| 模块 | 职责 | 状态 |
|------|------|------|
| `constant/` | 全局常量定义 | ✅ 完成 |
| `log/` | 日志系统封装 | ✅ 完成 |
| `option/` | 配置和参数管理 | ✅ 完成 |
| `dns/` | DoH 查询和 DNS 协议 | ✅ 完成 |
| `common/tls/` | TLS、ECH、PQC 配置 | ✅ 完成 |
| `common/bufferpool/` | 内存池管理 | ✅ 完成 |
| `protocol/ewp/` | EWP 核心协议 | ✅ 已移动 |
| `transport/` | 传输层接口 | ✅ 接口完成 |
| `transport/websocket/` | WebSocket 传输 | ⚠️ 框架完成 |
| `cmd/ech-workers/` | 程序入口 | ⚠️ 框架完成 |

### 待实现模块

| 模块 | 职责 | 优先级 |
|------|------|--------|
| `protocol/socks5/` | SOCKS5 入站协议 | 🔴 高 |
| `protocol/http/` | HTTP 代理协议 | 🔴 高 |
| `transport/grpc/` | gRPC 传输实现 | 🟡 中 |
| `transport/xhttp/` | XHTTP 传输实现 | 🟡 中 |
| `tun/` | TUN 全局代理 | 🟡 中 |

## 设计原则

### 1. 模块化

每个模块职责单一：
- `dns/` 只负责 DNS 查询
- `tls/` 只负责 TLS 配置
- `transport/` 只负责传输层连接
- `protocol/` 只负责应用层协议

### 2. 分层架构

```
应用层:   protocol/socks5, protocol/http  (入站)
          protocol/ewp                      (核心协议)
          ↓
传输层:   transport/websocket, transport/grpc, transport/xhttp
          ↓
TLS 层:   common/tls  (ECH + PQC)
          ↓
网络层:   net.Conn
```

### 3. 接口抽象

参考 sing-box 的适配器模式：
```go
// 传输层接口
type Transport interface {
    Dial() (TunnelConn, error)
    Name() string
}

// 隧道连接接口
type TunnelConn interface {
    Connect(target string, initialData []byte) error
    Read(buf []byte) (int, error)
    Write(data []byte) error
    Close() error
    StartPing(interval time.Duration) chan struct{}
}
```

## 下一步工作

### 阶段 1：完成核心功能（必需）

1. **完善 WebSocket Transport**
   - 实现 `conn_simple.go` 的完整协议
   - 实现 `conn_flow.go` 的 EWP Flow 协议
   - 从旧 `transport.go` 迁移逻辑

2. **实现 SOCKS5 协议**
   - 创建 `protocol/socks5/server.go`
   - 从旧 `ech-workers.go` 提取 SOCKS5 逻辑
   - 实现 UDP ASSOCIATE 支持

3. **实现 HTTP 代理**
   - 创建 `protocol/http/server.go`
   - 从旧 `ech-workers.go` 提取 HTTP 代理逻辑

### 阶段 2：补充传输层（重要）

4. **实现 gRPC Transport**
   - 创建 `transport/grpc/`
   - 从旧 `transport.go` 迁移 gRPC 实现

5. **实现 XHTTP Transport**
   - 创建 `transport/xhttp/`
   - 从旧 `transport.go` 迁移 XHTTP 实现

### 阶段 3：高级功能（可选）

6. **实现 TUN 模式**
   - 创建 `tun/` 模块
   - 从旧 `ech-workers.go` 提取 TUN 逻辑
   - 实现 gVisor 网络栈封装

7. **实现 Adapter 层**（可选）
   - 创建 `adapter/inbound/` 和 `adapter/outbound/`
   - 实现适配器管理器

## 与 sing-box 的对应关系

| ech-workers | sing-box | 说明 |
|-------------|----------|------|
| `protocol/ewp/` | `protocol/shadowsocks/` | 核心协议实现 |
| `transport/websocket/` | `transport/v2raywebsocket/` | WebSocket 传输 |
| `transport/grpc/` | `transport/v2raygrpc/` | gRPC 传输 |
| `common/tls/` | `common/tls/` | TLS 配置 |
| `dns/` | `dns/` | DNS 查询 |
| `option/` | `option/` | 配置结构 |

## 编译和运行

```bash
# 构建（当前只有框架，需要完善）
cd cmd/ech-workers
go build -o ../../ech-workers.exe

# 运行
../../ech-workers.exe -f wss://your-server:443/ws -token your-token
```

## 注意事项

1. **当前状态**：基础架构已创建，但核心逻辑仍需从旧文件迁移
2. **旧文件保留**：`ech-workers.go`、`transport.go` 等旧文件暂时保留作为参考
3. **渐进式迁移**：建议逐模块迁移和测试，确保功能正常
4. **Import 路径**：所有模块使用 `ech-client/` 前缀

## 贡献指南

优先完成以下任务：
1. ✅ 基础模块框架（已完成）
2. 🔴 WebSocket Transport 完整实现
3. 🔴 SOCKS5/HTTP 代理服务器
4. 🟡 gRPC 和 XHTTP 传输
5. 🟡 TUN 模式支持
