# EWP-Core Android 集成指南

## 📖 概述

EWP-Core 提供完整的 Android VPN 解决方案，Kotlin 只需负责 UI 交互，所有核心功能（连接、TUN、路由）都由 Go 层实现。

### ✨ 核心特性

- ✅ **统一 VPN 管理器** - 一行代码启动完整 VPN
- ✅ **自动 Socket 保护** - 防止 VPN 流量循环
- ✅ **内置 gVisor 网络栈** - 无需 tun2socks
- ✅ **多协议支持** - WebSocket/gRPC/XHTTP
- ✅ **多安全特性** - ECH/Vision 流控/PQC
- ✅ **零配置** - 开箱即用的默认设置

---

## 🚀 快速开始

### 1. 编译 AAR

```bash
# Windows
cd ewp-core
build_android.bat

# Linux/Mac
./build_gomobile.sh
```

生成的 AAR 位于：`output/android/ewp-core.aar`

### 2. 添加依赖

将 AAR 复制到 Android 项目：

```bash
cp output/android/ewp-core.aar ../ech-workers-NG/app/libs/
```

在 `build.gradle.kts` 添加：

```kotlin
dependencies {
    implementation(files("libs/ewp-core.aar"))
}
```

### 3. 实现 VPN Service

创建 `EWPVpnService.kt`：

```kotlin
import android.net.VpnService
import ewpmobile.*

class EWPVpnService : VpnService(), Ewpmobile.SocketProtector {
    
    override fun onCreate() {
        super.onCreate()
        // 设置 Socket 保护器（必须！）
        Ewpmobile.setSocketProtector(this)
    }
    
    // 实现 SocketProtector 接口
    override fun protect(fd: Long): Boolean {
        return protect(fd.toInt())
    }
    
    fun startVPN(serverAddr: String, token: String) {
        // 1. 建立 VPN 接口
        val vpnInterface = Builder()
            .setSession("EWP VPN")
            .addAddress("10.0.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .setMtu(1400)
            .establish()
        
        val tunFD = vpnInterface.fd
        
        // 2. 启动 VPN（一行代码！）
        Ewpmobile.quickStartVPN(tunFD.toLong(), serverAddr, token)
    }
    
    fun stopVPN() {
        Ewpmobile.stopVPN()
    }
}
```

### 4. 在 Activity 中调用

```kotlin
class MainActivity : AppCompatActivity() {
    
    fun connectVPN() {
        val intent = Intent(this, EWPVpnService::class.java).apply {
            action = "START_VPN"
            putExtra("server_addr", "xxx.workers.dev:443")
            putExtra("token", "your-uuid")
        }
        startService(intent)
    }
    
    fun disconnectVPN() {
        Ewpmobile.stopVPN()
    }
    
    fun getStats() {
        val stats = Ewpmobile.getVPNStats()
        Log.d("VPN", stats)
    }
}
```

---

## 📚 API 参考

### 快捷函数（推荐）

#### 1. 快速启动（默认配置）

```kotlin
Ewpmobile.quickStartVPN(
    tunFD = fd.toLong(),
    serverAddr = "server.com:443",
    token = "your-token"
)
```

#### 2. 指定协议启动

```kotlin
Ewpmobile.startVPNWithProtocol(
    tunFD = fd.toLong(),
    serverAddr = "server.com:443",
    token = "your-token",
    protocol = "ws",  // ws / grpc / xhttp
    enableECH = true
)
```

#### 3. Trojan 协议

```kotlin
Ewpmobile.startVPNTrojan(
    tunFD = fd.toLong(),
    serverAddr = "server.com:443",
    password = "your-password",
    protocol = "ws"
)
```

### 配置构建器（高级）

```kotlin
val config = Ewpmobile.newVPNConfig("server.com:443", "token")
    .setServerIP("104.16.1.2")     // 优选 IP
    .setProtocol("ws")              // ws/grpc/xhttp
    .setAppProtocol("ewp")          // ewp/trojan
    .setPath("/ws")                 // WebSocket 路径
    .setEnableECH(true)             // ECH 加密 SNI
    .setEnableFlow(true)            // Vision 流控
    .setEnablePQC(false)            // 后量子加密
    .setTunMTU(1400)                // MTU
    .setTunDNS("8.8.8.8")           // DNS
    .build()

Ewpmobile.startVPN(fd.toLong(), config)
```

### 状态管理

```kotlin
// 检查运行状态
val isRunning = Ewpmobile.isVPNRunning()

// 获取统计信息（JSON）
val stats = Ewpmobile.getVPNStats()
// 返回: {"running":true,"uptime":123.45,"bytes_up":1024,...}

// 停止 VPN
Ewpmobile.stopVPN()
```

### Socket 保护器

```kotlin
class EWPVpnService : VpnService(), Ewpmobile.SocketProtector {
    override fun onCreate() {
        super.onCreate()
        // 必须在启动前设置！
        Ewpmobile.setSocketProtector(this)
    }
    
    override fun protect(fd: Long): Boolean {
        return protect(fd.toInt())
    }
}
```

---

## 🔧 协议配置

### WebSocket（默认）

```kotlin
val config = Ewpmobile.newVPNConfig("server.com:443", "token")
    .setProtocol("ws")
    .setPath("/ws")  // 默认 "/"
    .build()
```

### gRPC

```kotlin
val config = Ewpmobile.newVPNConfig("server.com:443", "token")
    .setProtocol("grpc")
    .setPath("/TunnelService")  // gRPC 服务名
    .build()
```

### XHTTP

```kotlin
val config = Ewpmobile.newVPNConfig("server.com:443", "token")
    .setProtocol("xhttp")
    .setPath("/xhttp")
    .build()
```

---

## 🛡️ 安全特性

### ECH (Encrypted Client Hello)

```kotlin
val config = Ewpmobile.newVPNConfig("server.com:443", "token")
    .setEnableECH(true)                          // 启用 ECH
    .setECHDomain("cloudflare-ech.com")          // ECH 域名
    .setDNSServer("dns.alidns.com/dns-query")    // DoH 服务器
    .build()
```

**作用**：加密 TLS SNI，防止中间人识别目标域名

### Vision 流控

```kotlin
val config = Ewpmobile.newVPNConfig("server.com:443", "token")
    .setEnableFlow(true)  // 启用 Vision 流控
    .build()
```

**作用**：流量混淆 + 零拷贝优化，提升性能和隐私

### PQC (后量子加密)

```kotlin
val config = Ewpmobile.newVPNConfig("server.com:443", "token")
    .setEnablePQC(true)  // 启用 PQC
    .build()
```

**作用**：抵抗量子计算机攻击

---

## 🌐 优选 IP

```kotlin
val config = Ewpmobile.newVPNConfig("cloudflare.com:443", "token")
    .setServerIP("104.16.1.2")  // Cloudflare 优选 IP
    .build()
```

**工作原理**：
- 直接连接优选 IP，绕过 DNS 污染
- TLS SNI 仍使用原域名

---

## 📊 统计信息

```kotlin
val stats = Ewpmobile.getVPNStats()
```

返回 JSON 示例：

```json
{
  "running": true,
  "uptime": 123.45,
  "bytes_up": 1024000,
  "bytes_down": 2048000,
  "connections": 42,
  "server_addr": "server.com:443",
  "protocol": "ws",
  "app_protocol": "ewp",
  "enable_ech": true,
  "enable_flow": true,
  "tun_mtu": 1400
}
```

---

## 🔄 从旧版本迁移

### 旧版本（ech-workers-NG/core）

```kotlin
// 旧接口：单个函数，13+ 参数
import core.Core

val proxyAddr = Core.startProxy(
    serverAddr,
    serverIp,
    token,
    localAddr,
    protocol,
    enableECH,
    enableFlow,
    enablePQC,
    echDomain,
    echDohServer,
    wsPath,
    grpcServiceName,
    xhttpPath,
    xhttpMode
)

// 还需要单独处理 TUN
Core.startTun2Socks(...)
```

### 新版本（ewp-core）

```kotlin
// 新接口：一行搞定！
import ewpmobile.Ewpmobile

Ewpmobile.quickStartVPN(fd, serverAddr, token)

// 或使用配置构建器
val config = Ewpmobile.newVPNConfig(serverAddr, token)
    .setProtocol(protocol)
    .setEnableECH(enableECH)
    .build()

Ewpmobile.startVPN(fd, config)
```

### 迁移对照表

| 功能 | 旧接口 | 新接口 |
|------|--------|--------|
| **连接** | `Core.startProxy(...)` | `Ewpmobile.startVPN(...)` |
| **断开** | `Core.stopProxy()` | `Ewpmobile.stopVPN()` |
| **TUN** | `Core.startTun2Socks(...)` | 自动集成 ✅ |
| **Socket 保护** | `Core.setSocketProtector()` | `Ewpmobile.setSocketProtector()` |
| **统计** | 无 | `Ewpmobile.getVPNStats()` ✅ |

---

## ⚠️ 常见问题

### 1. VPN 流量循环

**原因**：未设置 Socket 保护器

**解决**：

```kotlin
override fun onCreate() {
    super.onCreate()
    Ewpmobile.setSocketProtector(this)  // 必须设置！
}
```

### 2. 连接失败

**检查清单**：
- ✅ 服务器地址正确
- ✅ Token/密码正确
- ✅ 网络权限已授予
- ✅ VPN 权限已授予

**查看日志**：

```kotlin
// Go 层日志会输出到 Logcat
adb logcat | grep "VPNManager"
```

### 3. 性能优化

**推荐配置**：

```kotlin
val config = Ewpmobile.newVPNConfig(serverAddr, token)
    .setEnableFlow(true)    // Vision 流控（零拷贝）
    .setTunMTU(1400)        // 优化 MTU
    .build()
```

---

## 📦 完整示例

参考文件：
- [`ewpmobile/EWPVpnExample.kt`](./ewpmobile/EWPVpnExample.kt) - 完整的 VPN 服务实现
- [`build_android.bat`](./build_android.bat) - Windows 编译脚本
- [`build_gomobile.sh`](./build_gomobile.sh) - Linux/Mac 编译脚本

---

## 🏗️ 架构优势

### 旧架构（ech-workers-NG）

```
┌─────────────────────────────────┐
│  Kotlin (UI + 业务逻辑)          │
├─────────────────────────────────┤
│  core.go (3000+ 行单文件)        │  ❌ 难以维护
│  - 连接、TUN、协议混在一起        │  ❌ 扩展困难
└─────────────────────────────────┘
```

### 新架构（ewp-core）

```
┌─────────────────────────────────┐
│  Kotlin (UI 交互)                │  ✅ 职责清晰
├─────────────────────────────────┤
│  ewpmobile (GoMobile 接口层)     │  ✅ 简单易用
├─────────────────────────────────┤
│  VPNManager (统一管理器)         │  ✅ 一行启动
├─────────────────────────────────┤
│  Transport (传输层)              │  ✅ 可扩展
│  - WebSocket / gRPC / XHTTP      │
├─────────────────────────────────┤
│  TUN (gVisor 网络栈)             │  ✅ 高性能
│  - TCP/UDP 处理器                │
└─────────────────────────────────┘
```

---

## 📄 许可证

MIT License
