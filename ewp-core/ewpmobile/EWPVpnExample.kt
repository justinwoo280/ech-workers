package com.example.ewp.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import ewpmobile.*
import kotlinx.coroutines.*

/**
 * EWP-Core VPN 服务示例
 * 
 * 这个示例展示如何使用 ewp-core 的 GoMobile 接口实现 Android VPN
 * 
 * 关键特性：
 * 1. ✅ 使用 VPNManager 统一管理连接和 TUN
 * 2. ✅ 自动 Socket 保护（防止 VPN 循环）
 * 3. ✅ 支持 WebSocket/gRPC/XHTTP 多协议
 * 4. ✅ 支持 ECH/Vision/PQC 安全特性
 * 5. ✅ 内置 gVisor 网络栈，无需 tun2socks
 */
class EWPVpnService : VpnService(), Ewpmobile.SocketProtector {

    companion object {
        private const val TAG = "EWPVpnService"
        
        // VPN 配置
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val VPN_GATEWAY = "10.0.0.1"
        private const val VPN_MTU = 1400
        private const val VPN_DNS = "8.8.8.8"
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onCreate() {
        super.onCreate()
        
        // 设置 Socket 保护器（防止 VPN 流量循环）
        Ewpmobile.setSocketProtector(this)
        Log.i(TAG, "Socket protector has been set")
    }

    /**
     * 实现 SocketProtector 接口
     * 保护 socket 不经过 VPN，防止流量循环
     */
    override fun protect(fd: Long): Boolean {
        val result = protect(fd.toInt())
        if (!result) {
            Log.w(TAG, "Failed to protect socket: fd=$fd")
        }
        return result
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "START_VPN" -> {
                val serverAddr = intent.getStringExtra("server_addr") ?: ""
                val token = intent.getStringExtra("token") ?: ""
                val protocol = intent.getStringExtra("protocol") ?: "ws"
                val enableECH = intent.getBooleanExtra("enable_ech", true)
                
                startVPN(serverAddr, token, protocol, enableECH)
            }
            "STOP_VPN" -> {
                stopVPN()
            }
        }
        return START_STICKY
    }

    /**
     * 启动 VPN
     * 
     * 方式 1：使用快捷函数（推荐）
     */
    private fun startVPN(serverAddr: String, token: String, protocol: String, enableECH: Boolean) {
        scope.launch {
            try {
                Log.i(TAG, "Starting VPN: server=$serverAddr, protocol=$protocol")
                
                // 1. 建立 VPN 接口
                val tunFD = establishVpnInterface()
                if (tunFD < 0) {
                    Log.e(TAG, "Failed to establish VPN interface")
                    return@launch
                }
                
                // 2. 启动 VPN（一行代码搞定！）
                Ewpmobile.startVPNWithProtocol(tunFD.toLong(), serverAddr, token, protocol, enableECH)
                
                Log.i(TAG, "VPN started successfully")
                
                // 3. 监控 VPN 状态
                monitorVPN()
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start VPN", e)
            }
        }
    }

    /**
     * 启动 VPN - 方式 2：使用配置构建器（更多控制）
     */
    private fun startVPNWithBuilder(
        serverAddr: String,
        token: String,
        serverIP: String = "",
        protocol: String = "ws",
        enableECH: Boolean = true,
        enableFlow: Boolean = true,
        enablePQC: Boolean = false
    ) {
        scope.launch {
            try {
                val tunFD = establishVpnInterface()
                if (tunFD < 0) return@launch
                
                // 使用配置构建器
                val config = Ewpmobile.newVPNConfig(serverAddr, token)
                    .setServerIP(serverIP)
                    .setProtocol(protocol)
                    .setEnableECH(enableECH)
                    .setEnableFlow(enableFlow)
                    .setEnablePQC(enablePQC)
                    .setTunMTU(VPN_MTU.toLong())
                    .build()
                
                Ewpmobile.startVPN(tunFD.toLong(), config)
                
                Log.i(TAG, "VPN started with custom config")
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start VPN", e)
            }
        }
    }

    /**
     * 启动 VPN - 方式 3：Trojan 协议
     */
    private fun startVPNTrojan(
        serverAddr: String,
        password: String,
        protocol: String = "ws"
    ) {
        scope.launch {
            try {
                val tunFD = establishVpnInterface()
                if (tunFD < 0) return@launch
                
                Ewpmobile.startVPNTrojan(tunFD.toLong(), serverAddr, password, protocol)
                
                Log.i(TAG, "Trojan VPN started")
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start Trojan VPN", e)
            }
        }
    }

    /**
     * 建立 VPN 接口
     */
    private fun establishVpnInterface(): Int {
        try {
            val builder = Builder()
                .setSession("EWP VPN")
                .addAddress(VPN_ADDRESS, 24)
                .addRoute(VPN_ROUTE, 0)
                .addDnsServer(VPN_DNS)
                .setMtu(VPN_MTU)
                .setBlocking(false)
            
            vpnInterface = builder.establish()
            
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                return -1
            }
            
            val fd = vpnInterface!!.fd
            Log.i(TAG, "VPN interface established: fd=$fd")
            return fd
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN interface", e)
            return -1
        }
    }

    /**
     * 监控 VPN 状态
     */
    private fun monitorVPN() {
        scope.launch {
            while (Ewpmobile.isVPNRunning()) {
                delay(5000) // 每 5 秒检查一次
                
                val stats = Ewpmobile.getVPNStats()
                Log.d(TAG, "VPN Stats: $stats")
                
                // 可以在这里更新通知、统计等
            }
            
            Log.i(TAG, "VPN stopped")
        }
    }

    /**
     * 停止 VPN
     */
    private fun stopVPN() {
        scope.launch {
            try {
                Log.i(TAG, "Stopping VPN...")
                
                // 停止 VPN（自动清理所有资源）
                Ewpmobile.stopVPN()
                
                // 关闭 VPN 接口
                vpnInterface?.close()
                vpnInterface = null
                
                Log.i(TAG, "VPN stopped successfully")
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to stop VPN", e)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVPN()
        scope.cancel()
    }
}

/**
 * 使用示例（在 Activity 中调用）
 */
class VPNExampleActivity {
    
    fun startVPN(context: android.content.Context) {
        val intent = Intent(context, EWPVpnService::class.java).apply {
            action = "START_VPN"
            putExtra("server_addr", "xxx.workers.dev:443")
            putExtra("token", "your-uuid-token")
            putExtra("protocol", "ws")  // ws / grpc / xhttp
            putExtra("enable_ech", true)
        }
        context.startService(intent)
    }
    
    fun stopVPN(context: android.content.Context) {
        val intent = Intent(context, EWPVpnService::class.java).apply {
            action = "STOP_VPN"
        }
        context.startService(intent)
    }
    
    fun getVPNStats(): String {
        return Ewpmobile.getVPNStats()
    }
}

/**
 * 高级用法示例
 */
object AdvancedVPNExamples {
    
    /**
     * 使用优选 IP
     */
    fun startWithPreferredIP() {
        val config = Ewpmobile.newVPNConfig("cloudflare.com:443", "token")
            .setServerIP("104.16.1.2")  // 优选 IP
            .setProtocol("ws")
            .build()
        
        // Ewpmobile.startVPN(fd, config)
    }
    
    /**
     * 启用所有安全特性
     */
    fun startWithAllSecurity() {
        val config = Ewpmobile.newVPNConfig("server.com:443", "token")
            .setEnableECH(true)      // ECH 加密 SNI
            .setEnableFlow(true)     // Vision 流控
            .setEnablePQC(true)      // 后量子加密
            .build()
        
        // Ewpmobile.startVPN(fd, config)
    }
    
    /**
     * 自定义 DNS
     */
    fun startWithCustomDNS() {
        val config = Ewpmobile.newVPNConfig("server.com:443", "token")
            .setTunDNS("1.1.1.1")    // Cloudflare DNS
            .setDNSServer("dns.cloudflare.com/dns-query")  // DoH
            .build()
        
        // Ewpmobile.startVPN(fd, config)
    }
    
    /**
     * gRPC 协议
     */
    fun startWithGRPC() {
        val config = Ewpmobile.newVPNConfig("server.com:443", "token")
            .setProtocol("grpc")
            .setPath("/TunnelService")  // gRPC 服务名
            .build()
        
        // Ewpmobile.startVPN(fd, config)
    }
    
    /**
     * XHTTP 协议
     */
    fun startWithXHTTP() {
        val config = Ewpmobile.newVPNConfig("server.com:443", "token")
            .setProtocol("xhttp")
            .setPath("/xhttp")
            .build()
        
        // Ewpmobile.startVPN(fd, config)
    }
}
