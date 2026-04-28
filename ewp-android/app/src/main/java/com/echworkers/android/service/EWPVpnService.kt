package com.echworkers.android.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.echworkers.android.model.EWPNode
import com.echworkers.android.model.ProxyConfig
import com.echworkers.android.model.ProxyMode
import ewpmobile.Ewpmobile
import ewpmobile.SocketProtector
import ewpmobile.VPNConfig
import kotlinx.coroutines.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString

class EWPVpnService : VpnService(), SocketProtector {
    
    companion object {
        private const val TAG = "EWPVpnService"
        
        const val ACTION_START = "com.echworkers.android.START_VPN"
        const val ACTION_STOP = "com.echworkers.android.STOP_VPN"
        
        // P1-18: Changed from EXTRA_NODE_JSON to EXTRA_NODE_ID to prevent credential leakage
        const val EXTRA_NODE_ID = "node_id"
        const val EXTRA_PROXY_CONFIG_JSON = "proxy_config_json"
        
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "ewp_vpn_channel"
        
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val VPN_DNS = "8.8.8.8"
        private const val VPN_MTU = 1400
    }
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var currentNode: EWPNode? = null
    private var proxyConfig: ProxyConfig = ProxyConfig()
    
    override fun onCreate() {
        super.onCreate()
        
        Ewpmobile.setSocketProtector(this)
        Log.i(TAG, "Socket protector set")
        
        createNotificationChannel()
    }
    
    override fun protect(fd: Long): Boolean {
        val result = protect(fd.toInt())
        if (!result) {
            Log.w(TAG, "Failed to protect socket: fd=$fd")
        }
        return result
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                // P1-18: Retrieve node from encrypted storage instead of Intent extras
                val nodeId = intent.getStringExtra(EXTRA_NODE_ID)
                val proxyConfigJson = intent.getStringExtra(EXTRA_PROXY_CONFIG_JSON)
                
                if (nodeId != null) {
                    try {
                        // Retrieve node from encrypted SharedPreferences (P1-25)
                        val nodeRepository = com.echworkers.android.data.NodeRepository(this)
                        val node = nodeRepository.getNodeById(nodeId)
                        
                        if (node == null) {
                            Log.e(TAG, "Node not found: $nodeId")
                            broadcastError("节点不存在")
                            stopSelf()
                            return START_NOT_STICKY
                        }
                        
                        proxyConfig = proxyConfigJson?.let { 
                            Json.decodeFromString(it) 
                        } ?: ProxyConfig()
                        
                        startVPN(node)
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to load node", e)
                        broadcastError("节点加载失败: ${e.message}")
                        stopSelf()
                    }
                } else {
                    Log.e(TAG, "No node ID provided")
                    broadcastError("缺少节点 ID")
                    stopSelf()
                }
            }
            ACTION_STOP -> {
                stopVPN()
                stopSelf()
            }
        }
        return START_STICKY
    }
    
    private fun startVPN(node: EWPNode) {
        scope.launch {
            try {
                Log.i(TAG, "Starting VPN: ${node.displayType()} - ${node.serverAddress}")
                
                broadcastState(VpnServiceState.CONNECTING)
                
                val tunFD = establishVpnInterface(node)
                if (tunFD < 0) {
                    broadcastError("Failed to establish VPN interface")
                    stopSelf()
                    return@launch
                }
                
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    startForeground(
                        NOTIFICATION_ID, 
                        createNotification(node), 
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                    )
                } else {
                    startForeground(NOTIFICATION_ID, createNotification(node))
                }
                
                val config = buildVPNConfig(node)
                
                Ewpmobile.startVPN(tunFD.toLong(), config)
                
                currentNode = node
                
                Log.i(TAG, "VPN started successfully")
                broadcastState(VpnServiceState.CONNECTED)
                
                monitorVPN()
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start VPN", e)
                broadcastError("连接失败: ${e.message}")
                stopSelf()
            }
        }
    }
    
    private fun buildVPNConfig(node: EWPNode): VPNConfig {
        val protocol = when (node.transportMode) {
            EWPNode.TransportMode.WS -> "ws"
            EWPNode.TransportMode.GRPC -> "grpc"
            EWPNode.TransportMode.XHTTP -> "xhttp"
            EWPNode.TransportMode.H3GRPC -> "h3grpc"
        }
        val path = when (node.transportMode) {
            EWPNode.TransportMode.WS -> node.wsPath
            EWPNode.TransportMode.GRPC -> node.grpcServiceName
            EWPNode.TransportMode.XHTTP -> node.xhttpPath
            EWPNode.TransportMode.H3GRPC -> node.grpcServiceName
        }
        val serverAddr = "${node.serverAddress}:${node.serverPort}"

        // v2 builder: PQC, TLS 1.3, Mozilla CA bundle and EWP app
        // protocol are baked in — there are no setters for those any
        // more. Trojan is gone entirely. Flow padding is gone.
        return Ewpmobile.newVPNConfig(serverAddr, node.uuid).apply {
            setProtocol(protocol)
            setPath(path)
            if (node.host.isNotEmpty()) setHost(node.host)
            if (node.sni.isNotEmpty()) setSNI(node.sni)
            setEnableECH(node.enableECH)
            if (node.echDomain.isNotEmpty()) setECHDomain(node.echDomain)
            if (node.dohServers.isNotBlank()) setDoHServers(node.dohServers)
            setTUNMTU(VPN_MTU.toLong())
        }.build()
    }
    
    private fun establishVpnInterface(node: EWPNode): Int {
        return try {
            val builder = Builder()
                .setSession("EWP - ${node.name}")
                .addAddress(VPN_ADDRESS, 24)
                .addRoute(VPN_ROUTE, 0)
                .addDnsServer(VPN_DNS)
                .setMtu(VPN_MTU)
            
            configureProxyMode(builder)
            
            vpnInterface = builder.establish()
            
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                -1
            } else {
                // detachFd() 将 fd 所有权转移给 Go 层，避免 ParcelFileDescriptor.close()
                // 与 Go 的 os.NewFile() 双重持有同一 fd 导致 fdsan SIGABRT
                val fd = vpnInterface!!.detachFd()
                Log.i(TAG, "VPN interface established: fd=$fd, proxyMode=${proxyConfig.mode}")
                fd
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN interface", e)
            -1
        }
    }
    
    private fun configureProxyMode(builder: Builder) {
        when (proxyConfig.mode) {
            ProxyMode.GLOBAL -> {
                // 全局模式：仅排除自身，所有其他 app 走 VPN
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to disallow self in GLOBAL mode", e)
                }
                Log.d(TAG, "Proxy mode: GLOBAL")
            }

            ProxyMode.BYPASS -> {
                // 绕过模式：自身 + 选中的 app 直连，其他走 VPN
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to disallow self in BYPASS mode", e)
                }
                proxyConfig.selectedPackages.forEach { pkg ->
                    try {
                        builder.addDisallowedApplication(pkg)
                        Log.d(TAG, "Bypass app: $pkg")
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to bypass app: $pkg", e)
                    }
                }
                Log.d(TAG, "Proxy mode: BYPASS, bypassed ${proxyConfig.selectedPackages.size} apps")
            }

            ProxyMode.PROXY_ONLY -> {
                // 仅代理模式：使用白名单，只有选中的 app 走 VPN
                // 注意：addAllowedApplication 与 addDisallowedApplication 不能混用
                // 自身始终直连，不加入白名单
                if (proxyConfig.selectedPackages.isEmpty()) {
                    // 没有选择任何 app 时，退化为全局模式以避免全部直连
                    try {
                        builder.addDisallowedApplication(packageName)
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to disallow self in PROXY_ONLY (empty) mode", e)
                    }
                    Log.w(TAG, "Proxy mode: PROXY_ONLY with no apps selected, fallback to GLOBAL")
                } else {
                    proxyConfig.selectedPackages.forEach { pkg ->
                        try {
                            builder.addAllowedApplication(pkg)
                            Log.d(TAG, "Allow app: $pkg")
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to allow app: $pkg", e)
                        }
                    }
                    Log.d(TAG, "Proxy mode: PROXY_ONLY, allowed ${proxyConfig.selectedPackages.size} apps")
                }
            }
        }
    }
    
    private fun monitorVPN() {
        scope.launch {
            while (Ewpmobile.isVPNRunning()) {
                // P2-29: Increased from 2s to 5s to reduce battery consumption
                // Stats updates every 5 seconds are sufficient for user experience
                delay(5000)
                
                try {
                    val statsJson = Ewpmobile.getVPNStats()
                    broadcastStats(statsJson)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get VPN stats", e)
                }
            }
            
            Log.i(TAG, "VPN monitoring stopped")
            broadcastState(VpnServiceState.DISCONNECTED)
        }
    }
    
    private fun stopVPN() {
        scope.launch {
            try {
                Log.i(TAG, "Stopping VPN...")
                
                broadcastState(VpnServiceState.DISCONNECTING)
                
                Ewpmobile.stopVPN()
                
                vpnInterface?.close()
                vpnInterface = null
                currentNode = null
                
                Log.i(TAG, "VPN stopped successfully")
                broadcastState(VpnServiceState.DISCONNECTED)
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to stop VPN", e)
                broadcastError("断开失败: ${e.message}")
            }
        }
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "EWP VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "EWP VPN Service"
                setShowBadge(false)
            }
            
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(node: EWPNode): Notification {
        val intent = packageManager.getLaunchIntentForPackage(packageName)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("EWP VPN")
            .setContentText("已连接到 ${node.name}")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
    
    private fun broadcastState(state: VpnServiceState) {
        val intent = Intent(VPN_STATE_ACTION).apply {
            setPackage(packageName)
            putExtra(EXTRA_STATE, state.name)
        }
        sendBroadcast(intent)
    }
    
    private fun broadcastStats(statsJson: String) {
        val intent = Intent(VPN_STATS_ACTION).apply {
            setPackage(packageName)
            putExtra(EXTRA_STATS, statsJson)
        }
        sendBroadcast(intent)
    }
    
    private fun broadcastError(message: String) {
        val intent = Intent(VPN_ERROR_ACTION).apply {
            setPackage(packageName)
            putExtra(EXTRA_ERROR, message)
        }
        sendBroadcast(intent)
    }
    
    override fun onDestroy() {
        super.onDestroy()
        stopVPN()
        scope.cancel()
    }
}

enum class VpnServiceState {
    DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING
}

const val VPN_STATE_ACTION = "com.echworkers.android.VPN_STATE"
const val VPN_STATS_ACTION = "com.echworkers.android.VPN_STATS"
const val VPN_ERROR_ACTION = "com.echworkers.android.VPN_ERROR"

const val EXTRA_STATE = "state"
const val EXTRA_STATS = "stats"
const val EXTRA_ERROR = "error"
