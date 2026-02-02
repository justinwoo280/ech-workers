package com.echworkers.android.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.echworkers.android.model.EWPNode
import com.echworkers.android.model.ProxyConfig
import com.echworkers.android.model.ProxyMode
import ewpmobile.Ewpmobile
import kotlinx.coroutines.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString

class EWPVpnService : VpnService(), Ewpmobile.SocketProtector {
    
    companion object {
        private const val TAG = "EWPVpnService"
        
        const val ACTION_START = "com.echworkers.android.START_VPN"
        const val ACTION_STOP = "com.echworkers.android.STOP_VPN"
        
        const val EXTRA_NODE_JSON = "node_json"
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
                val nodeJson = intent.getStringExtra(EXTRA_NODE_JSON)
                val proxyConfigJson = intent.getStringExtra(EXTRA_PROXY_CONFIG_JSON)
                
                if (nodeJson != null) {
                    try {
                        val node = Json.decodeFromString<EWPNode>(nodeJson)
                        proxyConfig = proxyConfigJson?.let { 
                            Json.decodeFromString(it) 
                        } ?: ProxyConfig()
                        
                        startVPN(node)
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to parse node JSON", e)
                        broadcastError("配置解析失败: ${e.message}")
                        stopSelf()
                    }
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
                
                val config = buildVPNConfig(node)
                
                Ewpmobile.startVPN(tunFD.toLong(), config)
                
                currentNode = node
                
                Log.i(TAG, "VPN started successfully")
                broadcastState(VpnServiceState.CONNECTED)
                
                startForeground(NOTIFICATION_ID, createNotification(node))
                
                monitorVPN()
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start VPN", e)
                broadcastError("连接失败: ${e.message}")
                stopSelf()
            }
        }
    }
    
    private fun buildVPNConfig(node: EWPNode): Ewpmobile.VPNConfig {
        val protocol = when (node.transportMode) {
            EWPNode.TransportMode.WS -> "ws"
            EWPNode.TransportMode.GRPC -> "grpc"
            EWPNode.TransportMode.XHTTP -> "xhttp"
        }
        
        val path = when (node.transportMode) {
            EWPNode.TransportMode.WS -> node.wsPath
            EWPNode.TransportMode.GRPC -> node.grpcServiceName
            EWPNode.TransportMode.XHTTP -> node.xhttpPath
        }
        
        val serverAddr = "${node.serverAddress}:${node.serverPort}"
        
        val builder = if (node.appProtocol == EWPNode.AppProtocol.TROJAN) {
            Ewpmobile.newVPNConfig(serverAddr, "")
                .setPassword(node.password)
                .setAppProtocol("trojan")
        } else {
            Ewpmobile.newVPNConfig(serverAddr, node.uuid)
        }
        
        return builder.apply {
            setProtocol(protocol)
            setPath(path)
            
            if (node.serverIP.isNotEmpty()) {
                setServerIP(node.serverIP)
            }
            
            setEnableECH(node.enableECH)
            if (node.enableECH) {
                setECHDomain(node.echDomain)
                setDNSServer(node.dnsServer)
            }
            
            setEnableFlow(node.enableFlow)
            setEnablePQC(node.enablePQC)
            setTunMTU(VPN_MTU.toLong())
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
                .setBlocking(false)
            
            configureProxyMode(builder)
            
            vpnInterface = builder.establish()
            
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                return -1
            }
            
            val fd = vpnInterface!!.fd
            Log.i(TAG, "VPN interface established: fd=$fd, proxyMode=${proxyConfig.mode}")
            return fd
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN interface", e)
            return -1
        }
    }
    
    private fun configureProxyMode(builder: Builder) {
        builder.addDisallowedApplication(packageName)
        
        when (proxyConfig.mode) {
            ProxyMode.GLOBAL -> {
            }
            
            ProxyMode.BYPASS -> {
                proxyConfig.selectedPackages.forEach { pkg ->
                    try {
                        builder.addDisallowedApplication(pkg)
                        Log.d(TAG, "Bypass app: $pkg")
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to bypass app: $pkg", e)
                    }
                }
            }
            
            ProxyMode.PROXY_ONLY -> {
                proxyConfig.selectedPackages.forEach { pkg ->
                    try {
                        builder.addAllowedApplication(pkg)
                        Log.d(TAG, "Allow app: $pkg")
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to allow app: $pkg", e)
                    }
                }
            }
        }
    }
    
    private fun monitorVPN() {
        scope.launch {
            while (Ewpmobile.isVPNRunning()) {
                delay(2000)
                
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
            putExtra(EXTRA_STATE, state.name)
        }
        sendBroadcast(intent)
    }
    
    private fun broadcastStats(statsJson: String) {
        val intent = Intent(VPN_STATS_ACTION).apply {
            putExtra(EXTRA_STATS, statsJson)
        }
        sendBroadcast(intent)
    }
    
    private fun broadcastError(message: String) {
        val intent = Intent(VPN_ERROR_ACTION).apply {
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
