package com.example.ewp

import android.net.VpnService
import android.util.Log
import ewpmobile.*
import kotlinx.coroutines.*

/**
 * EWP TUN 集成示例
 * 
 * 这个示例展示如何在 Android Kotlin VPNService 中集成 ewp-core 的 TUN 功能
 * 不使用 tun2socks 库，直接使用 Go 实现的 gVisor 网络栈
 */
class EWPTunService : VpnService() {
    
    companion object {
        private const val TAG = "EWPTunService"
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_GATEWAY = "10.0.0.1"
        private const val VPN_NETMASK = "255.255.255.0"
        private const val VPN_DNS = "8.8.8.8"
        private const val VPN_MTU = 1500
    }
    
    // TUN 实例
    private var tunInstance: SimpleTUN? = null
    
    // 服务作业域
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    /**
     * 启动 VPN 服务
     */
    fun startVPN(serverAddr: String, token: String) {
        serviceScope.launch {
            try {
                // 1. 建立 VPN 接口
                Log.i(TAG, "Building VPN interface...")
                val vpnInterface = Builder()
                    .setSession("EWP Native VPN")
                    .addAddress(VPN_ADDRESS, 24)
                    .addDnsServer(VPN_DNS)
                    .addRoute("0.0.0.0", 0)  // 全局路由
                    .setMtu(VPN_MTU)
                    .setBlocking(false)
                    .establish()
                
                if (vpnInterface == null) {
                    Log.e(TAG, "Failed to establish VPN interface")
                    return@launch
                }
                
                Log.i(TAG, "VPN interface established")
                
                // 2. 获取文件描述符
                val fd = getFD(vpnInterface)
                Log.i(TAG, "VPN FD: $fd")
                
                // 3. 创建 SimpleTUN 实例
                tunInstance = Ewpmobile.newSimpleTUN(fd.toLong(), VPN_MTU.toLong())
                Log.i(TAG, "SimpleTUN instance created")
                
                // 4. 启动 TUN
                val err = tunInstance?.start(VPN_ADDRESS, VPN_GATEWAY, VPN_NETMASK, VPN_DNS)
                if (err != null) {
                    Log.e(TAG, "Failed to start TUN: $err")
                    vpnInterface.close()
                    return@launch
                }
                
                Log.i(TAG, "TUN started successfully")
                
                // 5. 监控 TUN 状态
                monitorTUN()
                
            } catch (e: Exception) {
                Log.e(TAG, "Error starting VPN", e)
            }
        }
    }
    
    /**
     * 停止 VPN 服务
     */
    fun stopVPN() {
        Log.i(TAG, "Stopping VPN...")
        
        serviceScope.launch {
            try {
                tunInstance?.stop()
                tunInstance = null
                Log.i(TAG, "VPN stopped")
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping VPN", e)
            }
        }
    }
    
    /**
     * 监控 TUN 状态
     */
    private suspend fun monitorTUN() {
        while (isActive && tunInstance?.isRunning() == true) {
            delay(10000) // 每 10 秒检查一次
            
            val stats = tunInstance?.getStats() ?: continue
            Log.d(TAG, "TUN Stats: $stats")
        }
        
        Log.w(TAG, "TUN monitoring stopped")
    }
    
    /**
     * 获取文件描述符
     * 
     * 使用反射从 ParcelFileDescriptor 中获取原始 FD
     * 这是因为 Android SDK 不直接暴露 FD
     */
    private fun getFD(vpnInterface: android.os.ParcelFileDescriptor): Int {
        return try {
            // 方法 1: 直接使用 getFd() (Android 12+)
            vpnInterface.fd
        } catch (e: Exception) {
            // 方法 2: 使用反射
            try {
                val fdField = vpnInterface.javaClass.getDeclaredField("mFd")
                fdField.isAccessible = true
                fdField.getInt(vpnInterface)
            } catch (e2: Exception) {
                Log.e(TAG, "Failed to get FD", e2)
                -1
            }
        }
    }
    
    /**
     * 获取 TUN 统计信息
     */
    fun getStats(): Map<String, Any> {
        val statsJson = tunInstance?.getStats() ?: return mapOf("running" to false)
        
        // 简单的 JSON 解析（实际项目中应使用 Gson/Kotlinx.serialization）
        return try {
            mapOf(
                "running" to (tunInstance?.isRunning() ?: false),
                "raw" to statsJson
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing stats", e)
            mapOf("error" to e.message.orEmpty())
        }
    }
    
    /**
     * Service 生命周期
     */
    override fun onDestroy() {
        super.onDestroy()
        stopVPN()
        serviceScope.cancel()
    }
}

/**
 * 使用示例：
 * 
 * ```kotlin
 * class MainActivity : AppCompatActivity() {
 *     private var vpnService: EWPTunService? = null
 *     
 *     fun startVPN() {
 *         // 1. 请求 VPN 权限
 *         val intent = VpnService.prepare(this)
 *         if (intent != null) {
 *             startActivityForResult(intent, VPN_REQUEST_CODE)
 *         } else {
 *             onVPNPermissionGranted()
 *         }
 *     }
 *     
 *     private fun onVPNPermissionGranted() {
 *         // 2. 启动 VPN
 *         vpnService = EWPTunService()
 *         vpnService?.startVPN(
 *             serverAddr = "server.com:443",
 *             token = "your-uuid-token"
 *         )
 *     }
 *     
 *     fun stopVPN() {
 *         vpnService?.stopVPN()
 *     }
 *     
 *     fun getStats() {
 *         val stats = vpnService?.getStats()
 *         println("VPN Stats: $stats")
 *     }
 * }
 * ```
 */
