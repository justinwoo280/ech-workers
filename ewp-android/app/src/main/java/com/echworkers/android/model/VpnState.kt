package com.echworkers.android.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

sealed class VpnState {
    object Disconnected : VpnState()
    object Connecting : VpnState()
    data class Connected(val stats: VpnStats) : VpnState()
    object Disconnecting : VpnState()
    data class Error(val message: String) : VpnState()
    
    fun isActive(): Boolean = this is Connecting || this is Connected
}

@Serializable
data class VpnStats(
    val running: Boolean = false,
    val uptime: Double = 0.0,
    val bytesUp: Long = 0,
    val bytesDown: Long = 0,
    val connections: Long = 0,
    val serverAddr: String = "",
    val protocol: String = "",
    val appProtocol: String = "",
    val enableEch: Boolean = false,
    val enableFlow: Boolean = false,
    val tunMtu: Int = 0
) {
    companion object {
        fun fromJson(json: String): VpnStats {
            return try {
                Json.decodeFromString(json)
            } catch (e: Exception) {
                VpnStats()
            }
        }
    }
    
    fun formatUptime(): String {
        val hours = (uptime / 3600).toInt()
        val minutes = ((uptime % 3600) / 60).toInt()
        val seconds = (uptime % 60).toInt()
        return String.format("%02d:%02d:%02d", hours, minutes, seconds)
    }
    
    fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> String.format("%.2f KB", bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> String.format("%.2f MB", bytes / (1024.0 * 1024))
            else -> String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024))
        }
    }
    
    fun formatSpeed(bytes: Long, seconds: Double): String {
        if (seconds <= 0) return "0 B/s"
        val bytesPerSec = bytes / seconds
        return "${formatBytes(bytesPerSec.toLong())}/s"
    }
}
