package com.echworkers.android.model

import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class EWPNode(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val serverAddress: String,
    val serverPort: Int = 443,
    
    val appProtocol: AppProtocol = AppProtocol.EWP,
    val uuid: String = "",
    val password: String = "",
    
    val transportMode: TransportMode = TransportMode.WS,
    val wsPath: String = "/",
    val grpcServiceName: String = "ProxyService",
    val xhttpPath: String = "/xhttp",
    
    val serverIP: String = "",
    
    val enableECH: Boolean = true,
    val echDomain: String = "cloudflare-ech.com",
    val dnsServer: String = "dns.alidns.com/dns-query",
    
    val enableFlow: Boolean = true,
    val enablePQC: Boolean = false,
    
    var latency: Int = 0
) {
    @Serializable
    enum class AppProtocol {
        EWP, TROJAN
    }
    
    @Serializable
    enum class TransportMode {
        WS, GRPC, XHTTP
    }
    
    fun isValid(): Boolean {
        return serverAddress.isNotEmpty() && when (appProtocol) {
            AppProtocol.EWP -> uuid.isNotEmpty()
            AppProtocol.TROJAN -> password.isNotEmpty()
        }
    }
    
    fun displayType(): String {
        val prefix = if (appProtocol == AppProtocol.TROJAN) "Trojan" else "EWP"
        val transport = when (transportMode) {
            TransportMode.WS -> "WS"
            TransportMode.GRPC -> "gRPC"
            TransportMode.XHTTP -> "XHTTP"
        }
        return "$prefix-$transport"
    }
    
    fun displayAddress(): String = "$serverAddress:$serverPort"
    
    fun displayLatency(): String = when {
        latency < 0 -> "失败"
        latency == 0 -> "-"
        else -> "${latency}ms"
    }
    
    fun displayAuth(): String {
        return when (appProtocol) {
            AppProtocol.TROJAN -> {
                if (password.length <= 4) "****"
                else "${password.take(2)}****${password.takeLast(2)}"
            }
            AppProtocol.EWP -> "${uuid.take(8)}..."
        }
    }
}
